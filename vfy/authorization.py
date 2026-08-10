"""Action-bound authorization, per spec/authorization.md.

Permission for one exact action, under one exact rulebook, on one exact frozen snapshot, in one
runtime, for a bounded interval, once.

Nothing here executes, acknowledges, stores, or receipts anything. No clock is read, no randomness
is drawn — Ed25519 is deterministic and the nonce is an input — no file is opened, and no network
is touched.
"""

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vfy import canon, gate, load, rulebook, schema
from vfy.errors import (
    CanonicalFormInvalid,
    AuthorizationBindingMismatch,
    AuthorizationExpired,
    AuthorizationNonceReused,
    AuthorizationNotYetValid,
    AuthorizationOutcomeIneligible,
    SignatureInvalid,
    SignatureMalformed,
    SigningKeyInvalid,
    SigningKeyRetired,
    SigningKeyUnknown,
)

AUTHORIZATION_VERSION = 1
AUTHORIZATION_SCHEMA_ID = "https://verifyrun.com/spec/v1/authorization.schema.json"

ALGORITHM = "ed25519"
DEFAULT_TTL_SECONDS = 300
KEY_LENGTH = 32
NANOS_PER_SECOND = 1000000000

ACTIVE = "active"
RETIRED = "retired"


@dataclass(frozen=True)
class FrozenAuthorization:
    """A complete authorization. Canonical text is the authority."""

    canonical: str
    authorization_id: str
    nonce: str
    issued_at: str
    expires_at: str

    @property
    def canonical_bytes(self):
        return self.canonical.encode("utf-8")

    def value(self):
        return load.load_json_bytes(self.canonical_bytes)


def build_key_registry(entries):
    """Return an immutable mapping from (key_id, key_version) to a verification key."""
    registry = {}
    identities = {}
    for entry in entries:
        identity = (entry["key_id"], entry["key_version"])
        if identity in registry:
            raise SigningKeyInvalid("Duplicate key identity in the registry.")
        public_key = entry["public_key"]
        if not isinstance(public_key, bytes) or len(public_key) != KEY_LENGTH:
            raise SigningKeyInvalid("An Ed25519 public key is 32 bytes.")
        # `key_id` and `key_version` are lookup metadata outside the signed bytes, and that is
        # safe only while one public key carries one identity: substituting a `key_id` is then
        # guaranteed to select a key the signature does not verify under. Registering one key
        # twice breaks that guarantee — the substitution finds the same key — and it would also
        # let a retired identity be escaped by relabelling, because status is held per identity
        # while the signing authority is held by the key.
        if public_key in identities:
            raise SigningKeyInvalid(
                "One public key carries one identity; this key is already registered as %r."
                % (identities[public_key],))
        identities[public_key] = identity
        status = entry.get("status", ACTIVE)
        if status not in (ACTIVE, RETIRED):
            raise SigningKeyInvalid("A key status is active or retired.")
        registry[identity] = {"public_key": public_key, "status": status}
    return registry


def issue_authorization(pinned, candidate, snapshot, result, authorization_id, nonce,
                        runtime_id, issued_at, key_id, key_version, private_key, registry):
    """Return the frozen authorization for one permitted action.

    Only ALLOW confers action authority. Every binding is computed here, never copied from a
    caller's claim.
    """
    for name, value in (("authorization_id", authorization_id), ("nonce", nonce),
                        ("runtime_id", runtime_id), ("issued_at", issued_at),
                        ("key_id", key_id)):
        if not isinstance(value, str):
            raise TypeError(name + " must be a string")
    if not isinstance(key_version, int) or isinstance(key_version, bool):
        raise TypeError("key_version must be an integer")
    if not isinstance(private_key, bytes) or len(private_key) != KEY_LENGTH:
        raise SigningKeyInvalid("An Ed25519 private key is 32 bytes.")

    if result.outcome != "ALLOW":
        raise AuthorizationOutcomeIneligible(
            "Only ALLOW confers action authority; this result is " + result.outcome)

    issued = _instant(issued_at, "issued_at")
    frozen = _instant(snapshot.frozen_at, "frozen_at")
    if issued < frozen:
        raise AuthorizationNotYetValid(
            "An authorization cannot be issued before the evidence it rests on was frozen.")

    ttl = pinned.value().get("authorization", {}).get("ttl_seconds", DEFAULT_TTL_SECONDS)
    payload = {
        "authorization_id": authorization_id,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": _add_seconds(issued_at, ttl),
        "runtime_id": runtime_id,
        "action_digest": canon.digest(candidate),
        "rulebook_digest": pinned.digest,
        "evidence_digest": snapshot.digest,
    }

    signing_bytes = canon.canonicalize(payload).encode("utf-8")
    try:
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(signing_bytes)
    except Exception:
        raise SigningKeyInvalid("The private key is not a usable Ed25519 key.") from None

    completed = dict(payload)
    completed["signature"] = {
        "alg": ALGORITHM, "key_id": key_id, "key_version": key_version,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    schema.validate(completed, AUTHORIZATION_SCHEMA_ID, registry)
    return _freeze(completed)


def verify_authorization(value, pinned, candidate, snapshot, result, runtime_id,
                         verification_time, keys, registry, consumed_nonces=None):
    """Verify one authorization against the objects a caller is actually holding.

    A signature proves who produced the bytes. It proves nothing about whether those bytes describe
    these objects, so every binding is recomputed and compared.

    With no `consumed_nonces` view this makes **no single-use claim**: a stateless function cannot
    enforce one-time use.

    `verification_time` is the instant this authorization is being checked *for spending*. The
    validity interval is always checked for internal consistency — issued at or after the freeze,
    expiring after it was issued — and is additionally compared against that instant when one is
    supplied. Passing `None` asks the historical question instead: *was this a well-formed
    authorization over these exact objects?* Replay uses `None`, because replay spends nothing and
    a receipt must not stop verifying because time passed. A runtime about to consume an
    authorization must always supply the instant; `runner.execute_authorized_command` does.
    """
    if not isinstance(value, dict):
        raise TypeError("an authorization value must be a mapping")
    if not isinstance(runtime_id, str):
        raise TypeError("runtime_id must be a string")

    schema.validate(value, AUTHORIZATION_SCHEMA_ID, registry)

    block = value["signature"]
    identity = (block["key_id"], block["key_version"])
    entry = keys.get(identity)
    if entry is None:
        raise SigningKeyUnknown("No key in the registry matches " + repr(identity))
    if entry["status"] == RETIRED:
        raise SigningKeyRetired("The signing key is retired and authorizes nothing.")

    # One signature byte string, one accepted encoding. Strict base64 refuses a bad alphabet and
    # bad padding but not unused trailing bits, so sixteen distinct texts decoded to the same
    # 64 bytes and all sixteen verified. See `canon.decode_signature`.
    try:
        signature = canon.decode_signature(block["value"])
    except CanonicalFormInvalid as failure:
        raise SignatureMalformed(str(failure)) from None

    payload = {key: member for key, member in value.items() if key != "signature"}
    signing_bytes = canon.canonicalize(payload).encode("utf-8")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(entry["public_key"])
    except Exception:
        raise SigningKeyInvalid("The registered key is not a usable Ed25519 key.") from None
    try:
        public_key.verify(signature, signing_bytes)
    except InvalidSignature:
        raise SignatureInvalid(
            "The signature does not verify over the authorization's payload.") from None

    _bind("rulebook_digest", value["rulebook_digest"], pinned.digest)
    _bind("action_digest", value["action_digest"], canon.digest(candidate))
    _bind("evidence_digest", value["evidence_digest"], snapshot.digest)

    recomputed = gate.evaluate(pinned, candidate, snapshot.value(), registry)
    if recomputed.canonical != result.canonical:
        raise AuthorizationBindingMismatch(
            "The supplied result is not what the bound inputs produce.")
    if recomputed.outcome != "ALLOW":
        raise AuthorizationOutcomeIneligible(
            "The bound inputs do not produce ALLOW; they produce " + recomputed.outcome)

    _bind("runtime_id", value["runtime_id"], runtime_id)

    issued = _instant(value["issued_at"], "issued_at")
    expires = _instant(value["expires_at"], "expires_at")
    if issued < _instant(snapshot.frozen_at, "frozen_at"):
        raise AuthorizationNotYetValid(
            "The authorization was issued before the evidence it rests on was frozen.")
    if expires <= issued:
        raise AuthorizationExpired("The authorization expires at or before it was issued.")

    if verification_time is not None:
        now = _instant(verification_time, "verification_time")
        if now < issued:
            raise AuthorizationNotYetValid("The authorization is not yet valid.")
        if now >= expires:
            raise AuthorizationExpired("The authorization has expired.")

    if consumed_nonces is not None and value["nonce"] in consumed_nonces:
        raise AuthorizationNonceReused("This authorization's nonce has already been consumed.")

    return _freeze(value)


def _freeze(value):
    return FrozenAuthorization(
        canonical=canon.canonicalize(value),
        authorization_id=value["authorization_id"], nonce=value["nonce"],
        issued_at=value["issued_at"], expires_at=value["expires_at"])


def _bind(field, bound, expected):
    if bound != expected:
        raise AuthorizationBindingMismatch(
            "The authorization's %s is not the one supplied." % field)


def _instant(text, field):
    try:
        return rulebook._instant(text)
    except TypeError:
        raise AuthorizationNotYetValid(
            "%s is not a date-time in the frozen grammar." % field) from None


def _add_seconds(text, seconds):
    """Render an instant plus a whole number of seconds, in the frozen grammar."""
    total = (rulebook._instant(text) + seconds * NANOS_PER_SECOND) // NANOS_PER_SECOND
    days, remainder = divmod(total, 86400)
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    day_of_era = z - era * 146097
    year_of_era = (day_of_era - day_of_era // 1460 + day_of_era // 36524
                   - day_of_era // 146096) // 365
    year = year_of_era + era * 400
    day_of_year = day_of_era - (365 * year_of_era + year_of_era // 4 - year_of_era // 100)
    month_position = (5 * day_of_year + 2) // 153
    day = day_of_year - (153 * month_position + 2) // 5 + 1
    month = month_position + 3 if month_position < 10 else month_position - 9
    year += month <= 2
    hour, rest = divmod(remainder, 3600)
    minute, second = divmod(rest, 60)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (year, month, day, hour, minute, second)
