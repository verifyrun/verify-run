"""Signed decision receipts, verification, and deterministic replay, per
spec/receipt-and-replay.md.

A receipt records that one rulebook, one candidate, and one snapshot produced one result. It never
authorizes retroactively, and it never claims the world changed.

Verification and replay make different claims and are separate functions. Nothing here executes an
action, acquires evidence, reads a clock, opens a file, or touches a network.
"""

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vfy import authorization as auth_module
from vfy import canon, gate, load, rulebook, schema, snapshot
from vfy.errors import (
    ReceiptBindingMismatch,
    ReceiptOutcomeIneligible,
    ReplayBodyMismatch,
    ReplayBodyMissing,
    ReplayResultMismatch,
    SignatureInvalid,
    SignatureMalformed,
    SigningKeyInvalid,
    SigningKeyRetired,
    SigningKeyUnknown,
)

RECEIPT_VERSION = 1
RECEIPT_SCHEMA_ID = "https://verifyrun.com/spec/v1/receipt.schema.json"
SPEC_VERSION = "1"
REPLAY_MODE = "recompute-decision"
DECISION_OUTCOMES = ("ALLOW", "BLOCK", "HOLD")


@dataclass(frozen=True)
class FrozenReceipt:
    canonical: str
    receipt_id: str
    outcome: str

    @property
    def canonical_bytes(self):
        return self.canonical.encode("utf-8")

    def value(self):
        return load.load_json_bytes(self.canonical_bytes)


@dataclass(frozen=True)
class ReceiptVerification:
    """What a receipt alone can establish: that the record is authentic and unaltered."""

    receipt_id: str
    outcome: str
    key_id: str
    key_version: int
    replay_mode: str
    signature_valid: bool
    replayed: bool = False


@dataclass(frozen=True)
class ReplayVerification:
    """What replay adds: that the recorded decision is the one the recorded inputs produce."""

    receipt_id: str
    outcome: str
    signature_valid: bool
    bodies_matched: bool
    result_recomputed: bool
    result_matched: bool
    authorization_verified: bool
    recomputed_canonical: str
    replayed: bool = True


def issue_receipt(pinned, candidate, snap, result, authorization, execution, receipt_id,
                  created_at, key_id, key_version, private_key, registry):
    """Return the signed receipt for one completed decision."""
    for name, value in (("receipt_id", receipt_id), ("created_at", created_at),
                        ("key_id", key_id)):
        if not isinstance(value, str):
            raise TypeError(name + " must be a string")
    if not isinstance(key_version, int) or isinstance(key_version, bool):
        raise TypeError("key_version must be an integer")
    if not isinstance(private_key, bytes) or len(private_key) != auth_module.KEY_LENGTH:
        raise SigningKeyInvalid("An Ed25519 private key is 32 bytes.")

    if result.outcome not in DECISION_OUTCOMES:
        raise ReceiptOutcomeIneligible(
            "ERROR is not a decision and emits no receipt.")

    _check_shape_for_outcome(result.outcome, authorization, execution)

    rulebook_value = pinned.value()
    payload = {
        "receipt_id": receipt_id,
        "spec_version": SPEC_VERSION,
        "created_at": created_at,
        "rulebook": {"rulebook_id": rulebook_value["rulebook_id"],
                     "version": rulebook_value["version"], "digest": pinned.digest},
        "candidate_digest": canon.digest(candidate),
        "evidence_digest": snap.digest,
        "result": result.value(),
        "replay": {"mode": REPLAY_MODE},
    }
    if authorization is not None:
        payload["authorization_id"] = authorization.authorization_id
    if execution is not None:
        payload["execution"] = execution

    signing_bytes = canon.canonicalize(payload).encode("utf-8")
    try:
        signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(signing_bytes)
    except Exception:
        raise SigningKeyInvalid("The private key is not a usable Ed25519 key.") from None

    completed = dict(payload)
    completed["signature"] = {
        "alg": auth_module.ALGORITHM, "key_id": key_id, "key_version": key_version,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    schema.validate(completed, RECEIPT_SCHEMA_ID, registry)
    return FrozenReceipt(canonical=canon.canonicalize(completed), receipt_id=receipt_id,
                         outcome=result.outcome)


def verify_receipt(value, keys, registry):
    """Establish that a receipt is authentic and unaltered. This is not replay.

    The rulebook, candidate, and snapshot are not seen here, so nothing is claimed about whether
    the recorded decision is correct. The report says `replayed = False`.
    """
    if not isinstance(value, dict):
        raise TypeError("a receipt value must be a mapping")
    schema.validate(value, RECEIPT_SCHEMA_ID, registry)

    if value["replay"]["mode"] != REPLAY_MODE:
        raise ReceiptBindingMismatch("Unsupported replay mode.")

    block = value["signature"]
    identity = (block["key_id"], block["key_version"])
    entry = keys.get(identity)
    if entry is None:
        raise SigningKeyUnknown("No receipt key in the registry matches " + repr(identity))
    # A retired key may not sign new receipts, but still verifies what it already signed:
    # spec/receipt-and-replay.md, so that "offline-replayable" stays true.
    if entry.get("status") == "revoked":
        raise SigningKeyRetired("The receipt signing key is revoked.")

    try:
        signature = base64.b64decode(block["value"], validate=True)
    except Exception:
        raise SignatureMalformed("The signature value is not valid base64.") from None

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
            "The signature does not verify over the receipt's payload.") from None

    outcome = value["result"]["outcome"]
    if outcome not in DECISION_OUTCOMES:
        raise ReceiptOutcomeIneligible("ERROR is not a decision and emits no receipt.")
    _check_shape_for_outcome(outcome, value.get("authorization_id"), value.get("execution"))

    return ReceiptVerification(receipt_id=value["receipt_id"], outcome=outcome,
                               key_id=block["key_id"], key_version=block["key_version"],
                               replay_mode=value["replay"]["mode"], signature_valid=True)


def replay_receipt(value, rulebook_source, candidate, snapshot_value, receipt_keys, registry,
                   authorization=None, authorization_keys=None, verification_time=None):
    """Recompute the recorded decision from the exact recorded inputs and compare.

    Nothing is reacquired, rerun, or re-executed. `replay.mode` is `recompute-decision` and that
    constant is the whole promise.
    """
    verified = verify_receipt(value, receipt_keys, registry)

    for name, body in (("rulebook", rulebook_source), ("candidate", candidate),
                       ("snapshot", snapshot_value)):
        if body is None:
            raise ReplayBodyMissing("Replay needs the " + name + " body, which was not supplied.")

    pinned = rulebook.load_rulebook_bytes(rulebook_source, registry)
    recorded = value["rulebook"]
    if (pinned.digest != recorded["digest"] or pinned.rulebook_id != recorded["rulebook_id"]
            or pinned.version != recorded["version"]):
        raise ReplayBodyMismatch("The supplied rulebook is not the one the receipt records.")

    if canon.digest(candidate) != value["candidate_digest"]:
        raise ReplayBodyMismatch("The supplied candidate is not the one the receipt records.")

    frozen = snapshot.verify_snapshot_value(snapshot_value, pinned, registry)
    if frozen.digest != value["evidence_digest"]:
        raise ReplayBodyMismatch("The supplied snapshot is not the one the receipt records.")

    recomputed = gate.evaluate(pinned, candidate, snapshot_value, registry)
    recorded_result = canon.canonicalize(value["result"])
    if recomputed.canonical != recorded_result:
        raise ReplayResultMismatch(
            "The recomputed decision differs from the one the receipt records.")

    authorization_verified = False
    if value.get("authorization_id") is not None:
        if authorization is not None:
            if authorization_keys is None or verification_time is None:
                raise ReplayBodyMissing(
                    "Verifying the referenced authorization needs its key registry and an "
                    "instant to check it against.")
            if authorization.get("authorization_id") != value["authorization_id"]:
                raise ReceiptBindingMismatch(
                    "The supplied authorization is not the one the receipt names.")
            for field, bound in (("action_digest", value["candidate_digest"]),
                                 ("rulebook_digest", value["rulebook"]["digest"]),
                                 ("evidence_digest", value["evidence_digest"])):
                if authorization.get(field) != bound:
                    raise ReceiptBindingMismatch(
                        "The authorization's %s is not the receipt's." % field)
            auth_module.verify_authorization(
                authorization, pinned, candidate, frozen, recomputed,
                authorization["runtime_id"], verification_time, authorization_keys, registry)
            authorization_verified = True

    return ReplayVerification(
        receipt_id=verified.receipt_id, outcome=verified.outcome, signature_valid=True,
        bodies_matched=True, result_recomputed=True, result_matched=True,
        authorization_verified=authorization_verified,
        recomputed_canonical=recomputed.canonical)


def _check_shape_for_outcome(outcome, authorization, execution):
    """A negative decision carries no action authority and must not look as though it might."""
    if outcome in ("BLOCK", "HOLD"):
        if authorization is not None:
            raise ReceiptBindingMismatch(
                "A %s decision authorizes nothing, so it names no authorization." % outcome)
        if execution is not None:
            raise ReceiptBindingMismatch(
                "A %s decision authorizes nothing, so nothing was executed." % outcome)
