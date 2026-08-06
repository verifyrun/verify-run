"""Derive the Decision Replay conformance bundles from this repository's golden vectors.

The golden vectors under `fixtures/receipts/` are the single source of truth. They are written for
this implementation's own suite, so they name Python file paths, YAML sources and reason codes.
A conformance bundle must be consumable by an implementation written in any language, so this
tool materializes each vector into finished, language-neutral artifacts: canonical JSON bodies, a
signed receipt, and a trust anchor holding public keys only.

Every bundle records the vector it came from and that vector's digest. `tools/run_conformance.py`
re-checks both, so a bundle can never drift away from the vector it claims to represent.

Run it from the repository root with the runtime's own dependencies available:

    python3 tools/build_conformance_fixtures.py

It writes `conformance/decision-replay-v1/fixtures/`. It is a derivation tool, not part of the
normative contract, and it decides nothing: the expected observations come from the vectors.
"""

import base64
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VECTORS = REPO / "fixtures" / "receipts"
OUT = REPO / "conformance" / "decision-replay-v1" / "fixtures"

# The neutral error categories the profile declares. An implementation's own reason codes are
# mapped onto these by its adapter, which is why the contract can be vendor-neutral without
# pretending every implementation spells its failures the same way.
CATEGORY = {
    "signature_invalid": "signature_invalid",
    "signature_malformed": "signature_malformed",
    "signing_key_unknown": "key_untrusted",
    "signing_key_retired": "key_untrusted",
    "receipt_schema_invalid": "artifact_schema_invalid",
    "store_artifact_noncanonical": "artifact_noncanonical",
    "replay_body_missing": "input_missing",
    "replay_body_mismatch": "binding_mismatch",
    "receipt_binding_mismatch": "binding_mismatch",
    "replay_result_mismatch": "binding_mismatch",
}

BASE_VECTOR = "accept_allow_with_authorization_and_execution.json"

# A refusal must be attributable to a declared category, but the ORDER in which an implementation
# checks shape, signature, trust and bindings is its own business: a verifier that notices a
# malformed artifact before it checks the signature is not less correct. So each mutation family
# declares the set of categories a correct refusal may carry, and the profile requires membership
# rather than a single value. Narrowing these to one value each would standardize this
# implementation's check order as though it were part of the contract.
CATEGORY_FAMILY = {
    "field": ["signature_invalid", "artifact_schema_invalid", "binding_mismatch"],
    "execution": ["signature_invalid", "artifact_schema_invalid", "binding_mismatch"],
    "result_outcome": ["signature_invalid", "artifact_schema_invalid", "binding_mismatch"],
    "replay_mode": ["artifact_schema_invalid"],
    "drop_signature": ["artifact_schema_invalid", "signature_invalid"],
    "sig": ["signature_invalid", "signature_malformed"],
    "sigfield": ["key_untrusted", "signature_invalid"],
    "signature_copy": ["signature_invalid"],
    "signed_by_other": ["key_untrusted"],
    "key_absent": ["key_untrusted"],
    "key_revoked": ["key_untrusted"],
    "omit": ["input_missing"],
    "swap_rulebook": ["binding_mismatch"],
    "swap_candidate": ["binding_mismatch"],
    "swap_snapshot": ["binding_mismatch"],
    "swap_auth_id": ["binding_mismatch"],
}


def allowed_categories(kind, reference_reason_code):
    allowed = list(CATEGORY_FAMILY[kind])
    mapped = CATEGORY.get(reference_reason_code)
    if mapped and mapped not in allowed:
        allowed.append(mapped)
    return sorted(allowed)



def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_vector(name):
    path = VECTORS / name
    raw = path.read_bytes()
    return json.loads(raw), path.relative_to(REPO).as_posix(), sha(raw)


def rulebook_body(vector):
    """The rulebook exactly as a store records it: canonical JSON of the parsed document.

    spec/local-store.md fixes this. Canonical JSON is valid input to the strict YAML loader, so
    an implementation reproduces the identical pinned digest from it and no bundle needs a YAML
    parser to verify a decision.
    """
    import yaml
    return canonical(yaml.safe_load(vector["rulebook_source"]))


def sign(payload, private_key_hex):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return base64.b64encode(key.sign(canonical(payload))).decode("ascii")


def public_of(private_key_hex):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return key.public_key().public_bytes_raw().hex()


def trust(receipt_public_hex, authorization_public_hex, receipt_status="active"):
    return {"trust_version": 1,
            "authorization": [{"key_id": "auth-key", "key_version": 1,
                               "public_key_hex": authorization_public_hex, "status": "active"}],
            "receipt": [{"key_id": "receipt-key", "key_version": 1,
                         "public_key_hex": receipt_public_hex, "status": receipt_status}]}


class Bundle:
    """One conformance bundle: finished artifacts plus the provenance of the vector behind them."""

    def __init__(self, name, source_path, source_digest, note):
        self.name = name
        self.source = {"path": source_path, "sha256": source_digest}
        self.note = note
        self.files = {}

    def put(self, filename, data):
        self.files[filename] = data

    def write(self):
        directory = OUT / self.name
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
        digests = {}
        for filename, data in sorted(self.files.items()):
            (directory / filename).write_bytes(data)
            digests[filename] = sha(data)
        return {"bundle": self.name, "derived_from": self.source, "note": self.note,
                "files": digests}


def base_bundle(name, vector, path, digest, note, *, receipt_status="active"):
    bundle = Bundle(name, path, digest, note)
    bundle.put("rulebook.json", rulebook_body(vector))
    bundle.put("rulebook.yaml", vector["rulebook_source"].encode("utf-8"))
    bundle.put("candidate.json", canonical(vector["candidate"]))
    bundle.put("snapshot.json", canonical(vector["snapshot"]))
    if vector.get("authorization") is not None:
        bundle.put("authorization.json", canonical(vector["authorization"]))
    bundle.put("receipt.json", vector["receipt_canonical"].encode("utf-8"))
    bundle.put("trust.json", canonical(trust(vector["receipt_public_key_hex"],
                                             vector.get("authorization_public_key_hex", "00" * 32),
                                             receipt_status)))
    return bundle


def resign(payload, private_key_hex, key_id="receipt-key", key_version=1, alg="ed25519"):
    signed = dict(payload)
    signed["signature"] = {"alg": alg, "key_id": key_id, "key_version": key_version,
                           "value": sign(payload, private_key_hex)}
    return signed


def mutate(vector, mutation):
    """Apply one declared mutation and return (receipt_bytes, trust_value, dropped_bodies)."""
    receipt = json.loads(vector["receipt_canonical"])
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    keys = trust(vector["receipt_public_key_hex"],
                 vector.get("authorization_public_key_hex", "00" * 32))
    dropped = []
    kind = mutation["kind"]

    if kind == "field":
        # A protected field changes; the old signature is retained, so verification must fail.
        receipt[mutation["field"]] = mutation["value"]
    elif kind == "execution":
        receipt["execution"] = mutation["value"]
    elif kind == "result_outcome":
        receipt["result"] = copy.deepcopy(receipt["result"])
        receipt["result"]["outcome"] = mutation["value"]
    elif kind == "replay_mode":
        receipt["replay"] = {"mode": mutation["value"]}
    elif kind == "drop_signature":
        receipt.pop("signature", None)
    elif kind == "sig":
        receipt["signature"] = dict(receipt["signature"], value=mutation["value"])
    elif kind == "sigfield":
        receipt["signature"] = dict(receipt["signature"], **{mutation["field"]: mutation["value"]})
    elif kind == "signature_copy":
        other, _, _ = read_vector(mutation.get("from", "accept_block_decision.json"))
        receipt["signature"] = dict(receipt["signature"],
                                    value=json.loads(other["receipt_canonical"])["signature"]["value"])
    elif kind == "signed_by_other":
        # A perfectly valid signature under a key nobody trusts. The refusal must be about trust,
        # so the signature block names an identity the registry does not hold: a verifier that
        # looked the key up by content rather than by declared identity would slip past this.
        other_private = mutation.get("private_key_hex", "20" * 32)
        receipt = resign(payload, other_private, key_id="untrusted-key")
    elif kind == "key_absent":
        keys["receipt"] = [dict(keys["receipt"][0], key_id="some-other-key")]
    elif kind == "key_revoked":
        keys["receipt"] = [dict(keys["receipt"][0], status="revoked")]
    elif kind == "omit":
        dropped.append(mutation["body"])
    elif kind in ("swap_rulebook", "swap_candidate", "swap_snapshot", "swap_auth_id"):
        pass                                    # handled by the caller, which has both vectors
    else:
        raise SystemExit("unhandled mutation kind: " + kind)

    text = canonical(receipt) if kind != "unchanged" else vector["receipt_canonical"].encode()
    return text, keys, dropped


def build():
    OUT.mkdir(parents=True, exist_ok=True)
    records = []

    # --- positive bundles -----------------------------------------------------------------------
    POSITIVE = [
        ("allow-with-execution", BASE_VECTOR,
         "ALLOW carrying an execution acknowledgment. Its authorization interval elapsed in 2026, "
         "so replaying it proves historical recomputation does not depend on present spendability."),
        ("allow-without-execution", "accept_allow_without_execution.json",
         "ALLOW with no execution acknowledgment. Absence of an acknowledgment is not evidence "
         "that the action ran."),
        ("block", "accept_block_decision.json",
         "BLOCK. A negative decision carries no authorization and no execution record."),
        ("hold", "accept_hold_decision.json",
         "HOLD. Unsettled evidence is not a failure and is never reported as BLOCK."),
    ]
    for name, vector_name, note in POSITIVE:
        vector, path, digest = read_vector(vector_name)
        records.append(base_bundle(name, vector, path, digest, note).write())

    vector, path, digest = read_vector(BASE_VECTOR)
    records.append(base_bundle(
        "allow-retired-key", vector, path, digest,
        "The signing key is retired. Retirement stops new signing; it does not repudiate what the "
        "key already signed, so historical verification still succeeds.",
        receipt_status="retired").write())

    # --- negative bundles ------------------------------------------------------------------------
    NEGATIVE = [
        "reject_altered_candidate_digest.json", "reject_altered_evidence_digest.json",
        "reject_altered_created_at.json", "reject_altered_receipt_id.json",
        "reject_altered_authorization_reference.json", "reject_altered_nested_result.json",
        "reject_altered_execution_acknowledgment.json", "reject_unknown_field.json",
        "reject_unsupported_replay_mode.json", "reject_no_signature.json",
        "reject_malformed_signature.json", "reject_invalid_signature.json",
        "reject_copied_signature.json", "reject_altered_key_id.json",
        "reject_altered_key_version.json", "reject_unknown_receipt_key.json",
        "reject_untrusted_key_valid_signature.json",
        "reject_missing_rulebook_body.json", "reject_missing_candidate_body.json",
        "reject_missing_snapshot_body.json", "reject_wrong_rulebook_body.json",
        "reject_wrong_candidate_body.json", "reject_wrong_snapshot_body.json",
        "reject_authorization_not_the_one_named.json",
    ]
    base_vector, base_path, base_digest = read_vector(BASE_VECTOR)
    for vector_name in NEGATIVE:
        vector, path, digest = read_vector(vector_name)
        name = vector_name[len("reject_"):-len(".json")].replace("_", "-")
        mutation = vector["mutation"]
        bundle = Bundle(name, path, digest, vector.get("description", ""))

        rulebook = rulebook_body(base_vector)
        candidate = canonical(base_vector["candidate"])
        snapshot = canonical(base_vector["snapshot"])
        authorization = canonical(base_vector["authorization"])

        if mutation["kind"] == "swap_rulebook":
            other, _, _ = read_vector("accept_block_decision.json")
            rulebook = rulebook_body(other)
        elif mutation["kind"] == "swap_candidate":
            other, _, _ = read_vector("accept_block_decision.json")
            candidate = canonical(other["candidate"])
        elif mutation["kind"] == "swap_snapshot":
            other, _, _ = read_vector("accept_block_decision.json")
            snapshot = canonical(other["snapshot"])
        elif mutation["kind"] == "swap_auth_id":
            altered = dict(base_vector["authorization"],
                           authorization_id="a-not-the-one-named")
            authorization = canonical(altered)

        receipt_bytes, keys, dropped = mutate(base_vector, mutation)

        bundle.put("rulebook.yaml", base_vector["rulebook_source"].encode("utf-8"))
        if "rulebook" not in dropped:
            bundle.put("rulebook.json", rulebook)
        if "candidate" not in dropped:
            bundle.put("candidate.json", candidate)
        if "snapshot" not in dropped:
            bundle.put("snapshot.json", snapshot)
        bundle.put("authorization.json", authorization)
        bundle.put("receipt.json", receipt_bytes)
        bundle.put("trust.json", canonical(keys))
        record = bundle.write()
        record["expected"] = {
            "conformance": "refused",
            "stage": vector["stage"],
            "error_category_any_of": allowed_categories(mutation["kind"],
                                                        vector["expected"]["reason_code"]),
            "reference_reason_code": vector["expected"]["reason_code"],
        }
        records.append(record)

    (OUT / "_derivation.json").write_text(
        json.dumps({"note": "Provenance of every bundle. tools/build_conformance_fixtures.py "
                            "writes this; tools/run_conformance.py re-checks it.",
                    "base_vector": {"path": base_path, "sha256": base_digest},
                    "bundles": records}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print("bundles: %d" % len(records))
    for record in records:
        print("  %-38s %2d files  <- %s" % (record["bundle"], len(record["files"]),
                                            record["derived_from"]["path"]))
    return records


if __name__ == "__main__":
    sys.exit(0 if build() else 1)
