"""Write the fixture manifest and the machine-readable profile from the built bundles.

The manifest is the runner's oracle: it names, for every fixture, which normative requirements it
exercises and exactly what a conforming implementation must be observed to do. It is generated so
that digests cannot drift from the bytes on disk, but the requirement mapping below is authored by
hand, because deciding what a fixture proves is not a mechanical question.
"""

import hashlib
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROOT = REPO / "conformance" / "decision-replay-v1"
FIXTURES = ROOT / "fixtures"

PROFILE_ID = "decision-replay-v1"
PROFILE_VERSION = "1.0.0"

# Which requirements each bundle is a witness for. Authored, not inferred.
POSITIVE = {
    "allow-with-execution": [
        "DR-1.1", "DR-1.2", "DR-1.3", "DR-2.1", "DR-3.1", "DR-3.2", "DR-3.4",
        "DR-4.1", "DR-4.2", "DR-4.3", "DR-4.4", "DR-4.6",
        "DR-6.1", "DR-6.2", "DR-6.3", "DR-6.4", "DR-6.5", "DR-6.6", "DR-7.1"],
    "allow-without-execution": ["DR-2.1", "DR-6.1", "DR-7.3"],
    "block": ["DR-2.1", "DR-3.3", "DR-6.1"],
    "hold": ["DR-2.1", "DR-2.3", "DR-3.3", "DR-6.1"],
    "allow-retired-key": ["DR-6.8"],
}

TERMINAL = {"allow-with-execution": "ALLOW", "allow-without-execution": "ALLOW",
            "block": "BLOCK", "hold": "HOLD", "allow-retired-key": "ALLOW"}

# Negative bundles: which requirements each refusal witnesses.
NEGATIVE = {
    "altered-candidate-digest": ["DR-4.5", "DR-8.2"],
    "altered-evidence-digest": ["DR-4.5", "DR-8.2"],
    "altered-created-at": ["DR-4.5", "DR-8.2"],
    "altered-receipt-id": ["DR-4.5", "DR-8.2"],
    "altered-authorization-reference": ["DR-4.5", "DR-8.2"],
    "altered-nested-result": ["DR-4.3", "DR-4.5", "DR-2.4"],
    "altered-execution-acknowledgment": ["DR-7.2", "DR-4.5"],
    "unknown-field": ["DR-5.5", "DR-8.2"],
    "unsupported-replay-mode": ["DR-5.4", "DR-8.1"],
    "no-signature": ["DR-5.3", "DR-4.4"],
    "malformed-signature": ["DR-5.3"],
    "invalid-signature": ["DR-5.3", "DR-4.5"],
    "copied-signature": ["DR-5.3", "DR-4.5"],
    "altered-key-id": ["DR-5.1", "DR-4.4"],
    "altered-key-version": ["DR-5.1", "DR-4.4"],
    "unknown-receipt-key": ["DR-5.1"],
    "untrusted-key-valid-signature": ["DR-5.2", "DR-4.6"],
    "missing-rulebook-body": ["DR-1.1", "DR-6.7"],
    "missing-candidate-body": ["DR-1.1", "DR-6.7"],
    "missing-snapshot-body": ["DR-1.1", "DR-6.7"],
    "wrong-rulebook-body": ["DR-6.7", "DR-4.2"],
    "wrong-candidate-body": ["DR-6.7", "DR-4.2"],
    "wrong-snapshot-body": ["DR-6.7", "DR-4.2"],
    "authorization-not-the-one-named": ["DR-3.1", "DR-6.2"],
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files_of(bundle):
    directory = FIXTURES / bundle
    return {p.name: sha(p) for p in sorted(directory.iterdir()) if p.is_file()}


def build():
    derivation = json.loads((FIXTURES / "_derivation.json").read_text(encoding="utf-8"))
    by_name = {record["bundle"]: record for record in derivation["bundles"]}
    fixtures = []

    for bundle, requirements in sorted(POSITIVE.items()):
        record = by_name[bundle]
        fixtures.append({
            "fixture_id": "positive/" + bundle,
            "bundle": bundle,
            "polarity": "positive",
            "operation": "replay",
            "required": True,
            "requirements": requirements,
            "expected": {"conformance": "accepted", "terminal": TERMINAL[bundle],
                         "signature_verified": True, "recomputed": True},
            "files": files_of(bundle),
            "derived_from": record["derived_from"],
            "evidence_acquisition_permitted": False,
            "action_execution_permitted": False,
            "current_time_relevant": False,
            "note": record["note"],
        })

    # One repeat of the same bundle, to witness that settlement is reproducible rather than
    # merely observed once.
    repeat = dict(fixtures[[f["bundle"] for f in fixtures].index("allow-with-execution")])
    repeat = json.loads(json.dumps(repeat))
    repeat["fixture_id"] = "positive/allow-with-execution-repeat"
    repeat["requirements"] = ["DR-2.2"]
    repeat["note"] = ("The same declared inputs a second time. A terminal that is observed once is "
                      "not yet known to be reproducible.")
    fixtures.append(repeat)

    for bundle, requirements in sorted(NEGATIVE.items()):
        record = by_name[bundle]
        expected = dict(record["expected"])
        expected.pop("reference_reason_code", None)
        expected.pop("stage", None)
        fixtures.append({
            "fixture_id": "negative/" + bundle,
            "bundle": bundle,
            "polarity": "negative",
            "operation": "replay",
            "required": True,
            # Every negative bundle derives from an ALLOW base, so accepting one is exactly
            # what defaulting to acceptance looks like: DR-2.5 is witnessed by all of them.
            "requirements": sorted(set(requirements) | {"DR-2.5"}),
            "expected": expected,
            "files": files_of(bundle),
            "derived_from": record["derived_from"],
            "reference_reason_code": record["expected"]["reference_reason_code"],
            "reference_stage": record["expected"]["stage"],
            "evidence_acquisition_permitted": False,
            "action_execution_permitted": False,
            "current_time_relevant": False,
            "note": record["note"],
        })

    manifest = {
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "note": "Every fixture is a finished artifact bundle. `derived_from` names the golden "
                "vector in this repository that the bundle was materialized from, and its digest, "
                "so a bundle can never drift away from the vector it claims to represent. No "
                "fixture permits evidence acquisition or action execution: a bundle contains no "
                "evidence source and no executable, so a replay that succeeds has demonstrably "
                "done neither.",
        "fixtures": sorted(fixtures, key=lambda f: f["fixture_id"]),
    }
    (FIXTURES / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    covered = sorted({r for f in fixtures for r in f["requirements"]})
    profile = {
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "status": "draft",
        "title": "Decision Replay Conformance Profile v1",
        "normative_document": "../../docs/conformance/decision-replay-v1.md",
        "fixture_manifest": "fixtures/manifest.json",
        "result_schema": "result.schema.json",
        "adapter_protocol": "adapter-protocol.md",
        "terminal_classes": ["ALLOW", "BLOCK", "HOLD", "ERROR"],
        "error_categories": ["signature_invalid", "signature_malformed", "key_untrusted",
                             "artifact_schema_invalid", "artifact_noncanonical",
                             "binding_mismatch", "input_missing",
                             "authorization_not_spendable"],
        "canonicalization_profile": {
            "id": "verify-canonical-json-1",
            "description": "UTF-8, object members sorted by code point, no insignificant "
                           "whitespace, integers only within plus or minus (2^53 - 1), no "
                           "floating point, no lone surrogates.",
            "normative_source": "spec/canonicalization.md"},
        "signing_profile": {
            "algorithms": ["ed25519"],
            "signed_bytes": "the canonical artifact with its own signature member omitted",
            "note": "v1 fixes Ed25519 because the reference implementation and every fixture use "
                    "it. This is a stated limit of v1, not a claim of algorithm neutrality."},
        "replay_modes": ["recompute-decision"],
        "requirements_covered": covered,
        "capability_flags": {
            "live_spend": "Optional. An implementation that exposes spending of an externally "
                          "supplied authorization must bound it by the validity interval. The "
                          "reference implementation does not expose this surface, so v1 carries "
                          "no fixture for it.",
            "historical_replay": "Required."},
        "nonclaims": [
            "truth of the declared evidence in the external world",
            "quality or wisdom of the rulebook",
            "legitimacy of the declared authority",
            "sandboxing or confinement of the authorized action",
            "attestation of the executed program's bytes",
            "exactly-once external side effects",
            "uniqueness of a single-use identifier beyond the declared store scope",
            "correctness of any model that produced the evidence",
            "proof that the action's external effects occurred",
            "regulatory, legal, or contractual compliance",
            "absence of compromise outside the declared boundary"],
        "reference_implementation": {
            "name": "verify-run",
            "version": "0.1.0a2",
            "source": "https://github.com/verifyrun/verify-run",
            "distribution": "https://pypi.org/project/verify-run/0.1.0a2/",
            "note": "First reference implementation. Conformance is defined by the fixtures and "
                    "the normative document, not by this implementation's behavior."},
        "compatibility_notes": [
            "Artifacts written by verify-run 0.1.0a1 verify and replay under 0.1.0a2 unchanged, "
            "including after their authorization's validity interval has elapsed.",
            "Profile versioning is independent of any implementation's package versioning."],
    }
    (ROOT / "profile.json").write_text(
        json.dumps(profile, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    print("fixtures: %d (%d positive, %d negative)"
          % (len(fixtures), len([f for f in fixtures if f["polarity"] == "positive"]),
             len([f for f in fixtures if f["polarity"] == "negative"])))
    print("requirements covered: %d -> %s" % (len(covered), ", ".join(covered)))


if __name__ == "__main__":
    build()
