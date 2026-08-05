"""Closure Unit 9 — acknowledgment, signed receipts, verification, and deterministic replay."""

import base64
import copy
import dataclasses
import itertools
import json
import pathlib
import unittest

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from vfy import authorization, canon, gate, load, receipt, rulebook, schema, snapshot
from vfy.errors import VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
RECEIPT_DIR = REPO_ROOT / "fixtures" / "receipts"

# TEST-ONLY published constants. They authorize nothing.
AUTH_SEED = bytes(range(32))
RECEIPT_SEED = bytes(range(64, 96))
OTHER_SEED = bytes(range(96, 128))
FROZEN_AT = "2026-08-05T00:00:00Z"


def _public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _case(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _receipt_keys(status="active", key_id="receipt-key", key_version=1, seed=RECEIPT_SEED):
    return {(key_id, key_version): {"public_key": _public(seed), "status": status}}


def _auth_keys():
    return authorization.build_key_registry(
        [{"key_id": "auth-key", "key_version": 1, "public_key": _public(AUTH_SEED)}])


class Chain:
    """The whole governed computation for one fixture, rebuilt from its recorded bodies."""

    def __init__(self, case, registry):
        self.registry = registry
        self.case = case
        self.source = case["rulebook_source"].encode("utf-8")
        self.pinned = rulebook.load_rulebook_bytes(self.source, registry)
        self.candidate = case["candidate"]
        self.snapshot = snapshot.build_snapshot(self.pinned, "s-1", FROZEN_AT,
                                                case["acquisitions"], registry)
        self.result = gate.evaluate(self.pinned, self.candidate, self.snapshot.value(),
                                    registry)
        self.authorization = case["authorization"]

    def issue(self, execution=None, seed=RECEIPT_SEED, key_id="receipt-key", key_version=1,
              auth=None):
        frozen_auth = None
        if self.result.outcome == "ALLOW":
            frozen_auth = auth if auth is not None else _FrozenAuthStub(self.authorization)
        return receipt.issue_receipt(
            self.pinned, self.candidate, self.snapshot, self.result, frozen_auth,
            execution if execution is not None else self.case["receipt"].get("execution"),
            "r-1", "2026-08-05T00:00:06Z", key_id, key_version, seed, self.registry)


class _FrozenAuthStub:
    """Only the field issue_receipt reads: the authorization's own identifier."""

    def __init__(self, value):
        self.authorization_id = value["authorization_id"] if value else None


class AcceptedVectors(unittest.TestCase):
    def test_every_accepted_fixture_is_reproduced_byte_for_byte(self):
        registry = _registry()
        paths = sorted(RECEIPT_DIR.glob("accept_*.json"))
        self.assertGreaterEqual(len(paths), 4)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                chain = Chain(case, registry)
                issued = chain.issue()
                self.assertEqual(issued.canonical, case["receipt_canonical"])
                self.assertEqual(issued.value()["signature"]["value"], case["signature"])
                self.assertEqual(canon.canonicalize(case["unsigned_payload"]),
                                 case["unsigned_canonical"])

    def test_every_accepted_fixture_verifies_and_replays(self):
        registry = _registry()
        for path in sorted(RECEIPT_DIR.glob("accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                chain = Chain(case, registry)
                verified = receipt.verify_receipt(case["receipt"], _receipt_keys(), registry)
                self.assertTrue(verified.signature_valid)
                self.assertFalse(verified.replayed)
                replayed = receipt.replay_receipt(
                    case["receipt"], chain.source, chain.candidate, case["snapshot"],
                    _receipt_keys(), registry,
                    authorization=case["authorization"],
                    authorization_keys=_auth_keys() if case["authorization"] else None,
                    verification_time="2026-08-05T00:01:00Z" if case["authorization"] else None)
                self.assertTrue(replayed.result_matched)
                self.assertTrue(replayed.replayed)
                self.assertEqual(replayed.outcome, case["expected_outcome"])

    def test_signing_is_deterministic(self):
        registry = _registry()
        chain = Chain(_case(RECEIPT_DIR / "accept_block_decision.json"), registry)
        self.assertEqual(chain.issue().canonical, chain.issue().canonical)

    def test_the_signature_verifies_with_the_library_directly(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        value = case["receipt"]
        payload = {k: v for k, v in value.items() if k != "signature"}
        Ed25519PublicKey.from_public_bytes(_public(RECEIPT_SEED)).verify(
            base64.b64decode(value["signature"]["value"]),
            canon.canonicalize(payload).encode("utf-8"))


class TerminalOutcomes(unittest.TestCase):
    def test_all_three_decision_outcomes_have_a_receipt(self):
        registry = _registry()
        outcomes = set()
        for path in sorted(RECEIPT_DIR.glob("accept_*.json")):
            case = _case(path)
            verified = receipt.verify_receipt(case["receipt"], _receipt_keys(), registry)
            outcomes.add(verified.outcome)
        self.assertEqual(outcomes, {"ALLOW", "BLOCK", "HOLD"})

    def test_error_emits_no_receipt(self):
        registry = _registry()
        chain = Chain(_case(RECEIPT_DIR / "accept_block_decision.json"), registry)
        error = gate.evaluate(chain.pinned, {"kind": "command"}, chain.snapshot.value(),
                              registry)
        self.assertEqual(error.outcome, "ERROR")
        with self.assertRaises(VerifyError) as caught:
            receipt.issue_receipt(chain.pinned, chain.candidate, chain.snapshot, error, None,
                                  None, "r", "2026-08-05T00:00:06Z", "receipt-key", 1,
                                  RECEIPT_SEED, registry)
        self.assertEqual(caught.exception.code, "receipt_outcome_ineligible")

    def test_a_negative_decision_carries_no_action_authority(self):
        registry = _registry()
        chain = Chain(_case(RECEIPT_DIR / "accept_block_decision.json"), registry)
        for authorization_stub, execution in ((_FrozenAuthStub({"authorization_id": "a"}), None),
                                              (None, {"acknowledged": True})):
            with self.subTest(carrying="authorization" if execution is None else "execution"):
                with self.assertRaises(VerifyError) as caught:
                    receipt.issue_receipt(chain.pinned, chain.candidate, chain.snapshot,
                                          chain.result, authorization_stub, execution, "r",
                                          "2026-08-05T00:00:06Z", "receipt-key", 1,
                                          RECEIPT_SEED, registry)
                self.assertEqual(caught.exception.code, "receipt_binding_mismatch")

    def test_a_block_receipt_carrying_authority_is_refused_at_verification_too(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        value = copy.deepcopy(case["receipt"])
        value["authorization_id"] = "smuggled"
        # Re-sign so the only defect is the shape, not the signature.
        payload = {k: v for k, v in value.items() if k != "signature"}
        signature = Ed25519PrivateKey.from_private_bytes(RECEIPT_SEED).sign(
            canon.canonicalize(payload).encode("utf-8"))
        value["signature"]["value"] = base64.b64encode(signature).decode("ascii")
        with self.assertRaises(VerifyError) as caught:
            receipt.verify_receipt(value, _receipt_keys(), registry)
        self.assertEqual(caught.exception.code, "receipt_binding_mismatch")


class RejectedVectors(unittest.TestCase):
    def test_every_reject_fixture_carries_its_code(self):
        registry = _registry()
        base = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        paths = [p for p in sorted(RECEIPT_DIR.glob("reject_*.json"))
                 if not p.stem.startswith("reject_issue_")]
        self.assertGreaterEqual(len(paths), 25)
        for path in paths:
            case = _case(path)
            mutation, kind = case["mutation"], case["mutation"]["kind"]
            with self.subTest(fixture=path.name):
                chain = Chain(base, registry)
                value = copy.deepcopy(base["receipt"])
                keys = _receipt_keys()
                source, candidate, snapshot_value = (chain.source, chain.candidate,
                                                     base["snapshot"])
                auth = copy.deepcopy(base["authorization"])

                if kind == "field":
                    value[mutation["field"]] = mutation["value"]
                elif kind == "sig":
                    value["signature"]["value"] = mutation["value"]
                elif kind == "sigfield":
                    value["signature"][mutation["field"]] = mutation["value"]
                elif kind == "result_outcome":
                    value["result"]["outcome"] = mutation["value"]
                elif kind == "execution":
                    value["execution"] = mutation["value"]
                elif kind == "replay_mode":
                    value["replay"]["mode"] = mutation["value"]
                elif kind == "drop_signature":
                    value.pop("signature")
                elif kind == "key_absent":
                    keys = {}
                elif kind == "key_revoked":
                    keys = _receipt_keys(status="revoked")
                elif kind == "signed_by_other":
                    value = chain.issue(seed=OTHER_SEED, key_id="untrusted").value()
                elif kind == "signature_copy":
                    other = Chain(_case(RECEIPT_DIR / "accept_block_decision.json"), registry)
                    value["signature"] = other.issue().value()["signature"]
                elif kind == "omit":
                    if mutation["body"] == "rulebook":
                        source = None
                    elif mutation["body"] == "candidate":
                        candidate = None
                    else:
                        snapshot_value = None
                elif kind == "swap_rulebook":
                    source = (REPO_ROOT / "templates" / "agent-guard.yaml").read_bytes()
                elif kind == "swap_candidate":
                    candidate = dict(chain.candidate, candidate_id="different")
                elif kind == "swap_snapshot":
                    snapshot_value = snapshot.build_snapshot(
                        chain.pinned, "s-2", FROZEN_AT,
                        [{"id": "tests", "status": "ok", "value": "passed",
                          "acquired_at": "2026-08-04T23:59:31Z"}], registry).value()
                elif kind == "swap_auth_id":
                    auth = dict(auth, authorization_id="not-the-one-named")

                with self.assertRaises(VerifyError) as caught:
                    if case["stage"] == "verification":
                        receipt.verify_receipt(value, keys, registry)
                    else:
                        receipt.replay_receipt(
                            value, source, candidate, snapshot_value, keys, registry,
                            authorization=auth, authorization_keys=_auth_keys(),
                            verification_time="2026-08-05T00:01:00Z")
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                self.assertEqual(caught.exception.outcome, "ERROR")

    def test_issuance_rejects(self):
        registry = _registry()
        chain = Chain(_case(RECEIPT_DIR / "accept_block_decision.json"), registry)
        with self.assertRaises(VerifyError) as caught:
            receipt.issue_receipt(chain.pinned, chain.candidate, chain.snapshot, chain.result,
                                  None, None, "r", "2026-08-05T00:00:06Z", "receipt-key", 1,
                                  b"short", registry)
        self.assertEqual(caught.exception.code, "signing_key_invalid")


class VerificationVersusReplay(unittest.TestCase):
    def test_verification_alone_makes_no_replay_claim(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        verified = receipt.verify_receipt(case["receipt"], _receipt_keys(), registry)
        self.assertTrue(verified.signature_valid)
        self.assertFalse(verified.replayed)
        self.assertFalse(hasattr(verified, "result_matched"))

    def test_a_receipt_can_verify_while_replay_is_impossible(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        self.assertTrue(receipt.verify_receipt(case["receipt"], _receipt_keys(),
                                               registry).signature_valid)
        with self.assertRaises(VerifyError) as caught:
            receipt.replay_receipt(case["receipt"], None, None, None, _receipt_keys(), registry)
        self.assertEqual(caught.exception.code, "replay_body_missing")

    def test_a_valid_signature_cannot_rescue_a_mismatched_body(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        other = (REPO_ROOT / "templates" / "agent-guard.yaml").read_bytes()
        with self.assertRaises(VerifyError) as caught:
            receipt.replay_receipt(case["receipt"], other, case["candidate"], case["snapshot"],
                                   _receipt_keys(), registry)
        self.assertEqual(caught.exception.code, "replay_body_mismatch")

    def test_replay_catches_divergence_beyond_the_terminal_word(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        chain = Chain(case, registry)
        for field, mutate in (("matched_rule", lambda r: r.update({"matched_rule": "other"})),
                              ("trace", lambda r: r.update({"trace": ["0:other:true"]})),
                              ("reasons", lambda r: r["reasons"][0].update({"code": "rule_hold"})),
                              ("message", lambda r: r["reasons"][0].update({"message": "x"}))):
            value = copy.deepcopy(case["receipt"])
            mutate(value["result"])
            self.assertEqual(value["result"]["outcome"], "ALLOW")   # terminal word unchanged
            payload = {k: v for k, v in value.items() if k != "signature"}
            signature = Ed25519PrivateKey.from_private_bytes(RECEIPT_SEED).sign(
                canon.canonicalize(payload).encode("utf-8"))
            value["signature"]["value"] = base64.b64encode(signature).decode("ascii")
            with self.subTest(diverged=field):
                with self.assertRaises(VerifyError) as caught:
                    receipt.replay_receipt(value, chain.source, chain.candidate,
                                           case["snapshot"], _receipt_keys(), registry)
                self.assertEqual(caught.exception.code, "replay_result_mismatch")

    def test_replay_reacquires_nothing_and_executes_nothing(self):
        source = (REPO_ROOT / "vfy" / "receipt.py").read_text(encoding="utf-8")
        for banned in ("subprocess", "import os", "import time", "import datetime",
                       "import random", "import socket", "urllib", "requests", "open(",
                       "float("):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)


class CrossBinding(unittest.TestCase):
    def test_a_receipt_never_authorizes_retroactively(self):
        # The receipt names an authorization; verifying the receipt does not verify it.
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        verified = receipt.verify_receipt(case["receipt"], _receipt_keys(), registry)
        self.assertFalse(hasattr(verified, "authorization_verified"))
        replayed = receipt.replay_receipt(
            case["receipt"], case["rulebook_source"].encode("utf-8"), case["candidate"],
            case["snapshot"], _receipt_keys(), registry)
        self.assertFalse(replayed.authorization_verified)

    def test_the_authorization_must_bind_the_same_objects(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        for field in ("action_digest", "rulebook_digest", "evidence_digest"):
            auth = copy.deepcopy(case["authorization"])
            auth[field] = "sha256:" + "0" * 64
            with self.subTest(field=field):
                with self.assertRaises(VerifyError) as caught:
                    receipt.replay_receipt(
                        case["receipt"], case["rulebook_source"].encode("utf-8"),
                        case["candidate"], case["snapshot"], _receipt_keys(), registry,
                        authorization=auth, authorization_keys=_auth_keys(),
                        verification_time="2026-08-05T00:01:00Z")
                self.assertEqual(caught.exception.code, "receipt_binding_mismatch")

    def test_the_receipt_and_authorization_may_use_different_keys(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        self.assertNotEqual(_public(AUTH_SEED), _public(RECEIPT_SEED))
        replayed = receipt.replay_receipt(
            case["receipt"], case["rulebook_source"].encode("utf-8"), case["candidate"],
            case["snapshot"], _receipt_keys(), registry, authorization=case["authorization"],
            authorization_keys=_auth_keys(), verification_time="2026-08-05T00:01:00Z")
        self.assertTrue(replayed.authorization_verified)

    def test_the_acknowledgment_is_bound_by_the_receipt_signature(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        value = copy.deepcopy(case["receipt"])
        value["execution"]["exit_status"] = 1
        with self.assertRaises(VerifyError) as caught:
            receipt.verify_receipt(value, _receipt_keys(), registry)
        self.assertEqual(caught.exception.code, "signature_invalid")


class KeyStates(unittest.TestCase):
    def test_a_retired_receipt_key_still_verifies_what_it_signed(self):
        # Deliberately different from authorization: "offline-replayable" would otherwise
        # become false the moment a key rotates.
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        retired = _receipt_keys(status="retired")
        verified = receipt.verify_receipt(case["receipt"], retired, registry)
        self.assertTrue(verified.signature_valid)

    def test_a_revoked_receipt_key_verifies_nothing(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        with self.assertRaises(VerifyError) as caught:
            receipt.verify_receipt(case["receipt"], _receipt_keys(status="revoked"), registry)
        self.assertEqual(caught.exception.code, "signing_key_retired")

    def test_an_untrusted_key_is_unknown_however_valid_its_signature(self):
        registry = _registry()
        chain = Chain(_case(RECEIPT_DIR / "accept_block_decision.json"), registry)
        forged = chain.issue(seed=OTHER_SEED, key_id="attacker")
        with self.assertRaises(VerifyError) as caught:
            receipt.verify_receipt(forged.value(), _receipt_keys(), registry)
        self.assertEqual(caught.exception.code, "signing_key_unknown")

    def test_no_artifact_certifies_itself(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        self.assertNotIn("public_key", json.dumps(case["receipt"]))
        with self.assertRaises(VerifyError):
            receipt.verify_receipt(case["receipt"], {}, registry)


class DeterminismAndImmutability(unittest.TestCase):
    def test_field_order_cannot_change_the_verdict(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        value = case["receipt"]
        for order in itertools.islice(itertools.permutations(sorted(value)), 12):
            shuffled = {key: value[key] for key in order}
            with self.subTest(first=order[0]):
                self.assertTrue(receipt.verify_receipt(shuffled, _receipt_keys(),
                                                       registry).signature_valid)

    def test_both_yaml_parsers_replay_identically(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        loaders = [yaml.SafeLoader]
        if getattr(yaml, "__with_libyaml__", False):
            loaders.append(yaml.CSafeLoader)
        results = set()
        for loader in loaders:
            value = load.load_yaml_bytes(case["rulebook_source"].encode("utf-8"),
                                         _loader_class=loader)
            source = canon.canonicalize(value).encode("utf-8")
            results.add(receipt.replay_receipt(case["receipt"], source, case["candidate"],
                                               case["snapshot"], _receipt_keys(),
                                               registry).recomputed_canonical)
        self.assertEqual(len(results), 1)

    def test_no_input_is_mutated(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        before = copy.deepcopy((case["receipt"], case["candidate"], case["snapshot"],
                                case["authorization"]))
        receipt.replay_receipt(case["receipt"], case["rulebook_source"].encode("utf-8"),
                               case["candidate"], case["snapshot"], _receipt_keys(), registry,
                               authorization=case["authorization"],
                               authorization_keys=_auth_keys(),
                               verification_time="2026-08-05T00:01:00Z")
        self.assertEqual((case["receipt"], case["candidate"], case["snapshot"],
                          case["authorization"]), before)

    def test_receipts_and_reports_are_immutable(self):
        registry = _registry()
        chain = Chain(_case(RECEIPT_DIR / "accept_block_decision.json"), registry)
        issued = chain.issue()
        self.assertTrue(dataclasses.is_dataclass(issued))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            issued.canonical = "tampered"
        verified = receipt.verify_receipt(issued.value(), _receipt_keys(), registry)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            verified.signature_valid = False
        borrowed = issued.value()
        borrowed["result"]["outcome"] = "ALLOW"
        self.assertNotEqual(issued.value(), borrowed)


class ExceptionContainment(unittest.TestCase):
    def test_malformed_receipts_and_keys_stay_typed(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        for signature_value in ("", "!!!!", "AAAA", "====", " ",
                                base64.b64encode(bytes(64)).decode()):
            value = copy.deepcopy(case["receipt"])
            value["signature"]["value"] = signature_value
            with self.subTest(signature=signature_value[:12]):
                try:
                    receipt.verify_receipt(value, _receipt_keys(), registry)
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                except Exception as untyped:
                    self.fail("%s crossed the boundary" % type(untyped).__name__)

    def test_programmer_defects_raise_type_errors(self):
        registry = _registry()
        for value in (None, "text", 5, []):
            with self.subTest(value=repr(value)):
                with self.assertRaises(TypeError):
                    receipt.verify_receipt(value, _receipt_keys(), registry)


if __name__ == "__main__":
    unittest.main()
