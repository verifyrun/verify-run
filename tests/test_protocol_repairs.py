"""Independent negative checks for the engineering audit's bounded repairs."""

import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vfy import authorization, canon, receipt, workflow
from vfy.evidence import acquire_command
from vfy.errors import VerifyError
from tests.test_authorization import Scenario, SEED_A, _keys, _registry
from tests.test_receipt import (Chain, RECEIPT_DIR, _case, _receipt_keys, _auth_keys)
from tests.test_execution import _Sandbox, _build, _run, EXEC_DIR

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "fixtures" / "repairs"


def resign(value):
    # Published TEST-ONLY key; this constructs a valid signature over a hostile interval.
    payload = {k: v for k, v in value.items() if k != "signature"}
    value["signature"]["value"] = base64.b64encode(
        Ed25519PrivateKey.from_private_bytes(SEED_A).sign(canon.canonical_bytes(payload))
    ).decode("ascii")
    return value


class AuthorizationPolicy(unittest.TestCase):
    def test_large_policy_ttl_is_a_binding_refusal_not_a_date_conversion_failure(self):
        ttl = json.loads((VECTORS / "authorization-policy.json").read_text())["large_ttl_seconds"]
        original = Scenario(_registry())
        changed = Scenario(original.registry, ttl=ttl)
        value = original.issue().value()
        value["rulebook_digest"] = changed.pinned.digest
        value["evidence_digest"] = changed.snapshot.digest
        resign(value)
        with self.assertRaises(VerifyError) as caught:
            changed.verify(value)
        self.assertEqual(caught.exception.code, "authorization_binding_mismatch")

    def test_signed_ttl_mutations_in_live_and_historical_verification(self):
        scenario = Scenario(_registry())
        for case in json.loads((VECTORS / "authorization-policy.json").read_text())["ttl"]:
            for at in (None, scenario.case["verification_time"]):
                with self.subTest(case=case, at=at):
                    value = scenario.issue().value()
                    value["expires_at"] = case["expires_at"]
                    resign(value)
                    def verify():
                        return authorization.verify_authorization(
                            value, scenario.pinned, scenario.candidate, scenario.snapshot,
                            scenario.result, value["runtime_id"], at, _keys(), scenario.registry)
                    if case["expected"] == "accept":
                        self.assertEqual(verify().value(), value)
                    else:
                        with self.assertRaises(VerifyError) as caught:
                            verify()
                        self.assertEqual(caught.exception.code, case["expected"])

    def test_trust_matrix(self):
        scenario = Scenario(_registry())
        value = scenario.issue().value()
        for case in json.loads((VECTORS / "authorization-policy.json").read_text())["trust"]:
            with self.subTest(case=case):
                keys = _keys()
                for entry in keys.values():
                    entry["status"] = case["status"]
                def verify():
                    return authorization.verify_authorization(
                        value, scenario.pinned, scenario.candidate, scenario.snapshot,
                        scenario.result, value["runtime_id"], None if case["historical"] else
                        scenario.case["verification_time"], keys, scenario.registry,
                        historical=case["historical"])
                if case["expected"] == "accept":
                    self.assertEqual(verify().value(), value)
                else:
                    with self.assertRaises(VerifyError) as caught:
                        verify()
                    self.assertEqual(caught.exception.code, case["expected"])

    def test_registry_accepts_revocation_but_not_unknown_status(self):
        self.assertEqual(next(iter(_keys(status="revoked").values()))["status"], "revoked")
        with self.assertRaises(VerifyError):
            _keys(status="unknown-status")

    def test_retired_key_with_no_time_is_not_implicitly_historical(self):
        s = Scenario(_registry())
        with self.assertRaises(VerifyError) as caught:
            authorization.verify_authorization(s.issue().value(), s.pinned, s.candidate,
                s.snapshot, s.result, s.case["runtime_id"], None, _keys(status="retired"),
                s.registry)
        self.assertEqual(caught.exception.code, "signing_key_retired")


class HistoricalTrust(unittest.TestCase):
    def test_real_store_replays_retirement_and_refuses_new_signing_and_revocation(self):
        with tempfile.TemporaryDirectory() as room:
            root = Path(room)
            w = workflow.initialize(root, "pipeline-gate", ROOT / "spec", ROOT / "templates",
                                    workflow.Identifiers())
            (root / "ci").mkdir()
            (root / "bin").mkdir()
            for name, body in (("ci/last-test-result.sh", '#!/bin/sh\nprintf \'"passed"\'\n'),
                               ("bin/action.sh", "#!/bin/sh\nprintf ran >> marker\n")):
                path = root / name
                path.write_text(body)
                path.chmod(0o700)
            clock = workflow.FixedClock("2026-09-18T00:00:00Z")
            args = (w, ["bin/action.sh"], clock, workflow.Identifiers(), {"branch": "main"})
            first = workflow.run(*args)
            trust_path = root / ".vfy/keys/trust.json"
            trust = json.loads(trust_path.read_text())
            for role in ("receipt", "authorization"):
                trust[role][0]["status"] = "retired"
            trust_path.write_bytes(canon.canonical_bytes(trust))
            self.assertTrue(workflow.replay(w, root / first.receipt_path).authorization_verified)
            with self.assertRaises(VerifyError) as caught:
                workflow.run(*args)
            self.assertEqual(caught.exception.code, "signing_key_retired")
            self.assertEqual((root / "marker").read_text(), "ran")
            for role in ("receipt", "authorization"):
                changed = copy.deepcopy(trust)
                changed[role][0]["status"] = "revoked"
                trust_path.write_bytes(canon.canonical_bytes(changed))
                with self.assertRaises(VerifyError) as caught:
                    workflow.replay(w, root / first.receipt_path)
                self.assertEqual(caught.exception.code, "signing_key_revoked")

    def test_signer_seed_must_match_trusted_identity_before_execution(self):
        case = json.loads((VECTORS / "signer-preflight.json").read_text())
        for role in case["roles"]:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as room:
                root = Path(room)
                w = workflow.initialize(root, "pipeline-gate", ROOT / "spec", ROOT / "templates",
                                        workflow.Identifiers())
                (root / "ci").mkdir()
                (root / "bin").mkdir()
                for name, body in (("ci/last-test-result.sh", '#!/bin/sh\nprintf \'"passed"\'\n'),
                                   ("bin/action.sh", "#!/bin/sh\nprintf ran >> marker\n")):
                    path = root / name
                    path.write_text(body)
                    path.chmod(0o700)
                seed_path = w.path(w.config["keys"][role])
                seed_path.write_bytes(SEED_A)
                before = {str(p.relative_to(root)): p.read_bytes()
                          for p in (root / ".vfy").rglob("*") if p.is_file()}
                with self.assertRaises(VerifyError) as caught:
                    workflow.run(w, ["bin/action.sh"],
                                 workflow.FixedClock("2026-09-18T00:00:00Z"),
                                 workflow.Identifiers(), {"branch": "main"})
                self.assertEqual(caught.exception.code, case["expected"])
                self.assertFalse((root / "marker").exists())
                after = {str(p.relative_to(root)): p.read_bytes()
                         for p in (root / ".vfy").rglob("*") if p.is_file()}
                self.assertEqual(before, after, "preflight refusal must not spend or publish")

    def test_retired_authorization_and_receipt_keys_preserve_replay(self):
        registry = _registry()
        case = _case(RECEIPT_DIR / "accept_allow_with_authorization_and_execution.json")
        chain = Chain(case, registry)
        keys = _auth_keys()
        for entry in keys.values():
            entry["status"] = "retired"
        report = receipt.replay_receipt(case["receipt"], chain.source, chain.candidate,
            case["snapshot"], _receipt_keys(status="retired"), registry,
            authorization=case["authorization"], authorization_keys=keys)
        self.assertTrue(report.result_matched)
        self.assertTrue(report.authorization_verified)
        for entry in keys.values():
            entry["status"] = "revoked"
        with self.assertRaises(VerifyError) as caught:
            receipt.replay_receipt(case["receipt"], chain.source, chain.candidate,
                case["snapshot"], _receipt_keys(), registry,
                authorization=case["authorization"], authorization_keys=keys)
        self.assertEqual(caught.exception.code, "signing_key_revoked")

    def test_receipt_rejects_unknown_status(self):
        case = _case(RECEIPT_DIR / "accept_block_decision.json")
        with self.assertRaises(VerifyError) as caught:
            receipt.verify_receipt(case["receipt"], _receipt_keys(status="unknown-status"),
                                   _registry())
        self.assertEqual(caught.exception.code, "signing_key_invalid")


class ExecutionBindingBoundary(unittest.TestCase):
    def test_subject_requirement_and_context_param_mutations_refuse_before_spend(self):
        case = json.loads((EXEC_DIR / "accept_exit_zero.json").read_text())
        case["candidate"]["action"]["params"] = {
            "subject": "sha256:" + "1" * 64, "requirements": "sha256:" + "2" * 64,
            "context": "sha256:" + "3" * 64}
        for field in ("subject", "requirements", "context"):
            with self.subTest(field=field), _Sandbox(case["tree"]) as sandbox:
                registry = _registry()
                pinned, candidate, frozen, result, granted = _build(case, sandbox, registry)
                candidate["action"]["params"][field] = "sha256:" + "4" * 64
                with self.assertRaises(VerifyError) as caught:
                    _run(case, sandbox, registry, pinned, candidate, frozen, result, granted)
                self.assertEqual(caught.exception.code, "authorization_binding_mismatch")
                self.assertFalse(sandbox.store.is_consumed(granted.nonce))

    def test_mutable_program_and_environment_are_still_not_a_core_binding(self):
        # This passing counterexample prevents claiming the draft profile is already enforced.
        case = json.loads((EXEC_DIR / "accept_exit_zero.json").read_text())
        with _Sandbox(case["tree"]) as sandbox:
            registry = _registry()
            pinned, candidate, frozen, result, granted = _build(case, sandbox, registry)
            (sandbox.root / "bin/ok.sh").write_text('#!/bin/sh\nprintf "changed:%s" "$MODE"\n')
            record = _run(case, sandbox, registry, pinned, candidate, frozen, result, granted,
                          environment={"MODE": "new"})
            self.assertEqual(record.stdout, b"changed:new")
            self.assertTrue(record.nonce_consumed)

    def test_retired_authorization_cannot_be_spent_after_historical_verification(self):
        case = json.loads((EXEC_DIR / "accept_exit_zero.json").read_text())
        with _Sandbox(case["tree"]) as sandbox:
            registry = _registry()
            pinned, candidate, frozen, result, granted = _build(case, sandbox, registry)
            keys = _keys(status="retired")
            historical = authorization.verify_authorization(granted.value(), pinned, candidate,
                frozen, result, case["runtime_id"], None, keys, registry, historical=True)
            with self.assertRaises(VerifyError) as caught:
                _run(case, sandbox, registry, pinned, candidate, frozen, result, historical,
                     authorization_keys=keys)
            self.assertEqual(caught.exception.code, "signing_key_retired")
            self.assertFalse(sandbox.store.is_consumed(granted.nonce))


@unittest.skipUnless(hasattr(os, "killpg"), "process-group guarantee is POSIX-only")
class EvidenceCleanup(unittest.TestCase):
    def test_normal_return_does_not_leave_background_work(self):
        case = json.loads((VECTORS / "evidence-descendants.json").read_text())
        with tempfile.TemporaryDirectory() as room:
            root = Path(room)
            program = root / "probe.sh"
            program.write_text(case["normal_exit_script"])
            program.chmod(0o700)
            result = acquire_command({"id": "tests", "source": "exec", "ref": "probe.sh"},
                root, "2026-09-18T00:00:00Z", timeout_seconds=5)
            self.assertEqual(result.status, "ok")
            time.sleep(2.2)
            self.assertFalse((root / "marker").exists())

    def test_timeout_ends_descendants_even_when_leader_has_exited(self):
        case = json.loads((VECTORS / "evidence-descendants.json").read_text())
        for script in case["scripts"]:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as room:
                root = Path(room)
                program = root / "probe.sh"
                program.write_text(script)
                program.chmod(0o700)
                result = acquire_command({"id": "tests", "source": "exec", "ref": "probe.sh"},
                    root, "2026-09-18T00:00:00Z", timeout_seconds=case["timeout_seconds"])
                self.assertEqual(result.status, case["expected_status"])
                time.sleep(1.5)
                self.assertEqual((root / "marker").exists(), case["marker_must_exist"])
