"""Closure Unit 12 — gated local command execution, consumption, acknowledgment, and receipt."""

import base64
import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import tokenize
import types
import unittest

from vfy import authorization as auth_module
from vfy import canon, gate, load, receipt as receipt_module, rulebook, runner, schema, snapshot
from vfy import workflow
from vfy import store as store_module
from vfy.errors import ExecutionRecordingFailed, VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
EXEC_DIR = REPO_ROOT / "fixtures" / "execution"
RUNNER_SOURCE = REPO_ROOT / "vfy" / "runner.py"


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _case(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _materialize(tree, root):
    for name in sorted(tree):
        if tree[name]["kind"] == "dir":
            (root / name).mkdir(parents=True, exist_ok=True)
    for name in sorted(tree):
        entry, target = tree[name], root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if entry["kind"] == "dir":
            continue
        if entry["kind"] == "file":
            target.write_bytes(base64.b64decode(entry["bytes_base64"]))
            target.chmod(int(entry.get("mode", "0644"), 8))
        elif entry["kind"] == "symlink":
            target.symlink_to(entry["target"])
        else:  # pragma: no cover
            raise AssertionError("unknown tree entry kind: " + entry["kind"])


class _Sandbox:
    """A materialized tree plus a fresh store, always torn down."""

    def __init__(self, tree):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="vfy-exec-"))
        self.root = self.base / "work"
        self.root.mkdir()
        _materialize(tree, self.root)
        self.store = store_module.LocalStore(self.base / "store")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        shutil.rmtree(self.base, ignore_errors=True)
        return False


def _build(case, sandbox, registry):
    """Pin the rulebook, freeze the snapshot, evaluate, and issue the authorization a case needs.

    Everything the runtime later verifies is produced here from the fixture, so nothing under
    test is also what proves the test.
    """
    pinned = rulebook.load_rulebook_bytes(
        (REPO_ROOT / case["rulebook_ref"]).read_bytes(), registry)
    candidate = copy.deepcopy(case["candidate"])
    argv = candidate.get("action", {}).get("argv")
    if isinstance(argv, list) and argv and isinstance(argv[0], str) \
            and argv[0].startswith("ABSOLUTE:"):
        candidate["action"]["argv"][0] = str(sandbox.root / argv[0][len("ABSOLUTE:"):])

    frozen = snapshot.build_snapshot(pinned, case["snapshot_id"], case["frozen_at"],
                                     case["acquisitions"], registry)
    result = gate.evaluate(pinned, candidate, frozen.value(), registry)

    declared = case["authorization"]
    key = case["authorization_key"]
    authorization = None
    if result.outcome == "ALLOW":
        authorization = auth_module.issue_authorization(
            pinned, candidate, frozen, result, declared["authorization_id"], declared["nonce"],
            declared["runtime_id"], declared["issued_at"], key["key_id"], key["key_version"],
            bytes.fromhex(key["private_key_hex"]), registry)
    return pinned, candidate, frozen, result, authorization


def _key_registry(case):
    key = case["authorization_key"]
    return auth_module.build_key_registry([{
        "key_id": case.get("registry_key_id", key["key_id"]),
        "key_version": key["key_version"],
        "public_key": bytes.fromhex(key["public_key_hex"]),
        "status": case.get("registry_key_status", "active"),
        "trusted_signer": True}])


def _receipt_registry(case):
    key = case["receipt_key"]
    return auth_module.build_key_registry([{
        "key_id": key["key_id"], "key_version": key["key_version"],
        "public_key": bytes.fromhex(key["public_key_hex"]),
        "status": "active", "trusted_signer": True}])


def _run(case, sandbox, registry, pinned, candidate, frozen, result, authorization, **over):
    key = case["receipt_key"]
    arguments = dict(
        runtime_id=case["runtime_id"], verification_time=case["verification_time"],
        acknowledged_at=case["acknowledged_at"], store=sandbox.store,
        authorization_keys=_key_registry(case), registry=registry,
        receipt_id=case["receipt_id"], receipt_created_at=case["receipt_created_at"],
        receipt_key_id=key["key_id"], receipt_key_version=key["key_version"],
        receipt_private_key=bytes.fromhex(key["private_key_hex"]),
        cwd=sandbox.root / case["cwd"], environment=case["environment"],
        timeout_seconds=case["timeout_seconds"])
    arguments.update(over)
    return runner.execute_authorized_command(pinned, candidate, frozen, result, authorization,
                                             **arguments)


class Fixtures(unittest.TestCase):
    def test_every_fixture_is_claimed_by_a_test(self):
        names = {p.stem for p in EXEC_DIR.glob("*.json")}
        claimed = {n for n in names
                   if n.startswith(("accept_", "reject_", "seam_", "concurrency_"))}
        self.assertEqual(names, claimed)
        self.assertGreaterEqual(len(names), 45)

    def _prepare(self, case, sandbox, registry):
        """Apply a case's post-issuance mutations, so the objects no longer match the signature."""
        pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)

        forced = case.get("force_outcome")
        if forced is not None:
            self.assertEqual(result.outcome, forced if forced != "ERROR" else result.outcome)
            if forced == "ERROR":
                result = gate.evaluate(pinned, {"candidate_id": "c", "kind": "command",
                                                "action": {"summary": "s"}, "bogus": True},
                                       frozen.value(), registry)
                self.assertEqual(result.outcome, "ERROR")
            authorization = _issue_anyway(case, pinned, candidate, frozen, registry)

        mutation = case.get("mutate_candidate_after_issue")
        if mutation is not None:
            candidate = copy.deepcopy(candidate)
            for section, fields in mutation.items():
                candidate[section].update(fields)

        if case.get("mutate_snapshot_after_issue"):
            frozen = snapshot.build_snapshot(pinned, "snap-other", case["frozen_at"],
                                             case["acquisitions"], registry)
            result = gate.evaluate(pinned, candidate, frozen.value(), registry)

        if case.get("preconsume"):
            sandbox.store.consume_once(authorization)
        return pinned, candidate, frozen, result, authorization

    def _accept(self, path):
        case = _case(path)
        registry = _registry()
        parent = case.get("parent_environment", {})
        restore = {name: os.environ.get(name) for name in parent}
        os.environ.update(parent)
        try:
            with _Sandbox(case["tree"]) as sandbox:
                pinned, candidate, frozen, result, authorization = self._prepare(
                    case, sandbox, registry)
                record = _run(case, sandbox, registry, pinned, candidate, frozen, result,
                              authorization)
                expected = case["expected"]
                self.assertEqual(record.nonce_consumed, expected["consumed"], path.name)
                self.assertEqual(record.started, expected["started"], path.name)
                self.assertEqual(record.exit_status, expected["exit_status"], path.name)
                self.assertEqual(record.timed_out, expected["timed_out"], path.name)
                self.assertEqual(record.acknowledgment(), expected["acknowledgment"], path.name)
                if "stdout_base64" in expected:
                    self.assertEqual(record.stdout,
                                     base64.b64decode(expected["stdout_base64"]), path.name)
                if "stderr_base64" in expected:
                    self.assertEqual(record.stderr,
                                     base64.b64decode(expected["stderr_base64"]), path.name)
                self.assertTrue(sandbox.store.is_consumed(case["authorization"]["nonce"]))
                stored = sandbox.store.get_record(
                    case["receipt_id"], receipt_keys=_receipt_registry(case), registry=registry,
                    authorization_keys=_key_registry(case),
                    verification_time=case["verification_time"])
                self.assertEqual(stored.receipt()["execution"], expected["acknowledgment"])
                return record, case, sandbox
        finally:
            for name, value in restore.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_accepted_execution_fixtures(self):
        paths = sorted(EXEC_DIR.glob("accept_*.json"))
        self.assertGreaterEqual(len(paths), 12)
        for path in paths:
            with self.subTest(fixture=path.name):
                self._accept(path)

    def test_rejected_execution_fixtures(self):
        paths = sorted(EXEC_DIR.glob("reject_*.json"))
        self.assertGreaterEqual(len(paths), 24)
        registry = _registry()
        for path in paths:
            with self.subTest(fixture=path.name):
                case = _case(path)
                with _Sandbox(case["tree"]) as sandbox:
                    pinned, candidate, frozen, result, authorization = self._prepare(
                        case, sandbox, registry)
                    launches = sandbox.root / "launches"
                    before = sandbox.store.is_consumed(case["authorization"]["nonce"])
                    with self.assertRaises(VerifyError) as caught:
                        _run(case, sandbox, registry, pinned, candidate, frozen, result,
                             authorization)
                    self.assertEqual(caught.exception.code, case["expected"]["reason_code"],
                                     path.name)
                    # Nothing spent that was not already spent, nothing started, nothing stored.
                    self.assertEqual(sandbox.store.is_consumed(case["authorization"]["nonce"]),
                                     before, path.name)
                    self.assertFalse(launches.exists(), path.name)
                    with self.assertRaises(VerifyError):
                        sandbox.store.get_record(case["receipt_id"], verify=False)


def _issue_anyway(case, pinned, candidate, frozen, registry):
    """A negative decision has no authorization, so a fixture that tests one supplies a valid
    authorization built from an ALLOW run. The runtime must refuse on the outcome regardless."""
    allow_case = _case(EXEC_DIR / "accept_exit_zero.json")
    allowing = gate.evaluate(pinned, allow_case["candidate"], frozen.value(), registry)
    if allowing.outcome != "ALLOW":
        return None
    key = case["authorization_key"]
    declared = case["authorization"]
    return auth_module.issue_authorization(
        pinned, allow_case["candidate"], frozen, allowing, declared["authorization_id"],
        declared["nonce"], declared["runtime_id"], declared["issued_at"], key["key_id"],
        key["key_version"], bytes.fromhex(key["private_key_hex"]), registry)


class CandidateContract(unittest.TestCase):
    def test_only_a_command_candidate_with_a_path_argv_is_executable(self):
        for candidate in (
                {"candidate_id": "c", "kind": "tool_call",
                 "action": {"summary": "s", "argv": ["./x.sh"]}},
                {"candidate_id": "c", "kind": "http_request",
                 "action": {"summary": "s", "argv": ["./x.sh"]}},
                {"candidate_id": "c", "kind": "custom",
                 "action": {"summary": "s", "argv": ["./x.sh"]}},
                {"candidate_id": "c", "kind": "command", "action": {"summary": "s"}},
                {"candidate_id": "c", "kind": "command", "action": {"summary": "s", "argv": []}},
                {"candidate_id": "c", "kind": "command",
                 "action": {"summary": "s", "argv": ["sh"]}},
                {"candidate_id": "c", "kind": "command",
                 "action": {"summary": "s", "argv": [""]}},
                {"candidate_id": "c", "kind": "command",
                 "action": {"summary": "s", "argv": ["./x.sh", 1]}},
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(VerifyError) as caught:
                    runner.executable_argv(candidate)
                self.assertEqual(caught.exception.code, "execution_candidate_unsupported")

    def test_the_argv_is_taken_verbatim_from_the_candidate(self):
        argv = ["./bin/run.sh", "a b", ";", "$(x)", "*", "--flag=1"]
        candidate = {"candidate_id": "c", "kind": "command",
                     "action": {"summary": "s", "argv": argv, "tool": "ignored",
                                "params": {"path": "ignored"}}}
        self.assertEqual(runner.executable_argv(candidate), argv)
        self.assertIsNot(runner.executable_argv(candidate), argv)  # a copy, not the caller's list

    def test_summary_and_tool_fields_are_never_executed_but_are_still_bound(self):
        one = {"candidate_id": "c", "kind": "command",
               "action": {"summary": "deploy", "argv": ["./bin/ok.sh"]}}
        two = copy.deepcopy(one)
        two["action"]["summary"] = "deploy something else"
        self.assertEqual(runner.executable_argv(one), runner.executable_argv(two))
        self.assertNotEqual(canon.digest(one), canon.digest(two))


class ProcessBoundary(unittest.TestCase):
    def setUp(self):
        self.case = _case(EXEC_DIR / "accept_exit_zero.json")
        self.registry = _registry()

    def _script(self, body, tree=None, name="bin/probe.sh"):
        entries = dict(self.case["tree"] if tree is None else tree)
        entries[name] = {"kind": "file", "mode": "0755",
                         "bytes_base64": base64.b64encode(
                             ("#!/bin/sh\n" + body).encode("utf-8")).decode("ascii")}
        return entries

    def _execute(self, argv, tree, **over):
        case = copy.deepcopy(self.case)
        case["candidate"] = dict(case["candidate"])
        case["candidate"]["action"] = dict(case["candidate"]["action"])
        case["candidate"]["action"]["argv"] = argv
        with _Sandbox(tree) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, self.registry)
            record = _run(case, sandbox, self.registry, pinned, candidate, frozen, result,
                          authorization, **over)
            return record, sandbox

    def test_no_shell_interprets_anything(self):
        tree = self._script("printf '%s' \"$1\"\n")
        record, _ = self._execute(["./bin/probe.sh", "$(echo pwned); rm -rf /; *"], tree)
        self.assertEqual(record.stdout, b"$(echo pwned); rm -rf /; *")

    def test_stdin_is_closed(self):
        tree = self._script("if read line; then printf 'read'; else printf 'eof'; fi\n")
        record, _ = self._execute(["./bin/probe.sh"], tree)
        self.assertEqual(record.stdout, b"eof")

    def test_output_is_bounded_and_truncation_is_operational_only(self):
        tree = self._script(
            "i=0\nwhile [ $i -lt 1200 ]; do printf '%s' '" + "o" * 1024
            + "'; i=$((i+1)); done\nexit 0\n")
        record, _ = self._execute(["./bin/probe.sh"], tree, timeout_seconds=60)
        self.assertEqual(len(record.stdout), runner.MAX_STDOUT_BYTES)
        self.assertTrue(record.output_truncated)
        self.assertNotIn("note", record.acknowledgment())
        self.assertEqual(record.acknowledgment()["exit_status"], 0)

    def test_a_timeout_ends_the_child_and_its_descendants(self):
        tree = self._script("i=0\nwhile [ $i -lt 60 ]; do printf x >> %s; /bin/sleep 1; "
                            "i=$((i+1)); done\n" % "$1", name="bin/grand.sh")
        tree = dict(tree)
        tree["bin/probe.sh"] = {"kind": "file", "mode": "0755",
                                "bytes_base64": base64.b64encode(
                                    b"#!/bin/sh\n./bin/grand.sh ./alive &\n/bin/sleep 60\n"
                                ).decode("ascii")}
        record, sandbox_root = self._execute_keeping(["./bin/probe.sh"], tree, timeout_seconds=1)
        self.assertTrue(record.timed_out)
        self.assertEqual(record.acknowledgment()["note"], "timed out")
        self.assertNotIn("exit_status", record.acknowledgment())
        # Settle-based rather than fixed-sleep: the descendant writes once a second, so any
        # growth across four samples means it outlived the group kill.
        marker = sandbox_root / "alive"

        def size():
            return marker.stat().st_size if marker.exists() else 0

        samples = []
        for _ in range(4):
            samples.append(size())
            time.sleep(1.2)
        self.assertEqual(len(set(samples)), 1,
                         "a descendant outlived the timeout: %r" % (samples,))

    def _execute_keeping(self, argv, tree, **over):
        """Like _execute but hands back a copy of the tree root that outlives the sandbox."""
        case = copy.deepcopy(self.case)
        case["candidate"]["action"] = dict(case["candidate"]["action"])
        case["candidate"]["action"]["argv"] = argv
        sandbox = _Sandbox(tree)
        self.addCleanup(shutil.rmtree, sandbox.base, ignore_errors=True)
        pinned, candidate, frozen, result, authorization = _build(case, sandbox, self.registry)
        record = _run(case, sandbox, self.registry, pinned, candidate, frozen, result,
                      authorization, **over)
        return record, sandbox.root

    def test_signal_death_is_not_an_exit_status(self):
        tree = self._script("kill -TERM $$\n")
        record, _ = self._execute(["./bin/probe.sh"], tree)
        self.assertEqual(record.signal_number, 15)
        self.assertIsNone(record.exit_status)
        self.assertEqual(record.acknowledgment()["note"], "terminated by signal")
        self.assertNotIn("exit_status", record.acknowledgment())

    def test_every_acknowledgment_note_comes_from_the_closed_set(self):
        for path in sorted(EXEC_DIR.glob("accept_*.json")):
            note = _case(path)["expected"]["acknowledgment"].get("note")
            if note is not None:
                self.assertIn(note, runner.NOTES, path.name)


class ConsumptionOrder(unittest.TestCase):
    def test_consumption_happens_before_the_process_is_created(self):
        case = _case(EXEC_DIR / "accept_exit_zero.json")
        registry = _registry()
        tree = dict(case["tree"])
        tree["bin/witness.sh"] = {"kind": "file", "mode": "0755",
                                  "bytes_base64": base64.b64encode(
                                      b"#!/bin/sh\nprintf started\n").decode("ascii")}
        case = copy.deepcopy(case)
        case["candidate"]["action"]["argv"] = ["./bin/witness.sh"]
        with _Sandbox(tree) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
            seen = []
            real_consume = sandbox.store.consume_once
            real_popen = subprocess.Popen

            def watched_consume(auth):
                seen.append("consume")
                return real_consume(auth)

            def watched_popen(*a, **k):
                seen.append("launch")
                return real_popen(*a, **k)

            sandbox.store.consume_once = watched_consume
            subprocess.Popen = watched_popen
            try:
                _run(case, sandbox, registry, pinned, candidate, frozen, result, authorization)
            finally:
                subprocess.Popen = real_popen
            self.assertEqual(seen, ["consume", "launch"])

    def test_a_second_attempt_with_the_same_authorization_never_launches(self):
        case = _case(EXEC_DIR / "accept_exit_zero.json")
        registry = _registry()
        with _Sandbox(case["tree"]) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
            _run(case, sandbox, registry, pinned, candidate, frozen, result, authorization)
            real_popen = subprocess.Popen
            launched = []
            subprocess.Popen = lambda *a, **k: launched.append(1) or real_popen(*a, **k)
            try:
                with self.assertRaises(VerifyError) as caught:
                    _run(case, sandbox, registry, pinned, candidate, frozen, result,
                         authorization, receipt_id="rcpt-second")
            finally:
                subprocess.Popen = real_popen
            self.assertEqual(caught.exception.code, "authorization_nonce_reused")
            self.assertEqual(launched, [])


class RecordingSeam(unittest.TestCase):
    def _sandbox_case(self):
        case = _case(EXEC_DIR / "accept_exit_zero.json")
        return case, _registry()

    def test_a_receipt_issuance_failure_is_typed_and_carries_no_receipt(self):
        case, registry = self._sandbox_case()
        with _Sandbox(case["tree"]) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
            with self.assertRaises(VerifyError) as caught:
                _run(case, sandbox, registry, pinned, candidate, frozen, result, authorization,
                     receipt_private_key=b"\x00" * 8)          # not an Ed25519 key
            self.assertEqual(caught.exception.code, "execution_recording_failed")
            self.assertEqual(caught.exception.stage, "issue")
            self.assertIsNone(caught.exception.receipt)
            self.assertTrue(sandbox.store.is_consumed(case["authorization"]["nonce"]))

    def test_a_store_failure_hands_the_receipt_back_so_it_can_be_persisted_later(self):
        case, registry = self._sandbox_case()
        with _Sandbox(case["tree"]) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
            real_put = sandbox.store.put_record
            sandbox.store.put_record = lambda *a, **k: (_ for _ in ()).throw(
                OSError("the disk is gone"))
            with self.assertRaises(VerifyError) as caught:
                _run(case, sandbox, registry, pinned, candidate, frozen, result, authorization)
            self.assertEqual(caught.exception.code, "execution_recording_failed")
            self.assertEqual(caught.exception.stage, "store")
            self.assertIsNotNone(caught.exception.receipt)

            # The whole point of handing it back: persist later, without running anything again.
            sandbox.store.put_record = real_put
            stored = real_put(caught.exception.receipt, pinned, candidate, frozen, authorization)
            self.assertEqual(stored.receipt()["receipt_id"], case["receipt_id"])
            self.assertTrue(sandbox.store.is_consumed(case["authorization"]["nonce"]))

    def test_the_runtime_contains_no_retry(self):
        code = _code_text(RUNNER_SOURCE)
        for token in ("retry", "reissue", "again", "while True", "for attempt"):
            self.assertNotIn(token, code)

    def test_seam_fixtures_describe_the_states_this_unit_actually_produces(self):
        states = {p.stem: _case(p) for p in sorted(EXEC_DIR.glob("seam_*.json"))}
        self.assertGreaterEqual(len(states), 8)
        for name, case in states.items():
            with self.subTest(seam=name):
                state = case["state"]
                self.assertFalse(state["automatic_retry_permitted"], name)
                if state["stored_record_available"]:
                    self.assertTrue(state["receipt_available"], name)
                if state["receipt_available"]:
                    self.assertTrue(state["acknowledgment_available"], name)
                if state["process_started"] or state["acknowledgment_available"]:
                    self.assertTrue(state["authorization_consumed"], name)


class Concurrency(unittest.TestCase):
    """Eight processes race for one authorization. Exactly one may launch."""

    def test_eight_concurrent_callers_produce_one_consumption_and_one_launch(self):
        expected = _case(EXEC_DIR / "concurrency_eight_callers.json")["expected"]
        case = _case(EXEC_DIR / "accept_exit_zero.json")
        registry = _registry()
        tree = dict(case["tree"])
        tree["bin/launch.sh"] = {"kind": "file", "mode": "0755",
                                 "bytes_base64": base64.b64encode(
                                     b"#!/bin/sh\nprintf x >> ./launches\nprintf ran\n"
                                 ).decode("ascii")}
        case = copy.deepcopy(case)
        case["candidate"]["action"]["argv"] = ["./bin/launch.sh"]

        with _Sandbox(tree) as sandbox:
            _build(case, sandbox, registry)  # prove the objects construct before forking
            payload = {"case": case, "root": str(sandbox.root), "store": str(sandbox.store.root),
                       "repo": str(REPO_ROOT)}
            handoff = sandbox.base / "case.json"
            handoff.write_text(json.dumps(payload), encoding="utf-8")

            children = [subprocess.Popen(
                [sys.executable, "-c", _CONCURRENT_CHILD, str(handoff), str(index)],
                cwd=str(REPO_ROOT),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE) for index in range(8)]
            reports = []
            for child in children:
                out, err = child.communicate(timeout=120)
                self.assertEqual(child.returncode, 0, err.decode("utf-8"))
                reports.append(json.loads(out.decode("utf-8")))

            succeeded = [r for r in reports if r["ok"]]
            refused = [r for r in reports if not r["ok"]]
            launches = (sandbox.root / "launches")
            launched = launches.stat().st_size if launches.exists() else 0

            self.assertEqual(len(succeeded), expected["consumptions_succeeded"])
            self.assertEqual(launched, expected["processes_launched"])
            self.assertEqual(len(refused), expected["callers_refused_before_launch"])
            for report in refused:
                self.assertEqual(report["code"], expected["refusal_reason_code"])
            self.assertEqual(len(sandbox.store.list_receipts()), expected["receipts_issued"])


_CONCURRENT_CHILD = """
import json, sys, pathlib
sys.path.insert(0, json.loads(pathlib.Path(sys.argv[1]).read_text())["repo"])
import tests.test_execution as harness
from vfy.errors import VerifyError
from vfy import store as store_module

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
case, index = payload["case"], sys.argv[2]
registry = harness._registry()

class Handle:
    pass

sandbox = Handle()
sandbox.root = pathlib.Path(payload["root"])
sandbox.store = store_module.LocalStore(pathlib.Path(payload["store"]))

pinned, candidate, frozen, result, authorization = harness._build(case, sandbox, registry)
try:
    harness._run(case, sandbox, registry, pinned, candidate, frozen, result, authorization)
    print(json.dumps({"ok": True, "index": index}))
except VerifyError as failure:
    print(json.dumps({"ok": False, "index": index, "code": failure.code}))
"""


class Immutability(unittest.TestCase):
    def test_no_argument_is_mutated(self):
        case = _case(EXEC_DIR / "accept_exit_zero.json")
        registry = _registry()
        with _Sandbox(case["tree"]) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
            before = {
                "candidate": canon.canonicalize(candidate),
                "rulebook": pinned.canonical, "snapshot": frozen.canonical,
                "result": result.canonical, "authorization": authorization.canonical,
                "environment": {"A": "b"},
            }
            environment = {"A": "b"}
            _run(case, sandbox, registry, pinned, candidate, frozen, result, authorization,
                 environment=environment)
            self.assertEqual(canon.canonicalize(candidate), before["candidate"])
            self.assertEqual(pinned.canonical, before["rulebook"])
            self.assertEqual(frozen.canonical, before["snapshot"])
            self.assertEqual(result.canonical, before["result"])
            self.assertEqual(authorization.canonical, before["authorization"])
            self.assertEqual(environment, before["environment"])

    def test_the_returned_record_is_frozen(self):
        case = _case(EXEC_DIR / "accept_exit_zero.json")
        registry = _registry()
        with _Sandbox(case["tree"]) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
            record = _run(case, sandbox, registry, pinned, candidate, frozen, result,
                          authorization)
        with self.assertRaises(Exception):
            record.started = False
        first = record.acknowledgment()
        first["acknowledged"] = "tampered"
        self.assertEqual(record.acknowledgment()["acknowledged"], True)


class StorageAndReplay(unittest.TestCase):
    def test_a_stored_record_replays_after_the_process_that_wrote_it_is_gone(self):
        case = _case(EXEC_DIR / "accept_exit_zero.json")
        registry = _registry()
        sandbox = _Sandbox(case["tree"])
        self.addCleanup(shutil.rmtree, sandbox.base, ignore_errors=True)
        pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
        record = _run(case, sandbox, registry, pinned, candidate, frozen, result, authorization)
        self.assertEqual(record.exit_status, 0)

        # A different process, holding nothing but the store root and the published keys.
        probe = subprocess.run(
            [sys.executable, "-c", _REPLAY_CHILD, str(sandbox.store.root), case["receipt_id"],
             case["receipt_key"]["public_key_hex"], case["authorization_key"]["public_key_hex"],
             case["verification_time"]],
            cwd=str(REPO_ROOT), capture_output=True,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)})
        self.assertEqual(probe.returncode, 0, probe.stderr.decode("utf-8"))
        report = json.loads(probe.stdout.decode("utf-8"))
        self.assertEqual(report["outcome"], "ALLOW")
        self.assertTrue(report["result_matched"])
        self.assertTrue(report["authorization_verified"])
        self.assertEqual(report["execution"],
                         {"acknowledged": True, "acknowledged_at": case["acknowledged_at"],
                          "exit_status": 0})

    def test_a_nonzero_exit_does_not_change_the_recorded_decision(self):
        case = _case(EXEC_DIR / "accept_exit_nonzero.json")
        registry = _registry()
        with _Sandbox(case["tree"]) as sandbox:
            pinned, candidate, frozen, result, authorization = _build(case, sandbox, registry)
            record = _run(case, sandbox, registry, pinned, candidate, frozen, result,
                          authorization)
            self.assertEqual(record.exit_status, 3)
            stored = sandbox.store.get_record(
                case["receipt_id"], receipt_keys=_receipt_registry(case), registry=registry,
                authorization_keys=_key_registry(case),
                verification_time=case["verification_time"])
            self.assertEqual(stored.receipt()["result"]["outcome"], "ALLOW")
            self.assertEqual(stored.receipt()["result"], result.value())


_REPLAY_CHILD = """
import json, pathlib, sys
from vfy import authorization as auth, load, schema
from vfy import store as store_module

root, receipt_id, receipt_hex, auth_hex, at = sys.argv[1:6]
registry = schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(pathlib.Path("spec").glob("*.schema.json"))])
receipt_keys = auth.build_key_registry([{"key_id": "receipt-key", "key_version": 1,
    "public_key": bytes.fromhex(receipt_hex), "status": "active", "trusted_signer": True}])
auth_keys = auth.build_key_registry([{"key_id": "test-key", "key_version": 1,
    "public_key": bytes.fromhex(auth_hex), "status": "active", "trusted_signer": True}])
store = store_module.LocalStore(pathlib.Path(root))
record = store.get_record(receipt_id, receipt_keys=receipt_keys, registry=registry,
                          authorization_keys=auth_keys, verification_time=at)
print(json.dumps({"outcome": record.outcome, "result_matched": record.replay_verified,
                  "authorization_verified": record.authorization_verified,
                  "execution": record.receipt().get("execution")}))
"""


def _code_text(path):
    """Source with comments and string literals removed, so a scanner reads code not prose."""
    pieces = []
    with tokenize.open(path) as handle:
        for token in tokenize.generate_tokens(handle.readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            pieces.append(token.string)
    return " ".join(pieces)


def _names(path):
    with tokenize.open(path) as handle:
        return [t.string for t in tokenize.generate_tokens(handle.readline)
                if t.type == tokenize.NAME]


class CompletionInstants(unittest.TestCase):
    """The two instants a caller cannot know before the child has run.

    A caller either states them, which is what a fixture reproducing a run byte for byte does, or
    hands over the clock that reads them, which is what a caller running a real command does. The
    runtime holds no clock either way: it constructs no timestamp and reads only what it is given.
    """

    def setUp(self):
        self.case = _case(EXEC_DIR / "accept_exit_zero.json")
        self.registry = _registry()

    def _execute(self, **over):
        with _Sandbox(self.case["tree"]) as sandbox:
            built = _build(self.case, sandbox, self.registry)
            return _run(self.case, sandbox, self.registry, *built, **over), sandbox

    def test_the_clock_is_read_once_after_the_child_and_dates_both_records(self):
        readings = []

        def clock():
            readings.append("2026-08-05T12:00:%02dZ" % (len(readings) + 30))
            return readings[-1]

        record, _ = self._execute(acknowledged_at=None, receipt_created_at=None,
                                  completion_clock=clock)
        self.assertEqual(len(readings), 1, "the completion instant was read more than once")
        self.assertEqual(record.acknowledgment()["acknowledged_at"], readings[0])
        self.assertEqual(record.receipt.value()["created_at"], readings[0])

    def test_stated_instants_still_work_exactly_as_before(self):
        record, _ = self._execute()
        self.assertEqual(record.acknowledgment()["acknowledged_at"],
                         self.case["acknowledged_at"])
        self.assertEqual(record.receipt.value()["created_at"], self.case["receipt_created_at"])

    def test_stating_an_instant_and_supplying_a_clock_is_refused(self):
        for over in ({"receipt_created_at": None}, {"acknowledged_at": None}, {}):
            with self.subTest(over=sorted(over)):
                with self.assertRaises(VerifyError) as caught:
                    self._execute(completion_clock=lambda: "2026-08-05T12:00:30Z", **over)
                self.assertEqual(caught.exception.code, "execution_configuration_invalid")

    def test_a_clock_that_is_not_callable_is_refused_before_anything_is_spent(self):
        with self.assertRaises(VerifyError) as caught:
            self._execute(acknowledged_at=None, receipt_created_at=None,
                          completion_clock="2026-08-05T12:00:30Z")
        self.assertEqual(caught.exception.code, "execution_configuration_invalid")

    def test_neither_a_stated_instant_nor_a_clock_is_a_type_error(self):
        with self.assertRaises(TypeError):
            self._execute(acknowledged_at=None, receipt_created_at=None)

    def test_a_clock_that_misbehaves_after_the_spend_is_a_recording_failure(self):
        """Below the line the command has run and the nonce is spent. Nothing is invented."""
        broken = {"raises": lambda: 1 / 0,
                  "returns nothing": lambda: None,
                  "returns a number": lambda: 12,
                  "returns prose": lambda: "not an instant",
                  "returns a local time": lambda: "2026-08-05T12:00:30"}
        for label, clock in broken.items():
            with self.subTest(clock=label):
                with self.assertRaises(ExecutionRecordingFailed) as caught:
                    self._execute(acknowledged_at=None, receipt_created_at=None,
                                  completion_clock=clock)
                self.assertEqual(caught.exception.stage, "acknowledge")
                self.assertIsNone(caught.exception.receipt)

    def test_the_full_frozen_grammar_is_accepted_exactly_as_a_stated_instant_is(self):
        """An explicit offset is a date-time in this product's grammar; `Clock` just never emits one."""
        record, _ = self._execute(acknowledged_at=None, receipt_created_at=None,
                                  completion_clock=lambda: "2026-08-05T13:00:30+01:00")
        self.assertEqual(record.acknowledgment()["acknowledged_at"], "2026-08-05T13:00:30+01:00")

    def test_a_spent_nonce_stays_spent_when_the_completion_instant_fails(self):
        with _Sandbox(self.case["tree"]) as sandbox:
            built = _build(self.case, sandbox, self.registry)
            with self.assertRaises(ExecutionRecordingFailed):
                _run(self.case, sandbox, self.registry, *built,
                     acknowledged_at=None, receipt_created_at=None,
                     completion_clock=lambda: "nonsense")
            self.assertTrue(sandbox.store.is_consumed(built[4].nonce),
                            "a failure below the line un-spent an authorization")


class Purity(unittest.TestCase):
    def test_the_runtime_reads_no_clock_and_draws_no_randomness(self):
        code = _code_text(RUNNER_SOURCE)
        for token in ("datetime", "time.time", "utcnow", "time.gmtime", "time.localtime",
                      "random", "secrets", "uuid"):
            self.assertNotIn(token, code)
        # A monotonic elapsed-time budget is not a clock reading: no time value reaches the record.
        self.assertIn("time . monotonic", code)

    def test_the_runtime_reads_no_environment_and_infers_no_home(self):
        code = _code_text(RUNNER_SOURCE)
        for token in ("os.environ", "getenv", "expanduser", "Path.home", "os.getcwd", "gethostname",
                      "getuser", "os.uname", "platform"):
            self.assertNotIn(token, code)

    def test_the_runtime_opens_no_socket_and_acquires_no_evidence(self):
        code = _code_text(RUNNER_SOURCE)
        for token in ("socket", "urllib", "http.client", "requests", "acquire_file",
                      "acquire_command", "evidence"):
            self.assertNotIn(token, code)

    def test_the_runtime_neither_evaluates_nor_issues_authority_itself(self):
        names = _names(RUNNER_SOURCE)
        for token in ("evaluate", "issue_authorization", "build_key_registry", "sign"):
            self.assertNotIn(token, names)
        code = _code_text(RUNNER_SOURCE)
        self.assertIn("verify_authorization", code)   # verification is called, not reimplemented
        self.assertIn("consume_once", code)           # consumption is the store's, not a second one
        self.assertIn("issue_receipt", code)          # receipts are the receipt unit's

    def test_no_shell_is_reachable(self):
        code = _code_text(RUNNER_SOURCE)
        for token in ("shell = True", "os.system", "shlex", "popen2", "execv"):
            self.assertNotIn(token, code)
        self.assertIn("shell = False", code)
        raw = RUNNER_SOURCE.read_text(encoding="utf-8")
        for interpreter in ("/bin/sh", "/bin/bash", "/usr/bin/env", "cmd.exe", "powershell"):
            self.assertNotIn(interpreter, raw)

    def test_only_one_process_is_ever_created(self):
        code = _code_text(RUNNER_SOURCE)
        self.assertEqual(code.count("subprocess . Popen"), 1)
        for token in ("subprocess . run", "subprocess . call", "subprocess . check_output",
                      "os . spawn", "os . fork", "multiprocessing"):
            self.assertNotIn(token, code)


class Vocabulary(unittest.TestCase):
    BANNED_EXACT = ("PAS_s", "PAS_h", "TEMPOLOCK", "CHORDLOCK", "GLYPHLOCK", "AURA", "ELF")
    BANNED_ANYCASE = ("resonance", "coherence", "regime", "corridor", "entitlement",
                      "constitution", "forcing", "admissibility", "lockgraph", "glyph",
                      "phase", "kernel")

    def test_no_banned_vocabulary_in_this_unit_or_the_repaired_guide(self):
        # This file is the scanner and is not scanned; the repo-wide grep excludes it likewise.
        paths = ([RUNNER_SOURCE, REPO_ROOT / "spec" / "execution.md",
                  REPO_ROOT / "docs" / "EXTRACTION_GUIDE.md"]
                 + sorted(EXEC_DIR.glob("*.json")))
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for word in self.BANNED_EXACT:
                with self.subTest(path=path.name, word=word):
                    self.assertNotIn(word, text)
            for word in self.BANNED_ANYCASE:
                with self.subTest(path=path.name, word=word):
                    self.assertNotIn(word, text.lower())

    def test_no_legacy_reference(self):
        for path in (RUNNER_SOURCE, REPO_ROOT / "spec" / "execution.md"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("ric_core", text)
            self.assertNotIn("ric-core", text)


if __name__ == "__main__":
    unittest.main()


class UnrecordedReceiptSurvives(unittest.TestCase):
    """An action that happened may not be erased by the failure to file it.

    Below the consume line the world may already have changed and the authority is spent, so the
    signed receipt is the only thing left that can still be true about it. It was handed back on
    the exception and then dropped: `receipts list` answered "no receipts yet" about a command
    that had run, the store denying what the runtime did.
    """

    def setUp(self):
        self.case = _case(EXEC_DIR / "accept_exit_zero.json")
        self.registry = _registry()

    def _failing_store_run(self, failure=OSError("the receipt store is unavailable")):
        sandbox = _Sandbox(self.case["tree"])
        self.addCleanup(sandbox.__exit__, None, None, None)
        built = _build(self.case, sandbox, self.registry)
        real = store_module.LocalStore.put_record

        def broken(self, *args, **kwargs):
            raise failure

        store_module.LocalStore.put_record = broken
        try:
            with self.assertRaises(ExecutionRecordingFailed) as caught:
                _run(self.case, sandbox, self.registry, *built)
        finally:
            store_module.LocalStore.put_record = real
        return sandbox, built, caught.exception

    def test_the_signed_receipt_is_preserved_where_a_person_can_find_it(self):
        sandbox, built, failure = self._failing_store_run()
        self.assertEqual(failure.stage, "store")
        self.assertIsNotNone(failure.receipt)
        self.assertIsNotNone(failure.preserved_at, "the signed receipt was not preserved")

        preserved = pathlib.Path(failure.preserved_at)
        self.assertTrue(preserved.is_file())
        self.assertEqual(preserved.read_bytes(), failure.receipt.canonical_bytes)
        self.assertTrue(preserved.name.endswith(".unrecorded.json"))

    def test_the_preserved_bytes_are_canonical_and_the_signature_verifies(self):
        sandbox, built, failure = self._failing_store_run()
        raw = pathlib.Path(failure.preserved_at).read_bytes()
        value = load.load_json_bytes(raw)
        self.assertEqual(canon.canonical_bytes(value), raw)
        report = receipt_module.verify_receipt(value, _receipt_registry(self.case), self.registry)
        self.assertTrue(report.signature_valid)
        self.assertEqual(report.receipt_id, self.case["receipt_id"])

    def test_it_is_never_mistaken_for_a_committed_record(self):
        sandbox, built, failure = self._failing_store_run()
        self.assertEqual(sandbox.store.listing().summaries, ())
        self.assertEqual(sandbox.store.listing().refused, ())
        with self.assertRaises(VerifyError):
            sandbox.store.get_record(self.case["receipt_id"], verify=False)
        self.assertIn(pathlib.Path(failure.preserved_at).name, sandbox.store.scan().abandoned_staging)

    def test_the_nonce_stays_spent_and_nothing_is_re_executed(self):
        sandbox, built, failure = self._failing_store_run()
        self.assertTrue(sandbox.store.is_consumed(built[4].nonce),
                        "preserving a receipt must not un-spend the authority")

    def test_preserving_twice_is_idempotent_and_a_conflict_fails_closed(self):
        sandbox, built, failure = self._failing_store_run()
        signed = failure.receipt
        again = sandbox.store.preserve_unrecorded(signed)
        self.assertEqual(pathlib.Path(again).read_bytes(), signed.canonical_bytes)

        pathlib.Path(failure.preserved_at).write_bytes(b'{"different": true}')
        with self.assertRaises(VerifyError) as conflict:
            sandbox.store.preserve_unrecorded(signed)
        self.assertEqual(conflict.exception.code, "store_record_conflict")

    def test_a_symlinked_preservation_path_is_refused(self):
        with _Sandbox(self.case["tree"]) as sandbox:
            built = _build(self.case, sandbox, self.registry)
            target = sandbox.base / "elsewhere.json"
            link = sandbox.store.unrecorded_path(self.case["receipt_id"])
            link.symlink_to(target)
            signed = receipt_module.issue_receipt(
                built[0], built[1], built[2], built[3], built[4],
                {"acknowledged": True, "acknowledged_at": self.case["acknowledged_at"],
                 "exit_status": 0},
                self.case["receipt_id"], self.case["receipt_created_at"],
                self.case["receipt_key"]["key_id"], self.case["receipt_key"]["key_version"],
                bytes.fromhex(self.case["receipt_key"]["private_key_hex"]), self.registry)
            with self.assertRaises(VerifyError) as caught:
                sandbox.store.preserve_unrecorded(signed)
            self.assertEqual(caught.exception.code, "store_path_invalid")
            self.assertFalse(target.exists(), "the link was followed")

    def test_preservation_failing_too_is_reported_rather_than_guessed(self):
        sandbox = _Sandbox(self.case["tree"])
        self.addCleanup(sandbox.__exit__, None, None, None)
        built = _build(self.case, sandbox, self.registry)
        real_put = store_module.LocalStore.put_record
        real_preserve = store_module.LocalStore.preserve_unrecorded
        store_module.LocalStore.put_record = lambda self, *a, **k: (_ for _ in ()).throw(OSError("x"))
        store_module.LocalStore.preserve_unrecorded = \
            lambda self, *a, **k: (_ for _ in ()).throw(OSError("tmp is gone too"))
        try:
            with self.assertRaises(ExecutionRecordingFailed) as caught:
                _run(self.case, sandbox, self.registry, *built)
        finally:
            store_module.LocalStore.put_record = real_put
            store_module.LocalStore.preserve_unrecorded = real_preserve
        self.assertIsNone(caught.exception.preserved_at,
                          "a preservation that did not happen must not be claimed")
        self.assertIsNotNone(caught.exception.receipt, "the receipt still travels on the failure")


class ExecutableIdentityDoesNotDependOnSpelling(unittest.TestCase):
    """A receipt naming one program while another runs defeats the point of recording the action.

    The two branches of `resolve_program` disagreed. A bare name was checked with
    `not candidate.is_symlink()` and refused a link; a path form was checked with `is_file()`,
    which **follows** one, and accepted it. So `bin/deploy.sh` pointing at `elsewhere.sh` was
    ALLOWed and executed — with the receipt, the candidate digest and the authorization all
    naming `bin/deploy.sh` — while the identical link written as `deploy.sh` was refused. How the
    caller spelled argv[0] decided whether a symlink was permitted.

    Refusal is the repair rather than canonicalization: the config, the signing keys, the trust
    registry, every store entry and evidence paths already reject a symlink instead of resolving
    one, and canonicalizing would change what a candidate digest denotes.

    What is asserted here is **path identity** — the recorded name is a real regular executable
    file and not an alias. Not content identity: nothing claims the bytes checked are the bytes
    that run.
    """

    def setUp(self):
        self.room = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.room, ignore_errors=True)
        self.bin = self.room / "bin"
        self.bin.mkdir()

    def _executable(self, path, body="real"):
        path.write_text("#!/bin/sh\necho %s\n" % body, encoding="utf-8")
        os.chmod(path, 0o755)
        return path

    def _workspace(self, search_path=("bin",)):
        class Config(dict):
            pass

        config = {"execution": {"working_directory": "."}, "search_path": list(search_path)}
        return types.SimpleNamespace(
            path=lambda relative: self.room / relative, config=config)

    def test_both_spellings_accept_a_plain_executable(self):
        self._executable(self.bin / "deploy.sh")
        workspace = self._workspace()
        self.assertEqual(workflow.resolve_program(workspace, "bin/deploy.sh"), "bin/deploy.sh")
        self.assertEqual(workflow.resolve_program(workspace, "deploy.sh"),
                         str(self.bin / "deploy.sh"))

    def test_both_spellings_refuse_a_symlinked_executable(self):
        self._executable(self.room / "elsewhere.sh", "decoy")
        (self.bin / "deploy.sh").symlink_to(self.room / "elsewhere.sh")
        workspace = self._workspace()
        for spelling in ("bin/deploy.sh", "deploy.sh"):
            with self.subTest(argv0=spelling):
                with self.assertRaises(VerifyError) as caught:
                    workflow.resolve_program(workspace, spelling)
                self.assertEqual(caught.exception.code, "cli_executable_not_found")

    def test_a_symlink_chain_is_refused_at_the_first_link(self):
        self._executable(self.room / "target.sh")
        (self.room / "hop.sh").symlink_to(self.room / "target.sh")
        (self.bin / "deploy.sh").symlink_to(self.room / "hop.sh")
        with self.assertRaises(VerifyError):
            workflow.resolve_program(self._workspace(), "bin/deploy.sh")

    def test_a_dangling_symlink_is_refused_and_named_as_a_symlink(self):
        (self.bin / "deploy.sh").symlink_to(self.room / "absent.sh")
        with self.assertRaises(VerifyError) as caught:
            workflow.resolve_program(self._workspace(), "bin/deploy.sh")
        self.assertIn("symlink", str(caught.exception).lower())

    def test_a_directory_and_a_fifo_are_not_executables(self):
        (self.bin / "adir").mkdir()
        os.mkfifo(self.bin / "afifo")
        for name in ("adir", "afifo"):
            for spelling in ("bin/" + name, name):
                with self.subTest(argv0=spelling):
                    with self.assertRaises(VerifyError):
                        workflow.resolve_program(self._workspace(), spelling)

    def test_a_non_executable_regular_file_is_refused(self):
        (self.bin / "notexec.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(self.bin / "notexec.sh", 0o644)
        for spelling in ("bin/notexec.sh", "notexec.sh"):
            with self.subTest(argv0=spelling):
                with self.assertRaises(VerifyError):
                    workflow.resolve_program(self._workspace(), spelling)
