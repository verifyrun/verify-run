"""Separate executable interface investigation; not historical conformance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import consumer_interface_probe as probe


class CapturedExecution(unittest.TestCase):
    def setUp(self):
        self.room = tempfile.TemporaryDirectory()
        self.addCleanup(self.room.cleanup)
        self.root = Path(self.room.name).resolve()
        self.source = self.root / "checker.py"
        self.source.write_text('print("captured-original")\n')
        self.environment = {"LC_ALL": "C"}
        if sys.platform == "darwin":
            self.environment["__CF_USER_TEXT_ENCODING"] = "0x%X:0x0:0x0" % os.getuid()
        self.data = probe.capture(self.source, self.root, self.environment)
        self.expected = hashlib.sha256(self.data).hexdigest()

    def run_checker(self, data=None, environment=None, cwd=None, flags=True):
        data = self.data if data is None else data
        argv = probe.command(data, hashlib.sha256(data).hexdigest())
        if not flags:
            argv.remove("-I")
        return subprocess.run(argv, cwd=cwd or self.root,
                              env=self.environment if environment is None else environment,
                              capture_output=True, timeout=10)

    def test_correct_context_executes_captured_checker(self):
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"captured-original\n")

    def test_original_source_mutation_cannot_replace_captured_execution(self):
        self.source.write_text('raise RuntimeError("replacement executed")\n')
        result = self.run_checker()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"captured-original\n")

    def test_source_body_substitution_refuses(self):
        value = json.loads(self.data)
        value["source"] = "cHJpbnQoJ3N1YnN0aXR1dGVkJyk="
        changed = probe.encode(value)
        with self.assertRaises(ValueError):
            probe.command(changed, self.expected)
        # Even a re-approved envelope cannot evade the worker's actual source check.
        result = self.run_checker(data=changed)
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, b"")

    def test_unknown_profile_refuses_without_launch(self):
        value = json.loads(self.data)
        value["profile"] = "engineering-improvement-v1"
        changed = probe.encode(value)
        with self.assertRaises(ValueError):
            probe.command(changed, hashlib.sha256(changed).hexdigest())

    def test_environment_change_refuses_before_checker(self):
        result = self.run_checker(environment={"LC_ALL": "C", "MODE": "changed"})
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, b"")

    def test_directory_change_refuses_before_checker(self):
        other = self.root / "other"
        other.mkdir()
        result = self.run_checker(cwd=other)
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, b"")

    def test_interpreter_flags_change_refuses_before_checker(self):
        result = self.run_checker(flags=False)
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, b"")

    def test_mutations_after_authorization_observe_both_boundaries(self):
        # Internal test setup only; the consumer tool itself uses exclusively the public CLI.
        from tests.test_execution import _Sandbox, _build, _run, _registry, EXEC_DIR
        from vfy.errors import VerifyError
        for mutation in ("source", "environment", "argv"):
            with self.subTest(mutation=mutation):
                case = json.loads((EXEC_DIR / "accept_exit_zero.json").read_text())
                with _Sandbox(case["tree"]) as sandbox:
                    source = sandbox.root / "checker.py"
                    source.write_text('print("captured-original")\n')
                    data = probe.capture(source, sandbox.root, self.environment)
                    case["candidate"]["action"]["argv"] = probe.command(
                        data, hashlib.sha256(data).hexdigest())
                    registry = _registry()
                    pinned, candidate, frozen, result, granted = _build(case, sandbox, registry)
                    environment = dict(self.environment)
                    # All following substitutions occur after authority has been issued.
                    if mutation == "source":
                        source.write_text('raise RuntimeError("replacement")\n')
                    elif mutation == "environment":
                        environment["MODE"] = "changed-after-authorization"
                    else:
                        candidate["action"]["argv"][-1] += " "
                    if mutation == "argv":
                        with self.assertRaises(VerifyError) as caught:
                            _run(case, sandbox, registry, pinned, candidate, frozen, result,
                                 granted, environment=environment)
                        self.assertEqual(caught.exception.code, "authorization_binding_mismatch")
                        self.assertFalse(sandbox.store.is_consumed(granted.nonce))
                    else:
                        record = _run(case, sandbox, registry, pinned, candidate, frozen, result,
                                      granted, environment=environment)
                        self.assertTrue(sandbox.store.is_consumed(granted.nonce))
                        self.assertEqual(record.exit_status, 0 if mutation == "source" else 65)
                        self.assertEqual(record.stdout, b"captured-original\n" if mutation == "source" else b"")
