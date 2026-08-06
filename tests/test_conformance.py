"""The conformance kit's own self-audit.

A conformance runner that cannot tell a conforming implementation from a plausible impostor is
worse than none: it converts an unexamined claim into a document that looks like evidence. So the
load-bearing tests here are not the ones that show the reference implementation passing. They are
the ones that build deliberately nonconforming adapters and require the runner to refuse them, for
the stated reason, every time.

Each stub is a small script speaking the adapter protocol. None of them touches `verify-run`: they
answer from a table, which is exactly what a dishonest implementation would do.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROFILE = REPO / "conformance" / "decision-replay-v1" / "profile.json"
MANIFEST = REPO / "conformance" / "decision-replay-v1" / "fixtures" / "manifest.json"
RUNNER = REPO / "tools" / "run_conformance.py"
ADAPTER = REPO / "tools" / "conformance_adapter.py"

EXIT_PASS, EXIT_FAIL, EXIT_INCOMPLETE, EXIT_RUNNER_ERROR = 0, 1, 2, 3

STUB_HEADER = '''
import json, sys, time
request = json.loads(sys.stdin.read())
operation = request.get("operation")
bundle = (request.get("bundle") or "").rsplit("/", 1)[-1]
POSITIVE = {"allow-with-execution": "ALLOW", "allow-without-execution": "ALLOW",
            "allow-retired-key": "ALLOW", "block": "BLOCK", "hold": "HOLD"}
def answer(body):
    body.setdefault("adapter", "stub")
    body.setdefault("implementation", {"name": "stub", "version": "0"})
    body.setdefault("operation", operation)
    sys.stdout.write(json.dumps(body))
    raise SystemExit(0)
if operation == "capabilities":
    answer({"operations": ["replay"], "live_spend": False,
            "accepted_profiles": ["decision-replay-v1"], "historical_replay_supported": True})
def honest():
    """What a conforming implementation would report for this bundle."""
    if bundle in POSITIVE:
        return {"accepted": True, "terminal": POSITIVE[bundle], "signature_verified": True,
                "recomputed": True, "bindings_verified": True, "error_category": None}
    return {"accepted": False, "terminal": None, "signature_verified": False,
            "recomputed": False, "error_category": CATEGORY.get(bundle, "signature_invalid")}
CATEGORY = {
 "unknown-field": "artifact_schema_invalid", "unsupported-replay-mode": "artifact_schema_invalid",
 "no-signature": "artifact_schema_invalid", "malformed-signature": "signature_malformed",
 "altered-key-id": "key_untrusted", "altered-key-version": "key_untrusted",
 "unknown-receipt-key": "key_untrusted", "untrusted-key-valid-signature": "key_untrusted",
 "missing-rulebook-body": "input_missing", "missing-candidate-body": "input_missing",
 "missing-snapshot-body": "input_missing", "wrong-rulebook-body": "binding_mismatch",
 "wrong-candidate-body": "binding_mismatch", "wrong-snapshot-body": "binding_mismatch",
 "authorization-not-the-one-named": "binding_mismatch",
 "altered-nested-result": "binding_mismatch",
}
'''

# name -> the body appended to STUB_HEADER, and the reason the runner must refuse it.
STUBS = {
    "maps-hold-to-block": ('''
result = honest()
if result.get("terminal") == "HOLD":
    result["terminal"] = "BLOCK"
answer(result)
''', "collapses HOLD into BLOCK"),

    "maps-error-to-block": ('''
result = honest()
if not result["accepted"]:
    result = {"accepted": True, "terminal": "BLOCK", "signature_verified": True,
              "recomputed": True, "bindings_verified": True}
answer(result)
''', "reports a refusal as a BLOCK decision"),

    "defaults-allow": ('''
answer({"accepted": True, "terminal": "ALLOW", "signature_verified": True,
        "recomputed": True, "bindings_verified": True})
''', "defaults to ALLOW"),

    "signs-but-cannot-recompute": ('''
result = honest()
if result["accepted"]:
    result["recomputed"] = False
answer(result)
''', "verifies a signature without recomputing the decision"),

    "verifies-database-verdict-only": ('''
result = honest()
if result["accepted"]:
    result["signature_verified"] = False
answer(result)
''', "reports a stored verdict without verifying the artifact"),

    "rejects-expired-allow": ('''
result = honest()
if bundle.startswith("allow"):
    result = {"accepted": False, "terminal": None, "signature_verified": False,
              "recomputed": False, "error_category": "authorization_not_spendable"}
answer(result)
''', "requires a historical authorization to be presently spendable"),

    "ignores-altered-candidate-binding": ('''
result = honest()
if bundle == "altered-candidate-digest":
    result = {"accepted": True, "terminal": "ALLOW", "signature_verified": True,
              "recomputed": True, "bindings_verified": True}
answer(result)
''', "accepts an artifact whose candidate binding was altered"),

    "ignores-altered-acknowledgment": ('''
result = honest()
if bundle == "altered-execution-acknowledgment":
    result = {"accepted": True, "terminal": "ALLOW", "signature_verified": True,
              "recomputed": True, "bindings_verified": True}
answer(result)
''', "accepts a mutated execution acknowledgment"),

    "trusts-unknown-key": ('''
result = honest()
if bundle in ("unknown-receipt-key", "untrusted-key-valid-signature"):
    result = {"accepted": True, "terminal": "ALLOW", "signature_verified": True,
              "recomputed": True, "bindings_verified": True}
answer(result)
''', "trusts a key the anchor does not hold"),

    "malformed-output": ('''
sys.stdout.write("this is not JSON")
raise SystemExit(0)
''', "emits an unreadable envelope"),

    "hangs": ('''
time.sleep(120)
''', "does not answer"),

    "floods-output": ('''
sys.stdout.write("x" * (4 << 20))
raise SystemExit(0)
''', "floods the runner with output"),

    # The marker is assembled at run time on purpose. A repository file must not contain a PEM
    # header literal, even a fake one: the secret gate cannot tell a decoy from a leak, and it
    # should not have to. The stub still emits a real-looking marker where it matters — at run
    # time, in the adapter's output, which is exactly what the runner has to catch.
    "leaks-private-key": ('''
result = honest()
result["note"] = "-" * 5 + "BEGIN " + "PRIVATE KEY" + "-" * 5 + " MIIEvQIBADANBg"
answer(result)
''', "emits private key material"),
}


def write_stub(directory, name):
    path = Path(directory) / (name.replace("-", "_") + ".py")
    body, _ = STUBS[name]
    path.write_text(STUB_HEADER + body, encoding="utf-8")
    return path


def run_suite(adapter_command, out_path, profile=PROFILE, environment=None, adapter_args=None):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    if environment:
        env.update(environment)
    selection = ["--adapter", adapter_command] if adapter_args is None else \
        sum((["--adapter-arg", token] for token in adapter_args), [])
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "--profile", str(profile),
         "--out", str(out_path), "--adapter-timeout", "5"] + selection,
        capture_output=True, text=True, cwd=tempfile.gettempdir(), env=env, timeout=1200)
    document = None
    if Path(out_path).is_file():
        try:
            document = json.loads(Path(out_path).read_text(encoding="utf-8"))
        except ValueError:
            document = None
    return completed, document


class RunnerRefusesNonconformingImplementations(unittest.TestCase):
    """The load-bearing suite. Each stub must be refused, and for its own reason."""

    @classmethod
    def setUpClass(cls):
        cls._directory = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls._directory.name)

    @classmethod
    def tearDownClass(cls):
        cls._directory.cleanup()

    def _run_stub(self, name):
        stub = write_stub(self.workspace, name)
        out = self.workspace / (name + "-result.json")
        return run_suite("%s %s" % (sys.executable, stub), out)

    def test_every_nonconforming_stub_is_refused(self):
        for name, (_, reason) in sorted(STUBS.items()):
            with self.subTest(stub=name, reason=reason):
                completed, document = self._run_stub(name)
                self.assertNotEqual(
                    completed.returncode, EXIT_PASS,
                    "a stub that %s obtained PASS:\n%s" % (reason, completed.stdout))
                if document is not None:
                    self.assertNotEqual(document["overall"], "PASS",
                                        "a stub that %s wrote a PASS result" % reason)

    def test_the_stubs_are_not_vacuous(self):
        """An honest stub must PASS, or the suite above proves nothing about discrimination."""
        stub = self.workspace / "honest.py"
        stub.write_text(STUB_HEADER + "answer(honest())\n", encoding="utf-8")
        completed, document = run_suite("%s %s" % (sys.executable, stub),
                                        self.workspace / "honest-result.json")
        self.assertEqual(completed.returncode, EXIT_PASS,
                         "the honest stub must pass, otherwise every refusal above is "
                         "indistinguishable from a broken runner:\n" + completed.stdout)
        self.assertEqual(document["overall"], "PASS")

    def test_the_expired_allow_stub_fails_on_exactly_the_historical_requirement(self):
        """The stub that mirrors the 0.1.0a1 defect must fail on the ALLOW replay fixtures."""
        completed, document = self._run_stub("rejects-expired-allow")
        self.assertEqual(completed.returncode, EXIT_FAIL)
        failed = {entry["fixture_id"] for entry in document["fixtures"]
                  if entry["status"] != "PASS"}
        self.assertTrue(all(name.startswith("positive/allow") for name in failed), failed)
        self.assertEqual(document["requirement_status"].get("DR-6.6"), "FAIL")

    def test_a_leaked_secret_marker_never_reaches_the_result(self):
        completed, document = self._run_stub("leaks-private-key")
        self.assertNotEqual(completed.returncode, EXIT_PASS)
        if document is not None:
            self.assertNotIn("BEGIN PRIVATE KEY",
                             json.dumps(document), "secret material reached the result document")


class SetupFailuresAreNotVerdicts(unittest.TestCase):
    """A run that could not be conducted is INCOMPLETE. It is never FAIL.

    FAIL is a statement about an implementation. An adapter that will not start, times out, or
    does not speak the protocol says nothing whatever about the implementation behind it, and
    thirty fixtures reported as errors used to add up to exactly that false statement.
    """

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.workspace = Path(self._directory.name)
        self.addCleanup(self._directory.cleanup)

    def _stub(self, body, name="stub.py", directory=None):
        path = Path(directory or self.workspace) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def _run(self, body, **over):
        stub = self._stub(body)
        return run_suite("%s %s" % (sys.executable, stub),
                         self.workspace / "result.json", **over)

    def test_an_adapter_that_is_not_there_is_a_runner_error_named_in_one_sentence(self):
        completed, _ = run_suite(str(self.workspace / "absent") + " x",
                                 self.workspace / "result.json")
        self.assertEqual(completed.returncode, EXIT_RUNNER_ERROR)
        self.assertIn("not runnable", completed.stderr)
        self.assertIn("--adapter-arg", completed.stderr, "the remedy was not named")

    def test_an_adapter_that_says_nothing_is_incomplete_not_failed(self):
        completed, document = self._run("import sys\nsys.exit(1)\n")
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertEqual(document["overall"], "INCOMPLETE")
        self.assertEqual(document["counts"]["failed"], 0,
                         "a harness problem was counted as a failed fixture")
        self.assertIn("could not be conducted", completed.stderr)

    def test_an_adapter_that_declares_its_own_problem_is_incomplete_and_runs_nothing(self):
        completed, document = self._run(
            'import json, sys\n'
            'sys.stdout.write(json.dumps({"adapter": "stub", "accepted": False,'
            ' "adapter_error": "vfy is not installed in this environment"}))\n')
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertEqual(document["overall"], "INCOMPLETE")
        self.assertEqual(document["fixtures"], [],
                         "fixtures were run against an adapter that had already said it could not")
        self.assertIn("vfy is not installed", completed.stderr)

    def test_an_adapter_for_another_profile_is_incomplete_rather_than_measured(self):
        completed, document = self._run(
            'import json, sys\n'
            'request = json.loads(sys.stdin.read())\n'
            'sys.stdout.write(json.dumps({"adapter": "stub", "operation": '
            'request.get("operation"), "accepted": True, "accepted_profiles": ["something-else"]}))\n')
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertEqual(document["fixtures"], [])
        self.assertIn("something-else", completed.stderr)

    def test_an_adapter_that_hangs_is_incomplete_not_failed(self):
        completed, document = self._run("import time\ntime.sleep(600)\n")
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertEqual(document["overall"], "INCOMPLETE")

    def test_a_leaked_secret_is_still_a_failure_and_not_a_setup_problem(self):
        """The one carve-out: this is a real defect of the thing under test, not a harness fault."""
        stub = write_stub(self.workspace, "leaks-private-key")
        completed, document = run_suite("%s %s" % (sys.executable, stub),
                                        self.workspace / "leak-result.json")
        self.assertEqual(completed.returncode, EXIT_FAIL)
        self.assertEqual(document["overall"], "FAIL")
        self.assertNotIn("BEGIN PRIVATE KEY", json.dumps(document))

    def test_a_path_with_spaces_survives_adapter_arg_and_would_not_survive_adapter(self):
        directory = self.workspace / "my tools"
        stub = self._stub(STUB_HEADER + "answer(honest())\n", "honest.py", directory)

        completed, document = run_suite(None, self.workspace / "spaced-result.json",
                                        adapter_args=[sys.executable, str(stub)])
        self.assertEqual(completed.returncode, EXIT_PASS, completed.stdout + completed.stderr)
        self.assertEqual(document["overall"], "PASS")

        # The same command through the split form: the space ends a token, so the adapter is
        # handed two nonexistent paths instead of one real one. It must not PASS, and it must not
        # FAIL either — nothing was measured.
        completed, _ = run_suite("%s %s" % (sys.executable, stub),
                                 self.workspace / "split-result.json")
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertIn("could not be conducted", completed.stderr)

    def test_the_runner_preflight_names_the_version_it_needs(self):
        runner = _import_runner()
        self.assertIsNone(runner.preflight((3, 12, 0)))
        message = runner.preflight((3, 7, 0))
        self.assertIn("3.8", message)
        self.assertIn("3.7", message)

    def test_the_adapter_preflight_names_the_distributions_own_floor(self):
        completed = subprocess.run(
            [sys.executable, "-c",
             "import runpy, sys; sys.argv=['a']; "
             "module = runpy.run_path(%r); "
             "print(module['MINIMUM_PYTHON'])" % str(ADAPTER)],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("(3, 11)", completed.stdout)


def _import_runner():
    import importlib.util
    spec = importlib.util.spec_from_file_location("_conformance_runner", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManifestIntegrityIsEnforced(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.workspace = Path(self._directory.name)
        self.copy = self.workspace / "conformance"
        shutil.copytree(REPO / "conformance", self.copy)
        self.profile = self.copy / "decision-replay-v1" / "profile.json"

    def tearDown(self):
        self._directory.cleanup()

    def _honest_adapter(self):
        stub = self.workspace / "honest.py"
        stub.write_text(STUB_HEADER + "answer(honest())\n", encoding="utf-8")
        return "%s %s" % (sys.executable, stub)

    def test_an_altered_fixture_makes_the_run_incomplete(self):
        target = self.copy / "decision-replay-v1" / "fixtures" / "block" / "candidate.json"
        target.write_bytes(target.read_bytes() + b" ")
        completed, document = run_suite(self._honest_adapter(),
                                        self.workspace / "out.json", profile=self.profile)
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertEqual(document["overall"], "INCOMPLETE")
        self.assertTrue(any("digest mismatch" in problem
                            for problem in document["manifest_problems"]))

    def test_a_missing_fixture_makes_the_run_incomplete(self):
        (self.copy / "decision-replay-v1" / "fixtures" / "hold" / "snapshot.json").unlink()
        completed, document = run_suite(self._honest_adapter(),
                                        self.workspace / "out.json", profile=self.profile)
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertTrue(any("listed but absent" in problem
                            for problem in document["manifest_problems"]))

    def test_an_unlisted_fixture_makes_the_run_incomplete(self):
        (self.copy / "decision-replay-v1" / "fixtures" / "hold" / "extra.json").write_text("{}")
        completed, document = run_suite(self._honest_adapter(),
                                        self.workspace / "out.json", profile=self.profile)
        self.assertEqual(completed.returncode, EXIT_INCOMPLETE)
        self.assertTrue(any("present but unlisted" in problem
                            for problem in document["manifest_problems"]))

    def test_the_result_carries_the_manifest_digest_so_a_change_invalidates_it(self):
        completed, before = run_suite(self._honest_adapter(),
                                      self.workspace / "before.json", profile=self.profile)
        self.assertEqual(completed.returncode, EXIT_PASS)
        manifest = self.copy / "decision-replay-v1" / "fixtures" / "manifest.json"
        manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        _, after = run_suite(self._honest_adapter(),
                             self.workspace / "after.json", profile=self.profile)
        self.assertNotEqual(before["fixture_manifest_sha256"],
                            after["fixture_manifest_sha256"],
                            "a result must not survive a change to the fixture manifest")


class ProfileAndFixturesAreInternallyConsistent(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.document = (REPO / "docs" / "conformance" / "decision-replay-v1.md") \
            .read_text(encoding="utf-8")
        # The document is hard-wrapped prose. Searching it for a sentence must not depend on
        # where a line happens to break.
        self.flat = " ".join(self.document.split())

    def test_every_requirement_in_the_document_has_a_fixture(self):
        import re
        stated = set(re.findall(r"\*\*(DR-\d+\.\d+)\*\*", self.document))
        covered = {requirement for fixture in self.manifest["fixtures"]
                   for requirement in fixture["requirements"]}
        # DR-3.5 and DR-9.1 are declared without a fixture, each for a stated reason.
        exempt = {"DR-3.5", "DR-9.1"}
        self.assertTrue(stated, "no requirements were parsed out of the normative document")
        missing = stated - covered - exempt
        self.assertEqual(missing, set(), "requirements with no fixture: %s" % sorted(missing))

    def test_every_fixture_requirement_exists_in_the_document(self):
        import re
        stated = set(re.findall(r"\*\*(DR-\d+\.\d+)\*\*", self.document))
        covered = {requirement for fixture in self.manifest["fixtures"]
                   for requirement in fixture["requirements"]}
        invented = covered - stated
        self.assertEqual(invented, set(),
                         "the fixtures assert requirements the contract does not state: %s"
                         % sorted(invented))

    def test_the_exempt_requirements_state_why_they_have_no_fixture(self):
        self.assertIn("**DR-3.5** — no fixture", self.flat)
        self.assertIn("**DR-9.1** — no fixture in the bundle sense", self.flat)

    def test_the_profile_and_manifest_agree_on_identity(self):
        self.assertEqual(self.profile["profile_id"], self.manifest["profile_id"])
        self.assertEqual(self.profile["profile_version"], self.manifest["profile_version"])

    def test_every_negative_category_is_declared_by_the_profile(self):
        declared = set(self.profile["error_categories"])
        for fixture in self.manifest["fixtures"]:
            for category in fixture["expected"].get("error_category_any_of", []):
                self.assertIn(category, declared, fixture["fixture_id"])

    def test_the_profile_states_its_nonclaims(self):
        for phrase in ("exactly-once", "sandboxing", "regulatory"):
            self.assertTrue(any(phrase in claim for claim in self.profile["nonclaims"]), phrase)

    def test_the_normative_document_never_promises_re_execution(self):
        lowered = self.flat.lower()
        self.assertIn("recomputing a recorded decision is not re-executing an action", lowered)
        self.assertIn("replay spends nothing", lowered)

    def test_bundles_carry_no_evidence_source_or_executable(self):
        root = MANIFEST.parent
        allowed = {"rulebook.json", "rulebook.yaml", "candidate.json", "snapshot.json",
                   "authorization.json", "receipt.json", "trust.json"}
        for fixture in self.manifest["fixtures"]:
            for name in fixture["files"]:
                self.assertIn(name, allowed,
                              "%s carries %s" % (fixture["fixture_id"], name))
            for path in (root / fixture["bundle"]).iterdir():
                self.assertFalse(os.access(path, os.X_OK) and path.is_file()
                                 and path.suffix not in (".json", ".yaml"),
                                 "an executable is present in %s" % fixture["bundle"])


if __name__ == "__main__":
    unittest.main()
