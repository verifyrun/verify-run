"""Closure Unit 11 — bounded local evidence adapters for files and command output."""

import base64
import dataclasses
import inspect
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import tokenize
import unittest

import yaml

from vfy import canon, evidence, gate, load, rulebook, schema, snapshot
from vfy.errors import VerifyError
from vfy.evidence import _common, acquisition, command, file as file_adapter

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
ADAPTER_DIR = REPO_ROOT / "fixtures" / "adapters"
EVIDENCE_DIR = REPO_ROOT / "vfy" / "evidence"

ACQUIRED_AT = "2026-08-04T12:00:00Z"


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _case(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _materialize(tree, root):
    """Build the fixture's tree under `root`. Directories first, then links, so a link target
    inside the tree exists before the link does; a dangling link stays dangling."""
    for name in sorted(tree):
        entry = tree[name]
        target = root / name
        if entry["kind"] == "dir":
            target.mkdir(parents=True, exist_ok=True)
    for name in sorted(tree):
        entry = tree[name]
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if entry["kind"] == "dir":
            continue
        if entry["kind"] == "file":
            target.write_bytes(base64.b64decode(entry["bytes_base64"]))
            target.chmod(int(entry.get("mode", "0644"), 8))
        elif entry["kind"] == "fifo":
            os.mkfifo(target)
        elif entry["kind"] == "symlink":
            target.symlink_to(entry["target"])
        else:  # pragma: no cover - a fixture kind nobody declared
            raise AssertionError("unknown tree entry kind: " + entry["kind"])


class _Tree:
    """A materialized fixture tree that is always torn down, links and all."""

    def __init__(self, tree):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="vfy-adapter-"))
        _materialize(tree, self.root)

    def __enter__(self):
        return self.root

    def __exit__(self, *_):
        shutil.rmtree(self.root, ignore_errors=True)
        return False


def _acquire(case, root, adapter):
    """`adapter` is the one under test, taken from the fixture's name prefix. It is deliberately
    not read off the declaration: the wrong-source fixtures exist to prove each adapter refuses a
    declaration it does not own."""
    declaration = case["declaration"]
    at = case.get("acquired_at", ACQUIRED_AT)
    if adapter == "exec":
        kwargs = {}
        if "timeout_seconds" in case:
            kwargs["timeout_seconds"] = case["timeout_seconds"]
        if "environment" in case:
            kwargs["environment"] = case["environment"]
        if "working_directory" in case:
            kwargs["working_directory"] = root / case["working_directory"]
        return evidence.acquire_command(declaration, root, at, **kwargs)
    return evidence.acquire_file(declaration, root, at)


class Fixtures(unittest.TestCase):
    """Every fixture in fixtures/adapters/ is exercised, and none is skipped."""

    def test_every_fixture_is_claimed_by_a_test(self):
        names = {p.stem for p in ADAPTER_DIR.glob("*.json")}
        claimed = {n for n in names
                   if n.startswith(("file_", "command_", "bridge_"))}
        self.assertEqual(names, claimed)
        self.assertGreater(len(names), 60)

    def _run_case(self, path):
        case = _case(path)
        adapter = "exec" if path.name.startswith("command_") else "file"
        parent = case.get("parent_environment", {})
        restore = {name: os.environ.get(name) for name in parent}
        os.environ.update(parent)
        try:
            with _Tree(case["tree"]) as root:
                expected = case["expected"]
                if expected["class"] == "adapter_error":
                    with self.assertRaises(VerifyError) as caught:
                        _acquire(case, root, adapter)
                    self.assertEqual(caught.exception.code, expected["reason_code"], path.name)
                    return
                result = _acquire(case, root, adapter)
                self.assertEqual(result.as_acquisition(), expected["acquisition"], path.name)
                if "canonical" in expected:
                    self.assertEqual(result.canonical_value, expected["canonical"], path.name)
                    self.assertEqual(canon.hex_digest_of_text(result.canonical_value),
                                     expected["sha256"], path.name)
        finally:
            for name, value in restore.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_file_fixtures(self):
        paths = sorted(ADAPTER_DIR.glob("file_*.json"))
        self.assertGreaterEqual(len(paths), 30)
        for path in paths:
            with self.subTest(fixture=path.name):
                self._run_case(path)

    def test_command_fixtures(self):
        paths = sorted(ADAPTER_DIR.glob("command_*.json"))
        self.assertGreaterEqual(len(paths), 28)
        for path in paths:
            with self.subTest(fixture=path.name):
                self._run_case(path)


class Bridge(unittest.TestCase):
    """Adapter output goes straight into the builder and then into the closed evaluator."""

    def _bridge(self, path):
        case = _case(path)
        registry = _registry()
        source = (REPO_ROOT / case["rulebook_ref"]).read_bytes()
        pinned = rulebook.load_rulebook_bytes(source, registry)
        declarations = pinned.value()["evidence"]
        with _Tree(case["tree"]) as root:
            acquisitions = []
            for declaration in declarations:
                if declaration["source"] == "file":
                    result = evidence.acquire_file(declaration, root, case["acquired_at"])
                elif declaration["source"] == "exec":
                    result = evidence.acquire_command(declaration, root, case["acquired_at"],
                                                      timeout_seconds=5)
                else:
                    # No v1 adapter implements this source. Nothing is acquired, and the builder
                    # synthesizes the required item as missing.
                    continue
                acquisitions.append(result.as_acquisition())
            frozen = snapshot.build_snapshot(pinned, case["snapshot_id"], case["frozen_at"],
                                             acquisitions, registry)
            value = frozen.value()
            statuses = {item["id"]: item["status"] for item in value["items"]}
            self.assertEqual(statuses, case["expected"]["statuses"], path.name)
            result = gate.evaluate(pinned, case["candidate"], value, registry)
            self.assertEqual(result.outcome, case["expected"]["outcome"], path.name)
            if "matched_rule" in case["expected"]:
                self.assertEqual(result.value().get("matched_rule"),
                                 case["expected"]["matched_rule"], path.name)
            return frozen

    def test_bridge_fixtures(self):
        paths = sorted(ADAPTER_DIR.glob("bridge_*.json"))
        self.assertGreaterEqual(len(paths), 12)
        for path in paths:
            with self.subTest(fixture=path.name):
                self._bridge(path)

    def test_the_same_tree_freezes_to_the_same_digest_twice(self):
        for path in sorted(ADAPTER_DIR.glob("bridge_*.json")):
            with self.subTest(fixture=path.name):
                first, second = self._bridge(path), self._bridge(path)
                self.assertEqual(first.digest, second.digest)
                self.assertEqual(first.canonical, second.canonical)

    def test_every_template_source_is_either_implemented_or_visibly_absent(self):
        registry = _registry()
        for name in ("agent-guard", "pipeline-gate", "claims-gate"):
            pinned = rulebook.load_rulebook_bytes(
                (REPO_ROOT / "templates" / (name + ".yaml")).read_bytes(), registry)
            for declaration in pinned.value()["evidence"]:
                with self.subTest(rulebook=name, evidence=declaration["id"]):
                    if declaration["source"] in ("file", "exec"):
                        continue
                    # http and inline have no adapter, and nothing pretends otherwise.
                    for adapter in (evidence.acquire_file, evidence.acquire_command):
                        with self.assertRaises(VerifyError) as caught:
                            adapter(declaration, REPO_ROOT, ACQUIRED_AT)
                        self.assertEqual(caught.exception.code,
                                         "evidence_adapter_config_invalid")


class ResultShape(unittest.TestCase):
    def test_a_result_carries_no_order_no_source_and_no_diagnostic_text(self):
        with _Tree({"a.json": {"kind": "file",
                               "bytes_base64": base64.b64encode(b'{"x":1}').decode()}}) as root:
            result = evidence.acquire_file({"id": "docs_complete", "source": "file",
                                            "ref": "a.json"}, root, ACQUIRED_AT)
        self.assertEqual(set(result.as_acquisition()), {"id", "status", "acquired_at", "value"})
        self.assertEqual(sorted(f.name for f in
                                dataclasses.fields(acquisition.AcquisitionResult)),
                         ["acquired_at", "canonical_value", "id", "status"])

    def test_a_failed_result_carries_no_value_at_all(self):
        with _Tree({}) as root:
            result = evidence.acquire_file({"id": "approvals", "source": "file",
                                            "ref": "gone.json"}, root, ACQUIRED_AT)
        self.assertEqual(set(result.as_acquisition()), {"id", "status", "acquired_at"})
        self.assertIsNone(result.value())

    def test_no_adapter_originates_stale(self):
        self.assertEqual(acquisition.STATUSES, ("ok", "missing", "error"))
        self.assertNotIn("stale", acquisition.STATUSES)
        for name in ("file.py", "command.py", "acquisition.py", "_common.py", "__init__.py"):
            self.assertNotIn('"stale"', (EVIDENCE_DIR / name).read_text(encoding="utf-8"))

    def test_a_result_is_frozen_and_its_value_is_a_defensive_copy(self):
        with _Tree({"a.json": {"kind": "file",
                               "bytes_base64": base64.b64encode(b'{"x":[1,2]}').decode()}}) as root:
            result = evidence.acquire_file({"id": "docs_complete", "source": "file",
                                            "ref": "a.json"}, root, ACQUIRED_AT)
        with self.assertRaises(Exception):
            result.status = "ok"
        first = result.value()
        first["x"].append(3)
        self.assertEqual(result.value(), {"x": [1, 2]})

    def test_an_adapter_never_returns_a_terminal_outcome(self):
        for module in (file_adapter, command):
            text = inspect.getsource(module)
            for outcome in ("ALLOW", "BLOCK", "HOLD", "ERROR"):
                self.assertNotIn('"%s"' % outcome, text)


class PathDiscipline(unittest.TestCase):
    def test_escape_is_refused_by_resolution_for_every_spelling(self):
        with _Tree({"in": {"kind": "dir"}}) as root:
            for ref in ("..", "../x.json", "in/../../x.json", "./../x.json",
                        "in//../../x.json", "in/./../../x.json"):
                with self.subTest(ref=ref):
                    with self.assertRaises(VerifyError) as caught:
                        evidence.acquire_file({"id": "a", "source": "file", "ref": ref},
                                              root, ACQUIRED_AT)
                    self.assertEqual(caught.exception.code, "evidence_path_invalid")

    def test_a_spelling_that_lands_back_inside_is_not_refused(self):
        with _Tree({"in": {"kind": "dir"},
                    "in/a.json": {"kind": "file",
                                  "bytes_base64": base64.b64encode(b"1").decode()}}) as root:
            for ref in ("in/a.json", "./in/a.json", "in/../in/a.json", "in//a.json"):
                with self.subTest(ref=ref):
                    result = evidence.acquire_file({"id": "a", "source": "file", "ref": ref},
                                                   root, ACQUIRED_AT)
                    self.assertEqual((result.status, result.value()), ("ok", 1))

    def test_the_process_working_directory_never_decides_what_is_observed(self):
        with _Tree({"a.json": {"kind": "file",
                               "bytes_base64": base64.b64encode(b'"here"').decode()}}) as root:
            declaration = {"id": "a", "source": "file", "ref": "a.json"}
            first = evidence.acquire_file(declaration, root, ACQUIRED_AT)
            previous = os.getcwd()
            os.chdir(tempfile.gettempdir())
            try:
                second = evidence.acquire_file(declaration, root, ACQUIRED_AT)
            finally:
                os.chdir(previous)
            self.assertEqual(first, second)

    def test_a_relative_root_still_resolves(self):
        with _Tree({"a.json": {"kind": "file",
                               "bytes_base64": base64.b64encode(b'"here"').decode()}}) as root:
            previous = os.getcwd()
            os.chdir(root)
            try:
                result = evidence.acquire_file({"id": "a", "source": "file", "ref": "a.json"},
                                               pathlib.Path("."), ACQUIRED_AT)
            finally:
                os.chdir(previous)
            self.assertEqual(result.value(), "here")

    def test_a_root_that_does_not_exist_is_refused_rather_than_invented(self):
        with _Tree({}) as root:
            with self.assertRaises(VerifyError):
                evidence.acquire_file({"id": "a", "source": "file", "ref": "a.json"},
                                      root / "absent", ACQUIRED_AT)

    def test_a_root_that_is_not_a_path_is_a_caller_contract_violation(self):
        with self.assertRaises(VerifyError) as caught:
            evidence.acquire_file({"id": "a", "source": "file", "ref": "a.json"},
                                  "/tmp", ACQUIRED_AT)
        self.assertEqual(caught.exception.code, "evidence_adapter_config_invalid")


class CommandDiscipline(unittest.TestCase):
    def _script(self, body, name="probe.sh"):
        return {name: {"kind": "file",
                       "bytes_base64": base64.b64encode(
                           ("#!/bin/sh\n" + body).encode("utf-8")).decode(),
                       "mode": "0755"}}

    def test_a_ref_with_shell_metacharacters_is_one_literal_path(self):
        name = "a; echo x > y $(id) *.sh"
        with _Tree(self._script("printf '\"passed\"'\n", name)) as root:
            result = evidence.acquire_command({"id": "tests", "source": "exec", "ref": name},
                                              root, ACQUIRED_AT, timeout_seconds=5)
            self.assertEqual(result.value(), "passed")
            self.assertEqual(sorted(p.name for p in root.iterdir()), [name])

    def test_an_empty_environment_is_not_a_child_that_sees_no_path(self):
        """A shell interpreter synthesizes a default PATH when it inherits none. The adapter's
        guarantee is that the parent's value never reaches the child, not that the child's
        environment stays empty once an interpreter has started."""
        os.environ["PATH"] = "/vfy-parent-marker/bin:" + os.environ.get("PATH", "/usr/bin:/bin")
        try:
            with _Tree(self._script(
                    'printf \'{"path":"%s"}\' "${PATH-absent}"\n')) as root:
                result = evidence.acquire_command(
                    {"id": "tests", "source": "exec", "ref": "probe.sh"}, root, ACQUIRED_AT,
                    timeout_seconds=5)
                self.assertNotIn("vfy-parent-marker", result.value()["path"])
        finally:
            os.environ["PATH"] = os.environ["PATH"].replace("/vfy-parent-marker/bin:", "")

    def test_no_parent_variable_reaches_the_child(self):
        os.environ["VFY_UNIT_11_SENTINEL"] = "leaked"
        try:
            with _Tree(self._script(
                    'printf \'"%s"\' "${VFY_UNIT_11_SENTINEL-absent}"\n')) as root:
                result = evidence.acquire_command(
                    {"id": "tests", "source": "exec", "ref": "probe.sh"}, root, ACQUIRED_AT,
                    timeout_seconds=5)
                self.assertEqual(result.value(), "absent")
        finally:
            os.environ.pop("VFY_UNIT_11_SENTINEL", None)

    def test_an_explicit_environment_is_exactly_what_the_child_sees(self):
        with _Tree(self._script(
                'printf \'{"a":"%s","b":"%s"}\' "${A-absent}" "${B-absent}"\n')) as root:
            result = evidence.acquire_command({"id": "tests", "source": "exec", "ref": "probe.sh"},
                                              root, ACQUIRED_AT, timeout_seconds=5,
                                              environment={"A": "given"})
            self.assertEqual(result.value(), {"a": "given", "b": "absent"})

    def test_a_non_string_environment_entry_is_a_typed_adapter_error(self):
        with _Tree(self._script("printf '\"passed\"'\n")) as root:
            for bad in ({"A": 1}, {1: "a"}, "PATH=/bin", ["A=1"]):
                with self.subTest(environment=bad):
                    with self.assertRaises(VerifyError) as caught:
                        evidence.acquire_command(
                            {"id": "tests", "source": "exec", "ref": "probe.sh"}, root,
                            ACQUIRED_AT, environment=bad)
                    self.assertEqual(caught.exception.code, "evidence_adapter_config_invalid")

    def test_the_timeout_bounds_are_the_declared_ones(self):
        with _Tree(self._script("printf '\"passed\"'\n")) as root:
            declaration = {"id": "tests", "source": "exec", "ref": "probe.sh"}
            for bad in (0, -1, 301, 3600, 1.0, True, "30", None):
                with self.subTest(timeout=bad):
                    with self.assertRaises(VerifyError) as caught:
                        evidence.acquire_command(declaration, root, ACQUIRED_AT,
                                                 timeout_seconds=bad)
                    self.assertEqual(caught.exception.code, "evidence_adapter_config_invalid")
            for good in (1, 300):
                self.assertEqual(
                    evidence.acquire_command(declaration, root, ACQUIRED_AT,
                                             timeout_seconds=good).status, "ok")

    def test_a_child_that_outlives_its_timeout_is_terminated(self):
        with _Tree(self._script("/bin/sleep 60\n")) as root:
            result = evidence.acquire_command({"id": "tests", "source": "exec", "ref": "probe.sh"},
                                              root, ACQUIRED_AT, timeout_seconds=1)
            self.assertEqual(result.status, "error")
            remaining = subprocess.run(["/bin/ps", "-o", "command="], capture_output=True)
            self.assertNotIn(str(root).encode("utf-8"), remaining.stdout)

    def test_a_command_writing_only_to_stderr_does_not_deadlock(self):
        with _Tree(self._script(
                "i=0\nwhile [ $i -lt 512 ]; do printf '%s' '" + "e" * 1024
                + "' >&2; i=$((i+1)); done\nprintf '\"passed\"'\n")) as root:
            result = evidence.acquire_command({"id": "tests", "source": "exec", "ref": "probe.sh"},
                                              root, ACQUIRED_AT, timeout_seconds=30)
            self.assertEqual(result.value(), "passed")

    def test_stdin_is_never_the_parent_stdin(self):
        with _Tree(self._script(
                "if read line; then printf '\"read\"'; else printf '\"eof\"'; fi\n")) as root:
            result = evidence.acquire_command({"id": "tests", "source": "exec", "ref": "probe.sh"},
                                              root, ACQUIRED_AT, timeout_seconds=5)
            self.assertEqual(result.value(), "eof")


class SubstitutionWindow(unittest.TestCase):
    """What the check-then-open window does and does not close."""

    def test_a_symlink_at_the_leaf_is_refused_by_the_open_itself(self):
        with _Tree({"real.json": {"kind": "file",
                                  "bytes_base64": base64.b64encode(b'{"x":1}').decode()}}) as root:
            path = root / "a.json"
            path.write_bytes(b'{"x":1}')
            declaration = {"id": "docs_complete", "source": "file", "ref": "a.json"}
            self.assertEqual(evidence.acquire_file(declaration, root, ACQUIRED_AT).status, "ok")
            # Substitute a symlink after the check the adapter already made, then read again.
            path.unlink()
            path.symlink_to(root / "real.json")
            with self.assertRaises(VerifyError) as caught:
                evidence.acquire_file(declaration, root, ACQUIRED_AT)
            self.assertEqual(caught.exception.code, "evidence_path_invalid")
            # And with the pre-open check bypassed entirely, the open still refuses to follow it.
            self.assertEqual(
                file_adapter._OPEN_FLAGS & os.O_NOFOLLOW, os.O_NOFOLLOW)
            with self.assertRaises(OSError):
                os.close(os.open(path, file_adapter._OPEN_FLAGS))

    def test_a_named_pipe_never_blocks_the_open(self):
        with _Tree({"a.json": {"kind": "fifo"}}) as root:
            # A fifo is refused before the open; were it substituted afterwards, O_NONBLOCK keeps
            # the open from waiting for a writer that never comes.
            with self.assertRaises(VerifyError):
                evidence.acquire_file({"id": "docs_complete", "source": "file", "ref": "a.json"},
                                      root, ACQUIRED_AT)
            descriptor = os.open(root / "a.json", file_adapter._OPEN_FLAGS)
            try:
                self.assertFalse(stat.S_ISREG(os.fstat(descriptor).st_mode))
            finally:
                os.close(descriptor)


class Purity(unittest.TestCase):
    """The adapters are effectful by design; the effect is bounded to what the spec declares.

    Every check below runs against *code*, with comments and string literals stripped out. A
    scanner that reads prose would be satisfied by renaming a docstring, and would flag a spec
    reference for saying what the code must not do.
    """

    @staticmethod
    def _tokens(path):
        """Return (code text, identifier list) with comments and string literals removed."""
        pieces, names = [], []
        with tokenize.open(path) as handle:
            for token in tokenize.generate_tokens(handle.readline):
                if token.type in (tokenize.COMMENT, tokenize.STRING):
                    continue
                if token.type == tokenize.NAME:
                    names.append(token.string)
                pieces.append(token.string)
        return " ".join(pieces), names

    def _sources(self):
        return {p.name: self._tokens(p)[0] for p in sorted(EVIDENCE_DIR.glob("*.py"))}

    def _names(self):
        return {p.name: self._tokens(p)[1] for p in sorted(EVIDENCE_DIR.glob("*.py"))}

    def test_no_adapter_constructs_a_timestamp(self):
        for name, text in self._sources().items():
            for token in ("datetime", "time.time", "time.gmtime", "st_mtime", "utcnow",
                          "time.localtime", "time.time_ns", "st_ctime"):
                self.assertNotIn(token, text, name)

    def test_no_adapter_draws_randomness_or_opens_a_socket(self):
        for name, text in self._sources().items():
            for token in ("random", "secrets", "socket", "urllib", "http.client", "requests",
                          "ssl"):
                self.assertNotIn(token, text, name)

    def test_no_adapter_reads_an_environment_variable_or_infers_a_home(self):
        for name, text in self._sources().items():
            for token in ("os.environ", "getenv", "expanduser", "Path.home", "os.getcwd",
                          "expandvars", "environb"):
                self.assertNotIn(token, text, name)

    def test_no_adapter_evaluates_builds_a_snapshot_or_persists_anything(self):
        for name, text in self._sources().items():
            for token in ("build_snapshot", "evaluate", "authorization", "receipt", "store",
                          "write_bytes", "write_text", "mkdir", "unlink", "rename", "os.remove"):
                self.assertNotIn(token, text, name)


    def test_the_only_effects_are_one_read_and_one_child_process(self):
        names, sources = self._names(), self._sources()
        # `open` is counted as an identifier: the substring also sits inside `Popen`.
        self.assertEqual(names["file.py"].count("open"), 1)
        self.assertEqual(sources["file.py"].count("handle . read ("), 1)
        self.assertEqual(sources["command.py"].count("subprocess . Popen"), 1)
        for name, identifiers in names.items():
            if name != "file.py":
                self.assertNotIn("open", identifiers, name)
            if name != "command.py":
                self.assertNotIn("subprocess", identifiers, name)

    def test_no_shell_is_reachable_from_any_adapter(self):
        for name, text in self._sources().items():
            for token in ("shell = True", "os.system", "popen2", "shlex", "posix_spawn",
                          "execv", "pty"):
                self.assertNotIn(token, text, name)
        self.assertIn("shell = False", self._sources()["command.py"])
        # No interpreter path appears anywhere in the adapters, prose included. A fixture script
        # carries its own shebang; nothing here ever chooses an interpreter for a command.
        for path in sorted(EVIDENCE_DIR.glob("*.py")):
            raw = path.read_text(encoding="utf-8")
            for interpreter in ("/bin/sh", "/bin/bash", "/usr/bin/env", "cmd.exe", "powershell"):
                self.assertNotIn(interpreter, raw, path.name)

    def test_the_same_bytes_produce_the_same_result_under_hostile_interpreter_settings(self):
        digests = set()
        for environment in ({"PYTHONHASHSEED": "0"}, {"PYTHONHASHSEED": "12345"},
                            {"PYTHONHASHSEED": "1", "LC_ALL": "tr_TR.UTF-8",
                             "TZ": "Pacific/Chatham"},
                            {"PYTHONHASHSEED": "2", "PYTHONUTF8": "0", "LANG": "C"}):
            child = dict(os.environ)
            child.update(environment)
            child["PYTHONPATH"] = str(REPO_ROOT)
            completed = subprocess.run(
                [sys.executable, "-c", _PROBE], env=child, capture_output=True,
                cwd=str(REPO_ROOT))
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
            digests.add(completed.stdout.strip())
        self.assertEqual(len(digests), 1, digests)


_PROBE = """
import base64, json, pathlib, tempfile, sys
from vfy import canon, evidence
root = pathlib.Path(tempfile.mkdtemp())
(root / "a.json").write_bytes(b'{"b":[1,2,{"z":"\\u00e9"}],"a":true}')
script = root / "p.sh"
script.write_text('#!/bin/sh\\nprintf \\'{"k":"v"}\\'\\n')
script.chmod(0o755)
one = evidence.acquire_file({"id": "docs_complete", "source": "file", "ref": "a.json"},
                            root, "2026-08-04T12:00:00Z")
two = evidence.acquire_command({"id": "tests", "source": "exec", "ref": "p.sh"},
                               root, "2026-08-04T12:00:00Z", timeout_seconds=5)
print(canon.hex_digest_of_text(canon.canonicalize(
    [one.as_acquisition(), two.as_acquisition()])))
"""


class Vocabulary(unittest.TestCase):
    BANNED = ("PAS_s", "PAS_h", "TEMPOLOCK", "CHORDLOCK", "GLYPHLOCK", "AURA", "resonance",
              "coherence", "regime", "corridor", "entitlement", "constitution", "forcing",
              "admissibility", "lockgraph", "ELF", "glyph", "ric-core-2")

    def test_no_banned_vocabulary_in_this_unit(self):
        # This file is not scanned: it is the scanner, and the words it looks for are written out
        # here in full. The repo-wide grep excludes it for the same reason.
        paths = (list(EVIDENCE_DIR.glob("*.py")) + list(ADAPTER_DIR.glob("*.json"))
                 + [REPO_ROOT / "spec" / "evidence-adapters.md"])
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for word in self.BANNED:
                with self.subTest(path=path.name, word=word):
                    self.assertNotIn(word, text)
            for word in ("phase", "kernel"):
                with self.subTest(path=path.name, word=word):
                    self.assertNotIn(word, text.lower())

    def test_no_legacy_import(self):
        for path in EVIDENCE_DIR.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("ric_core", text)
            self.assertNotIn("ric-core", text)


if __name__ == "__main__":
    unittest.main()
