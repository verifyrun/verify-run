"""Closure Unit 13 — the public local CLI and the complete developer workflow."""

import base64
import io
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

from vfy import canon, cli, load, workflow
from vfy import store as store_module
from vfy.errors import VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CLI_DIR = REPO_ROOT / "fixtures" / "cli"
TEMPLATE_DIR = REPO_ROOT / "templates"

AT = "2026-08-05T12:00:00Z"
SEEDS = (bytes(range(1, 33)), bytes(range(33, 65)), bytes(range(65, 97)), bytes(range(97, 129)))


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


def _identifiers(count=8):
    return workflow.FixedIdentifiers(
        nonces=["n-%032d" % i for i in range(count)],
        receipt_ids=["r-%024d" % i for i in range(count)],
        seeds=list(SEEDS))


class Cli:
    """One invocation with a fixed clock, fixed identifiers, and captured streams."""

    def __init__(self, workspace):
        self.workspace = pathlib.Path(workspace)
        self.identifiers = _identifiers()

    def __call__(self, *argv, clock=AT, parent_environment=None):
        out, err = io.StringIO(), io.StringIO()
        restore = {}
        for name, value in (parent_environment or {}).items():
            restore[name] = os.environ.get(name)
            os.environ[name] = value
        try:
            code = cli.main(["--workspace", str(self.workspace)] + list(argv),
                            clock=workflow.FixedClock(clock), identifiers=self.identifiers,
                            out=out, err=err)
        finally:
            for name, value in restore.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        return code, out.getvalue(), err.getvalue()


class _Workspace:
    def __init__(self, tree=None, template=None, config_environment=None):
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="vfy-cli-"))
        self.root = self.base / "project"
        self.root.mkdir()
        if tree:
            _materialize(tree, self.root)
        self.cli = Cli(self.root)
        if template:
            code, _, err = self.cli("init", "--template", template)
            assert code == 0, err
            if config_environment is not None:
                self.set_config(execution_environment=config_environment)

    def set_config(self, **changes):
        path = self.root / ".vfy" / "config.json"
        value = load.load_json_bytes(path.read_bytes())
        if "execution_environment" in changes:
            value["execution"]["environment"] = changes.pop("execution_environment")
        value.update(changes)
        path.write_bytes(canon.canonical_bytes(value))

    def store(self):
        return store_module.LocalStore(self.root / ".vfy")

    def receipts(self):
        return sorted((self.root / ".vfy" / "receipts").glob("*.json"))

    def consumed(self):
        return sorted((self.root / ".vfy" / "consumed").glob("*.json"))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        shutil.rmtree(self.base, ignore_errors=True)
        return False


class FixtureCoverage(unittest.TestCase):
    def test_every_fixture_is_claimed(self):
        names = {p.stem for p in CLI_DIR.glob("*.json")}
        claimed = {n for n in names if n.startswith(
            ("parse_", "init_", "check_", "run_", "replay_", "receipts_", "exit_"))}
        self.assertEqual(names, claimed)
        self.assertGreaterEqual(len(names), 45)


class Parsing(unittest.TestCase):
    def test_parse_fixtures(self):
        paths = sorted(CLI_DIR.glob("parse_*.json"))
        self.assertGreaterEqual(len(paths), 8)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name), _Workspace() as workspace:
                code, _, _ = workspace.cli(*case["argv"])
                self.assertEqual(code, case["expected"]["exit"], path.name)

    def test_the_command_set_is_exactly_the_five(self):
        parser = cli.build_parser()
        commands = set()
        for action in parser._actions:
            if getattr(action, "choices", None) and hasattr(action.choices, "keys"):
                commands |= set(action.choices)
        self.assertEqual(commands, {"init", "check", "run", "replay", "receipts"})

    def test_help_renders_for_every_command(self):
        for argv in ([], ["init"], ["check"], ["run"], ["replay"], ["receipts"]):
            with self.subTest(argv=argv):
                parser = cli.build_parser()
                text = parser.format_help()
                self.assertIn("vfy", text)

    def test_importing_the_cli_reads_no_file_clock_or_environment(self):
        source = _code(REPO_ROOT / "vfy" / "cli.py")
        for token in ("time . time", "datetime", "os . environ [", "read_bytes ( )"):
            self.assertNotIn(token, source.split("def ")[0])


class Initialization(unittest.TestCase):
    def test_init_fixtures(self):
        for path in sorted(CLI_DIR.glob("init_accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name), _Workspace() as workspace:
                code, out, _ = workspace.cli("init", "--template", case["template"])
                expected = case["expected"]
                self.assertEqual(code, expected["exit"], path.name)
                present = sorted(str(p.relative_to(workspace.root))
                                 for p in workspace.root.rglob("*"))
                self.assertEqual(present, expected["paths"], path.name)
                for key in ("authorization.key", "receipt.key"):
                    mode = (workspace.root / ".vfy" / "keys" / key).stat().st_mode
                    self.assertEqual(stat.S_IMODE(mode), int(expected["key_mode"], 8), key)
                config = load.load_json_bytes(
                    (workspace.root / ".vfy" / "config.json").read_bytes())
                for name, value in expected["config"].items():
                    self.assertEqual(config[name], value, name)
                self.assertEqual((workspace.root / "rulebook.yaml").read_bytes(),
                                 (TEMPLATE_DIR / (case["template"] + ".yaml")).read_bytes())
                # The property is that no private byte is printed, not that a word is absent.
                for name in ("authorization.key", "receipt.key"):
                    seed = (workspace.root / ".vfy" / "keys" / name).read_bytes()
                    self.assertNotIn(seed.hex(), out, name)
                    self.assertNotIn(base64.b64encode(seed).decode("ascii"), out, name)

    def test_init_is_idempotent_only_on_identical_bytes(self):
        case = _case(CLI_DIR / "init_idempotent_on_identical_bytes.json")
        with _Workspace() as workspace:
            workspace.cli("init", "--template", case["template"])
            first = (workspace.root / ".vfy" / "keys" / "authorization.key").read_bytes()
            config = (workspace.root / ".vfy" / "config.json").read_bytes()
            workspace.identifiers = _identifiers()
            code, _, _ = workspace.cli("init", "--template", case["template"])
            self.assertEqual(code, case["expected"]["exit"])
            self.assertEqual((workspace.root / ".vfy" / "keys" / "authorization.key").read_bytes(),
                             first, "keys were regenerated over an existing workspace")
            self.assertEqual((workspace.root / ".vfy" / "config.json").read_bytes(), config)

    def test_init_refuses_to_overwrite_a_changed_rulebook(self):
        case = _case(CLI_DIR / "init_reject_changed_rulebook.json")
        with _Workspace() as workspace:
            workspace.cli("init", "--template", case["template"])
            (workspace.root / "rulebook.yaml").write_text("# edited by hand\n")
            workspace.identifiers = _identifiers()
            code, _, err = workspace.cli("init", "--template", case["template"])
            self.assertEqual(code, case["expected"]["exit"])
            self.assertIn(case["expected"]["reason_code"], err)
            self.assertEqual((workspace.root / "rulebook.yaml").read_text(), "# edited by hand\n")

    def test_init_refuses_a_symlinked_workspace(self):
        case = _case(CLI_DIR / "init_reject_symlinked_workspace.json")
        base = pathlib.Path(tempfile.mkdtemp(prefix="vfy-cli-link-"))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        (base / "real").mkdir()
        (base / "linked").symlink_to(base / "real")
        code, _, err = Cli(base / "linked")("init", "--template", case["template"])
        self.assertEqual(code, case["expected"]["exit"])
        self.assertIn(case["expected"]["reason_code"], err)

    def test_init_refuses_a_symlinked_vfy_directory(self):
        case = _case(CLI_DIR / "init_reject_symlinked_vfy.json")
        with _Workspace(tree=case["tree"]) as workspace:
            code, _, err = workspace.cli("init", "--template", case["template"])
            self.assertEqual(code, case["expected"]["exit"])
            self.assertIn(case["expected"]["reason_code"], err)

    def test_no_published_test_key_reaches_a_workspace(self):
        case = _case(CLI_DIR / "init_no_test_key_leakage.json")
        with _Workspace(template=case["template"]) as workspace:
            for path in (workspace.root / ".vfy" / "keys").iterdir():
                blob = path.read_bytes()
                for forbidden in case["forbidden_key_hex"]:
                    self.assertNotIn(bytes.fromhex(forbidden), blob, path.name)
                    self.assertNotIn(forbidden.encode("ascii"), blob, path.name)

    def test_generated_keys_are_distinct_and_never_printed(self):
        with _Workspace(template="pipeline-gate") as workspace:
            keys = workspace.root / ".vfy" / "keys"
            authorization = (keys / "authorization.key").read_bytes()
            receipt = (keys / "receipt.key").read_bytes()
            self.assertNotEqual(authorization, receipt)
            code, out, err = workspace.cli("receipts", "list")
            for blob in (authorization, receipt):
                self.assertNotIn(blob.hex(), out + err)


class Check(unittest.TestCase):
    def _run(self, path):
        case = _case(path)
        with _Workspace(tree=case.get("tree"), template=case["template"]) as workspace:
            candidate = workspace.root / "candidate.json"
            if "candidate_bytes_base64" in case:
                candidate.write_bytes(base64.b64decode(case["candidate_bytes_base64"]))
            else:
                candidate.write_bytes(canon.canonical_bytes(case["candidate"]))
            code, out, err = workspace.cli("check", str(candidate))
            expected = case["expected"]
            self.assertEqual(code, expected["exit"], path.name)
            self.assertIn(expected["outcome"], out, path.name)
            if "matched_rule" in expected:
                self.assertIn(expected["matched_rule"], out)
            if "note_contains" in expected:
                self.assertIn(expected["note_contains"], out)
            # check may never authorize, consume, launch, or write a receipt.
            self.assertEqual(len(workspace.receipts()), expected["receipts"], path.name)
            self.assertEqual(len(workspace.consumed()), expected["consumed"], path.name)
            self.assertIn("preview only", out)

    def test_check_fixtures(self):
        paths = sorted(CLI_DIR.glob("check_*.json"))
        self.assertGreaterEqual(len(paths), 6)
        for path in paths:
            with self.subTest(fixture=path.name):
                self._run(path)

    def test_check_never_starts_a_process(self):
        case = _case(CLI_DIR / "check_allow_preview.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            candidate = workspace.root / "candidate.json"
            candidate.write_bytes(canon.canonical_bytes(case["candidate"]))
            launched = []
            real_popen = subprocess.Popen

            def watched(*a, **k):
                # An evidence command is a legitimate acquisition; a gated action is not.
                launched.append(a[0])
                return real_popen(*a, **k)

            subprocess.Popen = watched
            try:
                workspace.cli("check", str(candidate))
            finally:
                subprocess.Popen = real_popen
            for argv in launched:
                self.assertNotIn("ok.sh", " ".join(argv),
                                 "check started the candidate's command")


class Run(unittest.TestCase):
    def _run(self, path):
        case = _case(path)
        with _Workspace(tree=case["tree"], template=case["template"],
                        config_environment=case.get("config_environment")) as workspace:
            code, out, err = workspace.cli(
                "run", *sum((["--identity", pair] for pair in case["identity"]), []),
                "--", *case["argv"], parent_environment=case.get("parent_environment"))
            expected = case["expected"]
            self.assertEqual(code, expected["exit"], path.name + " :: " + out + err)
            if "reason_code" in expected:
                self.assertIn(expected["reason_code"], err, path.name)
            if "outcome" in expected:
                self.assertIn(expected["outcome"], out, path.name)
            if "note_contains" in expected:
                self.assertIn(expected["note_contains"], out, path.name)
            self.assertEqual(len(workspace.receipts()), expected["receipts"], path.name)
            self.assertEqual(len(workspace.consumed()), expected["consumed"], path.name)
            if expected.get("replays"):
                receipt = workspace.receipts()[0]
                replay_code, replay_out, _ = workspace.cli("replay", str(receipt))
                self.assertIn(expected["outcome"], replay_out, path.name)
            return workspace, out, err

    def test_run_fixtures(self):
        paths = sorted(CLI_DIR.glob("run_*.json"))
        self.assertGreaterEqual(len(paths), 12)
        for path in paths:
            with self.subTest(fixture=path.name):
                self._run(path)

    def test_stdout_of_the_gated_command_is_not_rendered_by_the_cli(self):
        case = _case(CLI_DIR / "run_literal_metacharacters.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            code, out, err = workspace.cli(
                "run", "--identity", "branch=main", "--", *case["argv"])
            self.assertEqual(code, 0)
            # The CLI reports the decision, not the command's bytes.
            self.assertNotIn("[a; rm -rf /]", out)
            self.assertNotIn("[a; rm -rf /]", err)

    def test_the_recorded_argv_is_exactly_what_was_given(self):
        case = _case(CLI_DIR / "run_literal_metacharacters.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--identity", "branch=main", "--", *case["argv"])
            record = load.load_json_bytes(
                (workspace.receipts()[0].with_suffix("") .parent
                 / (workspace.receipts()[0].stem + ".inputs") / "candidate.json").read_bytes())
            self.assertEqual(record["action"]["argv"][1:], case["argv"][1:])

    def test_a_bare_name_is_resolved_into_the_candidate_before_it_is_hashed(self):
        case = _case(CLI_DIR / "run_bare_name_resolved_before_hashing.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--identity", "branch=main", "--", "ok.sh")
            receipt = workspace.receipts()[0]
            candidate = load.load_json_bytes(
                (receipt.parent / (receipt.stem + ".inputs") / "candidate.json").read_bytes())
            self.assertTrue(candidate["action"]["argv"][0].endswith("bin/ok.sh"),
                            candidate["action"]["argv"][0])
            self.assertNotEqual(candidate["action"]["argv"][0], "ok.sh")

    def test_one_authorization_is_consumed_once(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            self.assertEqual(len(workspace.consumed()), 1)
            workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            self.assertEqual(len(workspace.consumed()), 2, "each run gets its own authorization")
            self.assertEqual(len(workspace.receipts()), 2)

    def test_json_output_is_canonical_and_carries_no_secret(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            code, out, err = workspace.cli(
                "--json", "run", "--identity", "branch=main", "--", "bin/ok.sh")
            self.assertEqual(code, 0)
            body = load.load_json_bytes(out.strip().encode("utf-8"))
            self.assertEqual(canon.canonicalize(body), out.strip())
            self.assertEqual(set(body), {"command", "outcome", "matched_rule", "reasons",
                                         "receipt_id", "receipt_path", "executed",
                                         "exit_status", "notes"})
            keys = workspace.root / ".vfy" / "keys"
            for name in ("authorization.key", "receipt.key"):
                self.assertNotIn((keys / name).read_bytes().hex(), out + err)


class Replay(unittest.TestCase):
    def _decide(self, case):
        workspace = _Workspace(tree=case["tree"], template=case["template"])
        self.addCleanup(shutil.rmtree, workspace.base, ignore_errors=True)
        workspace.cli("run", *sum((["--identity", p] for p in case["identity"]), []),
                      "--", *case["argv"])
        return workspace

    def test_replay_accept_fixtures(self):
        for path in sorted(CLI_DIR.glob("replay_accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                workspace = self._decide(case)
                receipt = workspace.receipts()[0]
                launched = []
                real_popen = subprocess.Popen
                subprocess.Popen = lambda *a, **k: (launched.append(a[0]),
                                                    real_popen(*a, **k))[1]
                try:
                    code, out, err = workspace.cli("replay", str(receipt))
                finally:
                    subprocess.Popen = real_popen
                expected = case["expected"]
                self.assertEqual(code, expected["exit"], path.name)
                self.assertIn(expected["outcome"], out)
                self.assertIn("signature verified", out)
                self.assertEqual(launched, [], "replay started a process")

    def test_replay_reject_fixtures(self):
        for path in sorted(CLI_DIR.glob("replay_reject_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                workspace = self._decide(case)
                receipt = workspace.receipts()[0]
                mutation = case["mutation"]
                target = str(receipt)
                if "path" in mutation:
                    target = str(workspace.root / mutation["path"])
                if mutation.get("delete_inputs"):
                    shutil.rmtree(receipt.parent / (receipt.stem + ".inputs"))
                if "corrupt_body" in mutation:
                    body = (receipt.parent / (receipt.stem + ".inputs")
                            / (mutation["corrupt_body"] + ".json"))
                    body.write_bytes(b'{ "not": "canonical" }')
                if "trust_key_id" in mutation or "trust_status" in mutation:
                    path_ = workspace.root / ".vfy" / "keys" / "trust.json"
                    trust = load.load_json_bytes(path_.read_bytes())
                    for entry in trust["receipt"]:
                        if "trust_key_id" in mutation:
                            entry["key_id"] = mutation["trust_key_id"]
                        if "trust_status" in mutation:
                            entry["status"] = mutation["trust_status"]
                    path_.write_bytes(canon.canonical_bytes(trust))

                code, out, err = workspace.cli("replay", target)
                expected_code = case["expected"]["reason_code"]
                if expected_code is None:
                    # A retired receipt key still verifies what it signed.
                    self.assertEqual(code, 0, out + err)
                else:
                    self.assertNotEqual(code, 0, path.name)
                    self.assertIn(expected_code, err, path.name)


class Receipts(unittest.TestCase):
    def _prepare(self, case):
        workspace = _Workspace(tree=case["tree"], template=case["template"])
        self.addCleanup(shutil.rmtree, workspace.base, ignore_errors=True)
        for identity in case["runs"]:
            workspace.cli("run", *sum((["--identity", p] for p in identity), []),
                          "--", "bin/ok.sh")
        return workspace

    def test_receipts_fixtures(self):
        for path in sorted(CLI_DIR.glob("receipts_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                workspace = self._prepare(case)
                mutation = case.get("mutation", {})
                index = workspace.root / ".vfy" / "index.json"
                if "truncate_index" in mutation:
                    value = load.load_json_bytes(index.read_bytes())
                    value["receipts"] = value["receipts"][:mutation["truncate_index"]]
                    index.write_bytes(canon.canonical_bytes(value))
                if mutation.get("ghost_index_entry"):
                    value = load.load_json_bytes(index.read_bytes())
                    value["receipts"].append(dict(value["receipts"][0], receipt_id="ghost"))
                    index.write_bytes(canon.canonical_bytes(value))

                code, out, err = workspace.cli("--json", "receipts", "list")
                expected = case["expected"]
                self.assertEqual(code, expected["exit"], path.name)
                body = load.load_json_bytes(out.strip().encode("utf-8"))
                self.assertEqual(len(body["receipts"]), expected["count"], path.name)
                if "outcomes" in expected:
                    self.assertEqual(sorted(r["outcome"] for r in body["receipts"]),
                                     sorted(expected["outcomes"]), path.name)
                for summary in body["receipts"]:
                    self.assertTrue(
                        (workspace.root / ".vfy" / "receipts"
                         / (summary["receipt_id"] + ".json")).is_file(),
                        "listed a receipt with no committed record")
                if "text_contains" in expected:
                    _, text, _ = workspace.cli("receipts", "list")
                    self.assertIn(expected["text_contains"], text)

    def test_show_verifies_and_replays_one_record(self):
        case = _case(CLI_DIR / "receipts_several_outcomes_in_order.json")
        workspace = self._prepare(case)
        receipt_id = workspace.receipts()[0].stem
        code, out, _ = workspace.cli("receipts", "show", receipt_id)
        self.assertIn("verified and replayed", out)
        self.assertIn(receipt_id, out)


class ExitCodes(unittest.TestCase):
    def test_the_frozen_exit_code_table(self):
        codes = _case(CLI_DIR / "exit_codes.json")["codes"]
        self.assertEqual(sorted(codes.values()), [0, 1, 2, 10, 11, 12, 13, 14])
        self.assertEqual(cli.EXIT_OK, 0)
        self.assertEqual(cli.EXIT_OPERATIONAL, 1)
        self.assertEqual(cli.EXIT_USAGE, 2)
        self.assertEqual(cli.EXIT_BLOCK, 10)
        self.assertEqual(cli.EXIT_HOLD, 11)
        self.assertEqual(cli.EXIT_ERROR, 12)
        self.assertEqual(cli.EXIT_EXECUTION_FAILED, 13)
        self.assertEqual(cli.EXIT_RECORDING_FAILED, 14)

    def test_the_four_outcomes_stay_distinguishable(self):
        self.assertEqual(len(set(cli._DECISION_EXIT.values())), 4)

    def test_a_recording_failure_is_its_own_code(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            real_put = store_module.LocalStore.put_record
            store_module.LocalStore.put_record = lambda *a, **k: (_ for _ in ()).throw(
                OSError("the disk is gone"))
            try:
                code, out, err = workspace.cli(
                    "run", "--identity", "branch=main", "--", "bin/ok.sh")
            finally:
                store_module.LocalStore.put_record = real_put
            self.assertEqual(code, cli.EXIT_RECORDING_FAILED)
            self.assertIn("consumed", err)
            self.assertEqual(len(workspace.consumed()), 1)


class Configuration(unittest.TestCase):
    def _broken(self, mutate):
        with _Workspace(template="pipeline-gate") as workspace:
            path = workspace.root / ".vfy" / "config.json"
            value = load.load_json_bytes(path.read_bytes())
            mutate(value)
            path.write_bytes(canon.canonical_bytes(value))
            return workspace.cli("receipts", "list")

    def test_an_unknown_field_is_refused_not_ignored(self):
        code, _, err = self._broken(lambda v: v.update({"telemetry": "on"}))
        self.assertEqual(code, cli.EXIT_OPERATIONAL)
        self.assertIn("cli_config_invalid", err)
        self.assertIn("telemetry", err)

    def test_a_nested_unknown_field_is_refused(self):
        code, _, err = self._broken(lambda v: v["execution"].update({"sandbox": True}))
        self.assertEqual(code, cli.EXIT_OPERATIONAL)
        self.assertIn("cli_config_invalid", err)

    def test_bounds_and_traversal_are_enforced(self):
        for mutate in (
                lambda v: v["execution"].update({"timeout_seconds": 0}),
                lambda v: v["execution"].update({"timeout_seconds": 3601}),
                lambda v: v["evidence"].update({"command_timeout_seconds": 301}),
                lambda v: v.update({"rulebook": "../outside.yaml"}),
                lambda v: v.update({"rulebook": "/etc/passwd"}),
                lambda v: v["keys"].update({"trust": "../../trust.json"}),
                lambda v: v.update({"search_path": ["../bin"]}),
                lambda v: v.update({"runtime_id": "has spaces"}),
                lambda v: v.update({"config_version": 2}),
                lambda v: v.update({"template": "sensor-loop"}),
                lambda v: v["execution"].update({"environment": {"A": 1}}),
        ):
            with self.subTest(mutation=mutate):
                code, _, err = self._broken(mutate)
                self.assertEqual(code, cli.EXIT_OPERATIONAL)
                self.assertIn("cli_config_invalid", err)

    def test_a_missing_workspace_is_typed(self):
        base = pathlib.Path(tempfile.mkdtemp(prefix="vfy-cli-none-"))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        code, _, err = Cli(base)("receipts", "list")
        self.assertEqual(code, cli.EXIT_OPERATIONAL)
        self.assertIn("cli_workspace_invalid", err)

    def test_a_permissive_key_is_warned_about_not_ignored(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            (workspace.root / ".vfy" / "keys" / "receipt.key").chmod(0o644)
            code, _, err = workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            self.assertIn("readable beyond its owner", err)


class Determinism(unittest.TestCase):
    def test_the_same_inputs_produce_byte_identical_artifacts(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        digests = set()
        for _ in range(2):
            with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
                code, out, _ = workspace.cli(
                    "--json", "run", "--identity", "branch=main", "--", "bin/ok.sh")
                self.assertEqual(code, 0)
                receipt = workspace.receipts()[0]
                # The workspace path differs per run, so compare the artifacts, not the paths.
                digests.add((out, canon.hex_digest_of_text(
                    canon.canonicalize(load.load_json_bytes(receipt.read_bytes())))))
        self.assertEqual(len(digests), 1, "identical inputs produced different artifacts")

    def test_a_fixed_clock_reaches_every_recorded_instant(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh", clock=AT)
            receipt = load.load_json_bytes(workspace.receipts()[0].read_bytes())
            self.assertEqual(receipt["created_at"], AT)
            self.assertEqual(receipt["execution"]["acknowledged_at"], AT)
            snapshot = load.load_json_bytes(
                (workspace.receipts()[0].parent
                 / (workspace.receipts()[0].stem + ".inputs") / "snapshot.json").read_bytes())
            self.assertEqual(snapshot["frozen_at"], AT)

    def test_the_production_clock_is_utc_and_locale_free(self):
        instant = workflow.Clock().now_utc()
        self.assertRegex(instant, r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class Isolation(unittest.TestCase):
    def test_concurrent_cli_runs_share_one_store_safely(self):
        import concurrent.futures
        import threading

        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            start = threading.Barrier(6)

            def once(index):
                runner = Cli(workspace.root)
                runner.identifiers = workflow.FixedIdentifiers(
                    nonces=["n-concurrent-%026d" % index],
                    receipt_ids=["r-concurrent-%022d" % index])
                start.wait()
                return runner("run", "--identity", "branch=main", "--", "bin/ok.sh")[0]

            with concurrent.futures.ThreadPoolExecutor(6) as pool:
                codes = list(pool.map(once, range(6)))
            self.assertEqual(set(codes), {0}, "a concurrent run failed")
            self.assertEqual(len(workspace.receipts()), 6)
            self.assertEqual(len(workspace.consumed()), 6)
            self.assertEqual(len(workspace.store().list_receipts()), 6)

    def test_the_current_directory_never_decides_the_workspace(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            previous = os.getcwd()
            os.chdir(tempfile.gettempdir())
            try:
                code, out, _ = workspace.cli("run", "--identity", "branch=main", "--",
                                             "bin/ok.sh")
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0, out)


class ProductVocabulary(unittest.TestCase):
    BANNED_EXACT = ("PAS_s", "PAS_h", "TEMPOLOCK", "CHORDLOCK", "GLYPHLOCK", "AURA", "ELF")
    BANNED_ANYCASE = ("resonance", "coherence", "regime", "corridor", "entitlement",
                      "constitution", "forcing", "admissibility", "lockgraph", "glyph",
                      "phase", "kernel")

    def _surfaces(self):
        parser = cli.build_parser()
        text = [parser.format_help()]
        for action in parser._actions:
            if getattr(action, "choices", None) and hasattr(action.choices, "values"):
                text += [sub.format_help() for sub in action.choices.values()]
        return "\n".join(text)

    def test_help_and_generated_files_use_product_vocabulary_only(self):
        surfaces = [self._surfaces(),
                    (REPO_ROOT / "vfy" / "cli.py").read_text(encoding="utf-8"),
                    (REPO_ROOT / "vfy" / "workflow.py").read_text(encoding="utf-8"),
                    (REPO_ROOT / "spec" / "cli.md").read_text(encoding="utf-8")]
        with _Workspace(template="pipeline-gate") as workspace:
            surfaces.append((workspace.root / ".vfy" / "config.json").read_text())
            surfaces.append((workspace.root / "rulebook.yaml").read_text())
            for argv in (["receipts", "list"], ["run"], ["check", "nope.json"]):
                code, out, err = workspace.cli(*argv)
                surfaces.append(out + err)
        for text in surfaces:
            for word in self.BANNED_EXACT:
                self.assertNotIn(word, text)
            for word in self.BANNED_ANYCASE:
                self.assertNotIn(word, text.lower())

    def test_no_legacy_reference(self):
        for name in ("cli.py", "workflow.py"):
            text = (REPO_ROOT / "vfy" / name).read_text(encoding="utf-8")
            self.assertNotIn("ric_core", text)
            self.assertNotIn("ric-core", text)


def _code(path):
    pieces = []
    with tokenize.open(path) as handle:
        for token in tokenize.generate_tokens(handle.readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            pieces.append(token.string)
    return " ".join(pieces)


class LayerDiscipline(unittest.TestCase):
    def test_the_delivery_layer_duplicates_no_decision_semantics(self):
        for name in ("cli.py", "workflow.py"):
            text = _code(REPO_ROOT / "vfy" / name)
            for token in ("_walk", "_evaluate_node", "_rule_state", "Ed25519PublicKey",
                          "InvalidSignature", "hashlib . sha256 ( ) . update"):
                self.assertNotIn(token, text, name)

    def test_only_the_delivery_layer_holds_a_clock_or_randomness(self):
        for path in sorted((REPO_ROOT / "vfy").rglob("*.py")):
            relative = path.relative_to(REPO_ROOT)
            text = _code(path)
            if path.name in ("cli.py", "workflow.py"):
                continue
            for token in ("time . time", "time . gmtime", "datetime", "secrets", "random",
                          "uuid"):
                self.assertNotIn(token, text, str(relative))

    def test_no_layer_inherits_the_parent_environment_or_opens_a_socket(self):
        for path in sorted((REPO_ROOT / "vfy").rglob("*.py")):
            text = _code(path)
            for token in ("socket", "urllib", "requests", "shell = True", "os . system"):
                self.assertNotIn(token, text, path.name)
        # The CLI reads exactly one environment variable, and only to widen a traceback.
        cli_text = _code(REPO_ROOT / "vfy" / "cli.py")
        self.assertEqual(cli_text.count("os . environ"), 1)

    def test_the_runtime_is_reached_rather_than_reimplemented(self):
        text = _code(REPO_ROOT / "vfy" / "workflow.py")
        for expected in ("gate . evaluate", "snapshot_module . build_snapshot",
                         "auth_module . issue_authorization",
                         "runner . execute_authorized_command",
                         "receipt_module . issue_receipt", "store . put_record",
                         "get_record", "list_receipts"):
            self.assertIn(expected, text)


class EntryPoint(unittest.TestCase):
    def test_the_console_script_is_declared(self):
        text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[project.scripts]", text)
        self.assertIn('vfy = "vfy.cli:main"', text)

    def test_the_entry_point_runs_as_a_real_process(self):
        base = pathlib.Path(tempfile.mkdtemp(prefix="vfy-entry-"))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        completed = subprocess.run(
            [sys.executable, "-c",
             "import sys; from vfy.cli import main; sys.exit(main())",
             "--workspace", str(base), "init", "--template", "agent-guard"],
            capture_output=True, cwd=str(REPO_ROOT),
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT)})
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8"))
        self.assertTrue((base / "rulebook.yaml").is_file())
        self.assertTrue((base / ".vfy" / "store.json").is_file())


if __name__ == "__main__":
    unittest.main()


class StreamDiscipline(unittest.TestCase):
    """Diagnostics on stderr, the answer on stdout, and nothing escaping to the real streams."""

    def test_a_usage_error_reaches_the_supplied_stream_not_the_process_stderr(self):
        with _Workspace() as workspace:
            code, out, err = workspace.cli("frobnicate")
            self.assertEqual(code, cli.EXIT_USAGE)
            self.assertIn("invalid choice", err)
            self.assertEqual(out, "")

    def test_json_output_is_alone_on_stdout(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            code, out, err = workspace.cli(
                "--json", "run", "--identity", "branch=main", "--", "bin/ok.sh")
            self.assertEqual(code, 0)
            self.assertEqual(len(out.strip().splitlines()), 1, "stdout carried more than the object")
            load.load_json_bytes(out.strip().encode("utf-8"))

    def test_a_typed_failure_puts_its_line_on_stderr(self):
        base = pathlib.Path(tempfile.mkdtemp(prefix="vfy-cli-stream-"))
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        code, out, err = Cli(base)("receipts", "list")
        self.assertEqual(code, cli.EXIT_OPERATIONAL)
        self.assertIn("cli_workspace_invalid", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(out, "")


class HelpAndVersion(unittest.TestCase):
    """`--help` and `--version` succeed. They are not usage errors."""

    def test_help_exits_zero(self):
        with _Workspace() as workspace:
            code, out, _ = workspace.cli("--help")
            self.assertEqual(code, cli.EXIT_OK)
            self.assertIn("vfy", out)

    def test_version_exits_zero_and_reports_the_package_version(self):
        from vfy import __version__

        with _Workspace() as workspace:
            code, out, _ = workspace.cli("--version")
            self.assertEqual(code, cli.EXIT_OK)
            self.assertIn(__version__, out)

    def test_a_subcommand_help_exits_zero(self):
        with _Workspace() as workspace:
            for command in ("init", "check", "run", "replay", "receipts"):
                with self.subTest(command=command):
                    code, out, _ = workspace.cli(command, "--help")
                    self.assertEqual(code, cli.EXIT_OK)


class ReceiptsStayReplayableAsTimePasses(unittest.TestCase):
    """Replay is historical recomputation, not a question about present authority.

    spec/receipt-and-replay.md closed this hazard once already, for keys: "If retiring a key made
    its historical receipts unverifiable, replay would fail exactly when it matters most." An
    authorization's validity interval bounds when it may be *spent*. Replay spends nothing, so
    asking whether it is still spendable now would make every ALLOW receipt expire out of the
    guarantee `CLAUDE.md` states as done: "`vfy replay` on any emitted receipt verifies
    byte-identical."
    """

    LONG_AFTER = "2027-01-01T00:00:00Z"          # far past every template's ttl_seconds

    def _allow_workspace(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        workspace = _Workspace(tree=case["tree"], template=case["template"])
        code, out, err = workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
        assert code == 0, out + err
        return workspace

    def test_an_allow_receipt_replays_long_after_its_authorization_ttl(self):
        with self._allow_workspace() as workspace:
            receipt = workspace.receipts()[0]
            code, out, err = workspace.cli("replay", str(receipt), clock=self.LONG_AFTER)
            self.assertEqual(code, 0, err)
            self.assertIn("ALLOW", out)
            self.assertIn("recomputed and identical", out)

    def test_receipts_show_still_works_long_after_the_ttl(self):
        with self._allow_workspace() as workspace:
            receipt_id = workspace.receipts()[0].stem
            code, out, err = workspace.cli("receipts", "show", receipt_id,
                                           clock=self.LONG_AFTER)
            self.assertEqual(code, 0, err)
            self.assertIn("ALLOW", out)

    def test_the_recorded_authorization_is_still_cross_checked(self):
        """Dropping the expiry question must not drop the bindings with it."""
        with self._allow_workspace() as workspace:
            receipt = workspace.receipts()[0]
            inputs = receipt.parent / (receipt.stem + ".inputs")
            authorization = load.load_json_bytes((inputs / "authorization.json").read_bytes())
            authorization["action_digest"] = "sha256:" + "0" * 64
            (inputs / "authorization.json").write_bytes(canon.canonical_bytes(authorization))
            code, _, err = workspace.cli("replay", str(receipt), clock=self.LONG_AFTER)
            self.assertNotEqual(code, 0, "a mismatched authorization must still be refused")

    def test_a_block_receipt_was_never_affected(self):
        case = _case(CLI_DIR / "run_agent_guard_blocks_destructive.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--", *case["argv"])
            code, out, _ = workspace.cli("replay", str(workspace.receipts()[0]),
                                         clock=self.LONG_AFTER)
            self.assertEqual(code, 10)
            self.assertIn("BLOCK", out)


class CorruptHistoryDoesNotFailALaterRun(unittest.TestCase):
    """One unreadable historical receipt is a cache problem, not this run's problem.

    docs/security.md: the index "can never make a committed record look absent". The run below
    executes, consumes its nonce, and commits a complete record; reporting that as a recording
    failure would tell an operator to go looking for a receipt that is already on disk.
    """

    def _corrupt(self, path):
        path.write_bytes(b'{"receipt_id": "r-0",   "not": "canonical"}')

    def test_a_later_run_succeeds_and_commits_its_record(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            self._corrupt(workspace.receipts()[0])

            code, out, err = workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            self.assertEqual(code, 0, out + err)
            self.assertNotIn("could not be written", err)
            self.assertEqual(len(workspace.receipts()), 2)

            fresh = [p for p in workspace.receipts() if b"not" not in p.read_bytes()]
            self.assertEqual(len(fresh), 1)
            replay_code, replay_out, _ = workspace.cli("replay", str(fresh[0]))
            self.assertEqual(replay_code, 0)
            self.assertIn("recomputed and identical", replay_out)

    def test_the_listing_still_refuses_visibly(self):
        """Tolerating the cache failure must not turn into serving the corrupt record.

        A listing answers from the index while it names exactly the committed set — corrupting a
        record's bytes out of band does not change which names are committed, and the store still
        refuses to hand those bytes to anyone. Once a second record makes the cache disagree, the
        records govern, and the unreadable one is named rather than skipped.
        """
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            self._corrupt(workspace.receipts()[0])
            workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            code, _, err = workspace.cli("receipts", "list")
            self.assertEqual(code, 1)
            self.assertIn("store_artifact_noncanonical", err)

    def test_the_corrupt_record_is_never_served(self):
        case = _case(CLI_DIR / "run_allow_exit_zero.json")
        with _Workspace(tree=case["tree"], template=case["template"]) as workspace:
            workspace.cli("run", "--identity", "branch=main", "--", "bin/ok.sh")
            corrupt = workspace.receipts()[0]
            self._corrupt(corrupt)
            code, _, err = workspace.cli("replay", str(corrupt))
            self.assertEqual(code, 1)
            self.assertIn("store_artifact_noncanonical", err)
            self.assertTrue(corrupt.exists(), "a corrupt artifact is never silently deleted")
