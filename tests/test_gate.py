"""Closure Unit 6 — pure evaluation, three-valued settlement, rule walk, four outcomes."""

import copy
import dataclasses
import itertools
import json
import pathlib
import sys
import time
import tokenize
import unittest

from vfy import canon, gate, load, rulebook, schema
from vfy.errors import VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
EVAL_DIR = REPO_ROOT / "fixtures" / "evaluation"
TEMPLATES = REPO_ROOT / "templates"

FROZEN_AT = "2026-08-05T00:00:00Z"
NANOS = 1000000000
ZERO_DIGEST = "sha256:" + "0" * 64


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _instant_text(age_seconds):
    """Render frozen_at minus age_seconds, by the inverse of the pinned civil-days algorithm."""
    total = (rulebook._instant(FROZEN_AT) - age_seconds * NANOS) // NANOS
    days, seconds = divmod(total, 86400)
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    day_of_era = z - era * 146097
    year_of_era = (day_of_era - day_of_era // 1460 + day_of_era // 36524
                   - day_of_era // 146096) // 365
    year = year_of_era + era * 400
    day_of_year = day_of_era - (365 * year_of_era + year_of_era // 4 - year_of_era // 100)
    month_position = (5 * day_of_year + 2) // 153
    day = day_of_year - (153 * month_position + 2) // 5 + 1
    month = month_position + 3 if month_position < 10 else month_position - 9
    year += month <= 2
    hour, rest = divmod(seconds, 3600)
    minute, second = divmod(rest, 60)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (year, month, day, hour, minute, second)


def _snapshot(items, digest, frozen_at=FROZEN_AT):
    built = []
    for order, item in enumerate(items):
        node = {"id": item["id"], "order": order, "status": item["status"],
                "acquired_at": item.get("acquired_at",
                                        _instant_text(item.get("age_seconds", 0)))}
        if "value" in item:
            node["value"] = item["value"]
        built.append(node)
    return {"snapshot_id": "s", "rulebook_digest": digest, "frozen_at": frozen_at,
            "items": built, "snapshot_digest": ZERO_DIGEST}


def _pin(value, registry):
    """Pin a rulebook given as a canonical value. Canonical JSON is valid input to the strict
    YAML loader, so this goes through the real pinning path rather than around it."""
    return rulebook.load_rulebook_bytes(canon.canonicalize(value).encode("utf-8"), registry)


def _probe_rulebook(case):
    return {"rulebook_id": "probe", "version": "1.0.0", "adopted_at": FROZEN_AT,
            "evidence": case["declare"],
            "rules": [{"id": "probe", "when": case["when"], "outcome": "ALLOW",
                       "reason": "expression was true"}],
            "default_outcome": "BLOCK"}


OUTCOME_OF = {"ALLOW": "true", "BLOCK": "false", "HOLD": "unsettled"}



def _executable_source(path):
    """Return a module's code with comments and string literals removed."""
    pieces = []
    with open(path, "rb") as handle:
        for token in tokenize.tokenize(handle.readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING, tokenize.NL, tokenize.NEWLINE):
                continue
            pieces.append(token.string)
    return " ".join(pieces)

class Probes(unittest.TestCase):
    """Each probe reports one expression's own value through the terminal outcome."""

    def _run(self, case, registry):
        pinned = _pin(_probe_rulebook(case), registry)
        snapshot = _snapshot(case["items"], pinned.digest)
        return gate.evaluate(pinned, case["candidate"], snapshot, registry)

    def _check_group(self, prefix, minimum):
        registry = _registry()
        paths = sorted(EVAL_DIR.glob("probe_%s*.json" % prefix))
        self.assertGreaterEqual(len(paths), minimum)
        for path in paths:
            case = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(fixture=path.name, when=case["when"]):
                result = self._run(case, registry)
                self.assertEqual(OUTCOME_OF[result.outcome], case["expected"])

    def test_three_valued_algebra(self):
        self._check_group("algebra_", 25)

    def test_path_resolution(self):
        self._check_group("path_", 15)

    def test_evidence_settlement(self):
        self._check_group("evidence_", 17)

    def test_freshness_boundaries(self):
        self._check_group("freshness_", 9)

    def test_numeric_comparison(self):
        self._check_group("numeric_", 19)

    def test_membership(self):
        self._check_group("membership_", 8)

    def test_pattern_matching(self):
        self._check_group("pattern_", 16)

    def test_every_probe_result_validates_against_the_outcome_schema(self):
        registry = _registry()
        for path in sorted(EVAL_DIR.glob("probe_*.json")):
            case = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(fixture=path.name):
                result = self._run(case, registry)
                self.assertIsNone(schema.validate(result.value(), gate.OUTCOME_SCHEMA_ID,
                                                  registry))


class RuleWalks(unittest.TestCase):
    def test_every_walk_fixture_matches_its_frozen_result(self):
        registry = _registry()
        paths = sorted(EVAL_DIR.glob("walk_*.json"))
        self.assertGreaterEqual(len(paths), 12)
        for path in paths:
            case = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(fixture=path.name):
                pinned = _pin(case["rulebook"], registry)
                snapshot = _snapshot(case["items"], pinned.digest)
                document = gate.evaluate(pinned, case["candidate"], snapshot, registry).value()
                expected = case["expected"]
                self.assertEqual(document["outcome"], expected["outcome"])
                self.assertEqual(document.get("matched_rule"), expected["matched_rule"])
                self.assertEqual([r["code"] for r in document["reasons"]], expected["codes"])
                self.assertEqual(document["trace"], expected["trace"])


class OriginalEvaluationFixtures(unittest.TestCase):
    """The four fixtures frozen before any code existed, unchanged."""

    def _build(self, case, registry):
        pinned = rulebook.load_rulebook_bytes(
            (REPO_ROOT / case["rulebook_ref"]).read_bytes(), registry)
        overrides = case.get("evidence_overrides", {})
        items = []
        for identifier in sorted(overrides):
            override = overrides[identifier]
            item = {"id": identifier, "status": override["status"],
                    "age_seconds": override.get("age_seconds", 0)}
            if "value" in override:
                item["value"] = override["value"]
            items.append(item)
        for declaration in pinned.value()["evidence"]:
            if declaration["id"] not in overrides and declaration.get("required", True):
                items.append({"id": declaration["id"], "status": "missing"})
        return pinned, _snapshot(items, pinned.digest)

    def test_all_four_original_fixtures_produce_their_declared_expectations(self):
        registry = _registry()
        paths = sorted(EVAL_DIR.glob("eval_*.json"))
        self.assertEqual(len(paths), 4)
        for path in paths:
            case = json.loads(path.read_text(encoding="utf-8"))
            expected = case["expected"]
            with self.subTest(fixture=path.name):
                pinned, snapshot = self._build(case, registry)
                document = gate.evaluate(pinned, case["candidate"], snapshot, registry).value()
                self.assertEqual(document["outcome"], expected["outcome"])
                if "matched_rule" in expected:
                    self.assertEqual(document["matched_rule"], expected["matched_rule"])
                if "reason_code" in expected:
                    self.assertIn(expected["reason_code"],
                                  [r["code"] for r in document["reasons"]])

    def test_the_hold_fixture_reaches_hold_through_absorbing_settlement(self):
        # true and false and unsettled -> unsettled. Short-circuit logic would say false.
        registry = _registry()
        case = json.loads((EVAL_DIR / "eval_hold.json").read_text(encoding="utf-8"))
        pinned, snapshot = self._build(case, registry)
        document = gate.evaluate(pinned, case["candidate"], snapshot, registry).value()
        self.assertEqual(document["outcome"], "HOLD")
        self.assertEqual(document["trace"], ["0:tests-green-on-main:unsettled"])
        self.assertNotIn("matched_rule", document)


class CurrentTemplates(unittest.TestCase):
    def _evaluate(self, template, candidate, items, registry):
        pinned = rulebook.load_rulebook_bytes((TEMPLATES / template).read_bytes(), registry)
        return gate.evaluate(pinned, candidate, _snapshot(items, pinned.digest),
                             registry).value()

    def test_agent_guard_blocks_a_destructive_command(self):
        document = self._evaluate("agent-guard.yaml",
                                  {"candidate_id": "c", "kind": "command",
                                   "action": {"summary": "rm", "argv": ["rm", "-rf", "/"]}},
                                  [], _registry())
        self.assertEqual(document["outcome"], "BLOCK")
        self.assertEqual(document["matched_rule"], "no-destructive-shell")

    def test_agent_guard_allows_a_workspace_write(self):
        document = self._evaluate("agent-guard.yaml",
                                  {"candidate_id": "c", "kind": "tool_call",
                                   "action": {"summary": "write", "tool": "write_file",
                                              "params": {"path": "./workspace/report.md"}}},
                                  [], _registry())
        self.assertEqual(document["outcome"], "ALLOW")
        self.assertEqual(document["matched_rule"], "write-inside-workspace")

    def test_agent_guard_holds_outbound_email_without_approval(self):
        document = self._evaluate("agent-guard.yaml",
                                  {"candidate_id": "c", "kind": "tool_call",
                                   "action": {"summary": "mail", "tool": "send_email"}},
                                  [], _registry())
        self.assertEqual(document["outcome"], "HOLD")
        self.assertEqual(document["matched_rule"], "outbound-email-needs-approval")

    def test_agent_guard_falls_through_to_its_default_for_a_benign_command(self):
        document = self._evaluate("agent-guard.yaml",
                                  {"candidate_id": "c", "kind": "command",
                                   "action": {"summary": "ls", "argv": ["ls"]}},
                                  [], _registry())
        self.assertEqual(document["outcome"], "HOLD")
        self.assertNotIn("matched_rule", document)
        self.assertEqual([r["code"] for r in document["reasons"]], ["default_outcome_hold"])

    def test_pipeline_gate_allows_green_tests_on_main(self):
        document = self._evaluate(
            "pipeline-gate.yaml",
            {"candidate_id": "c", "kind": "command",
             "action": {"summary": "deploy"}, "identity": {"branch": "main"}},
            [{"id": "tests", "status": "ok", "value": "passed", "age_seconds": 30}],
            _registry())
        self.assertEqual(document["outcome"], "ALLOW")

    def test_pipeline_gate_blocks_failed_tests(self):
        document = self._evaluate(
            "pipeline-gate.yaml",
            {"candidate_id": "c", "kind": "command",
             "action": {"summary": "deploy"}, "identity": {"branch": "main"}},
            [{"id": "tests", "status": "ok", "value": "failed", "age_seconds": 30}],
            _registry())
        self.assertEqual(document["outcome"], "BLOCK")
        self.assertEqual(document["matched_rule"], "tests-red")

    def test_pipeline_gate_blocks_a_wrong_branch(self):
        document = self._evaluate(
            "pipeline-gate.yaml",
            {"candidate_id": "c", "kind": "command",
             "action": {"summary": "deploy"}, "identity": {"branch": "feature"}},
            [{"id": "tests", "status": "ok", "value": "passed", "age_seconds": 30}],
            _registry())
        self.assertEqual(document["outcome"], "BLOCK")
        self.assertEqual(document["matched_rule"], "wrong-branch")

    def test_claims_gate_auto_approves_within_authority(self):
        document = self._evaluate(
            "claims-gate.yaml",
            {"candidate_id": "c", "kind": "custom",
             "action": {"summary": "settle", "params": {"amount": "100.00"}},
             "identity": {"claim_id": "k1", "adjuster_id": "a1"}},
            [{"id": "coverage", "status": "ok", "value": "covered", "age_seconds": 10},
             {"id": "docs_complete", "status": "ok", "value": True, "age_seconds": 10},
             {"id": "authority_limit", "status": "ok", "value": "500.00", "age_seconds": 10}],
            _registry())
        self.assertEqual(document["outcome"], "ALLOW")
        self.assertEqual(document["matched_rule"], "auto-approve-in-authority")

    def test_claims_gate_holds_over_authority(self):
        document = self._evaluate(
            "claims-gate.yaml",
            {"candidate_id": "c", "kind": "custom",
             "action": {"summary": "settle", "params": {"amount": "900.00"}},
             "identity": {"claim_id": "k1", "adjuster_id": "a1"}},
            [{"id": "coverage", "status": "ok", "value": "covered", "age_seconds": 10},
             {"id": "docs_complete", "status": "ok", "value": True, "age_seconds": 10},
             {"id": "authority_limit", "status": "ok", "value": "500.00", "age_seconds": 10}],
            _registry())
        self.assertEqual(document["outcome"], "HOLD")
        self.assertEqual(document["matched_rule"], "over-authority")

    def test_claims_gate_blocks_an_excluded_claim(self):
        document = self._evaluate(
            "claims-gate.yaml",
            {"candidate_id": "c", "kind": "custom",
             "action": {"summary": "settle", "params": {"amount": "100.00"}},
             "identity": {"claim_id": "k1", "adjuster_id": "a1"}},
            [{"id": "coverage", "status": "ok", "value": "excluded", "age_seconds": 10},
             {"id": "docs_complete", "status": "ok", "value": True, "age_seconds": 10},
             {"id": "authority_limit", "status": "ok", "value": "500.00", "age_seconds": 10}],
            _registry())
        self.assertEqual(document["outcome"], "BLOCK")
        self.assertEqual(document["matched_rule"], "coverage-denies")

    def test_claims_gate_holds_when_evidence_cannot_settle(self):
        document = self._evaluate(
            "claims-gate.yaml",
            {"candidate_id": "c", "kind": "custom",
             "action": {"summary": "settle", "params": {"amount": "100.00"}},
             "identity": {"claim_id": "k1", "adjuster_id": "a1"}},
            [{"id": "coverage", "status": "stale", "age_seconds": 99999},
             {"id": "docs_complete", "status": "missing"},
             {"id": "authority_limit", "status": "missing"}],
            _registry())
        self.assertEqual(document["outcome"], "HOLD")
        self.assertIn("evidence_unsettled", [r["code"] for r in document["reasons"]])


class TerminalSeparation(unittest.TestCase):
    def _minimal(self, registry, default="HOLD", when="present(t)", outcome="ALLOW"):
        value = {"rulebook_id": "sep", "version": "1.0.0", "adopted_at": FROZEN_AT,
                 "evidence": [{"id": "t", "source": "file"}],
                 "rules": [{"id": "r", "when": when, "outcome": outcome, "reason": "x"}],
                 "default_outcome": default}
        return _pin(value, registry)

    def test_the_four_terminals_are_structurally_distinct(self):
        registry = _registry()
        candidate = {"candidate_id": "c", "kind": "command", "action": {"summary": "s"}}
        allow = gate.evaluate(self._minimal(registry), candidate,
                              _snapshot([{"id": "t", "status": "ok", "value": "v"}],
                                        ZERO_DIGEST), registry)
        block = gate.evaluate(self._minimal(registry, outcome="BLOCK"), candidate,
                              _snapshot([{"id": "t", "status": "ok", "value": "v"}],
                                        ZERO_DIGEST), registry)
        hold = gate.evaluate(self._minimal(registry, when='evidence.t == "v"'), candidate,
                             _snapshot([{"id": "t", "status": "missing"}], ZERO_DIGEST),
                             registry)
        error = gate.evaluate(self._minimal(registry), {"kind": "command"},
                              _snapshot([], ZERO_DIGEST), registry)
        outcomes = [allow.outcome, block.outcome, hold.outcome, error.outcome]
        self.assertEqual(outcomes, ["ALLOW", "BLOCK", "HOLD", "ERROR"])
        self.assertEqual(len(set(outcomes)), 4)

    def test_malformed_input_cannot_become_hold(self):
        registry = _registry()
        candidate = {"kind": "command"}          # missing candidate_id and action
        result = gate.evaluate(self._minimal(registry), candidate,
                               _snapshot([], ZERO_DIGEST), registry)
        self.assertEqual(result.outcome, "ERROR")
        self.assertNotEqual(result.outcome, "HOLD")
        self.assertEqual([r["code"] for r in result.value()["reasons"]],
                         ["candidate_schema_invalid"])

    def test_absent_evidence_cannot_become_block_by_failed_coercion(self):
        registry = _registry()
        result = gate.evaluate(self._minimal(registry, default="BLOCK",
                                             when='evidence.t == "v"'),
                               {"candidate_id": "c", "kind": "command",
                                "action": {"summary": "s"}},
                               _snapshot([{"id": "t", "status": "missing"}], ZERO_DIGEST),
                               registry)
        self.assertEqual(result.outcome, "HOLD")
        self.assertNotEqual(result.outcome, "BLOCK")

    def test_a_settled_negative_rule_is_block_not_error(self):
        registry = _registry()
        result = gate.evaluate(self._minimal(registry, when="present(t)", outcome="BLOCK"),
                               {"candidate_id": "c", "kind": "command",
                                "action": {"summary": "s"}},
                               _snapshot([{"id": "t", "status": "ok", "value": "v"}],
                                         ZERO_DIGEST), registry)
        self.assertEqual(result.outcome, "BLOCK")

    def test_a_rulebook_not_yet_adopted_is_error_not_hold(self):
        registry = _registry()
        value = {"rulebook_id": "later", "version": "1.0.0",
                 "adopted_at": "2030-01-01T00:00:00Z",
                 "evidence": [], "rules": [{"id": "r", "when": 'candidate.kind == "command"',
                                            "outcome": "ALLOW", "reason": "x"}],
                 "default_outcome": "HOLD"}
        result = gate.evaluate(_pin(value, registry),
                               {"candidate_id": "c", "kind": "command",
                                "action": {"summary": "s"}},
                               _snapshot([], ZERO_DIGEST), registry)
        self.assertEqual(result.outcome, "ERROR")
        self.assertEqual([r["code"] for r in result.value()["reasons"]],
                         ["rulebook_not_adopted"])

    def test_evidence_acquired_after_the_freeze_is_error(self):
        registry = _registry()
        snapshot = _snapshot([{"id": "t", "status": "ok", "value": "v",
                               "acquired_at": "2026-08-06T00:00:00Z"}], ZERO_DIGEST)
        result = gate.evaluate(self._minimal(registry),
                               {"candidate_id": "c", "kind": "command",
                                "action": {"summary": "s"}}, snapshot, registry)
        self.assertEqual(result.outcome, "ERROR")
        self.assertEqual([r["code"] for r in result.value()["reasons"]],
                         ["evidence_order_invalid"])


class DeterminismAndImmutability(unittest.TestCase):
    def _case(self):
        registry = _registry()
        value = {"rulebook_id": "det", "version": "1.0.0", "adopted_at": FROZEN_AT,
                 "evidence": [{"id": "t", "source": "file", "max_age_seconds": 60}],
                 "rules": [{"id": "r", "when": 'fresh(t) and evidence.t == "v"',
                            "outcome": "ALLOW", "reason": "ok"}],
                 "default_outcome": "HOLD"}
        pinned = _pin(value, registry)
        candidate = {"candidate_id": "c", "kind": "command",
                     "action": {"summary": "s"}, "identity": {"branch": "main"}}
        snapshot = _snapshot([{"id": "t", "status": "ok", "value": "v", "age_seconds": 10}],
                             pinned.digest)
        return registry, pinned, candidate, snapshot

    def test_same_inputs_give_byte_identical_canonical_results(self):
        registry, pinned, candidate, snapshot = self._case()
        first = gate.evaluate(pinned, candidate, snapshot, registry)
        second = gate.evaluate(pinned, candidate, snapshot, registry)
        self.assertEqual(first.canonical, second.canonical)
        self.assertEqual(canon.digest(first.value()), canon.digest(second.value()))

    def test_insertion_order_of_inputs_does_not_change_the_result(self):
        registry, pinned, candidate, snapshot = self._case()
        expected = gate.evaluate(pinned, candidate, snapshot, registry).canonical
        for order in itertools.permutations(sorted(candidate)):
            shuffled = {key: candidate[key] for key in order}
            with self.subTest(order=order):
                self.assertEqual(
                    gate.evaluate(pinned, shuffled, snapshot, registry).canonical, expected)

    def test_timestamp_offsets_denoting_one_instant_agree(self):
        registry, pinned, candidate, _snap = self._case()
        first = _snapshot([{"id": "t", "status": "ok", "value": "v",
                            "acquired_at": "2026-08-04T23:59:50Z"}], pinned.digest)
        second = _snapshot([{"id": "t", "status": "ok", "value": "v",
                             "acquired_at": "2026-08-05T00:59:50+01:00"}], pinned.digest)
        self.assertEqual(gate.evaluate(pinned, candidate, first, registry).canonical,
                         gate.evaluate(pinned, candidate, second, registry).canonical)

    def test_no_input_is_mutated(self):
        registry, pinned, candidate, snapshot = self._case()
        before = (copy.deepcopy(candidate), copy.deepcopy(snapshot), pinned.digest,
                  copy.deepcopy(registry))
        gate.evaluate(pinned, candidate, snapshot, registry)
        self.assertEqual(candidate, before[0])
        self.assertEqual(snapshot, before[1])
        self.assertEqual(pinned.digest, before[2])
        self.assertEqual(registry, before[3])

    def test_the_result_is_immutable(self):
        registry, pinned, candidate, snapshot = self._case()
        result = gate.evaluate(pinned, candidate, snapshot, registry)
        self.assertTrue(dataclasses.is_dataclass(result))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.canonical = "tampered"
        borrowed = result.value()
        borrowed["outcome"] = "ALLOW"
        borrowed["reasons"].append({"code": "x", "message": "y"})
        self.assertNotEqual(result.value(), borrowed)
        self.assertIsNot(result.value(), result.value())

    def test_no_sentinel_escapes_into_the_result(self):
        registry = _registry()
        value = {"rulebook_id": "sent", "version": "1.0.0", "adopted_at": FROZEN_AT,
                 "evidence": [{"id": "t", "source": "file"}],
                 "rules": [{"id": "r", "when": 'candidate.absent == "x"', "outcome": "ALLOW",
                            "reason": "ok"}],
                 "default_outcome": "HOLD"}
        result = gate.evaluate(_pin(value, registry),
                               {"candidate_id": "c", "kind": "command",
                                "action": {"summary": "s"}},
                               _snapshot([{"id": "t", "status": "missing"}], ZERO_DIGEST),
                               registry)
        self.assertNotIn("ABSENT", result.canonical)
        self.assertNotIn("unsettled", result.canonical.replace('"unsettled"', ""))


class ExceptionContainment(unittest.TestCase):
    def test_no_raw_exception_crosses_for_declared_input_classes(self):
        registry = _registry()
        value = {"rulebook_id": "fuzz", "version": "1.0.0", "adopted_at": FROZEN_AT,
                 "evidence": [{"id": "t", "source": "file"}],
                 "rules": [{"id": "r", "when": 'evidence.t == candidate.action.summary',
                            "outcome": "ALLOW", "reason": "ok"}],
                 "default_outcome": "HOLD"}
        pinned = _pin(value, registry)
        shapes = [None, True, 5, "text", [], {}, {"a": 1}, {"nested": {"deep": [1, 2]}}]
        for candidate_action in shapes:
            for item_value in shapes:
                candidate = {"candidate_id": "c", "kind": "command",
                             "action": {"summary": "s", "params": {"x": candidate_action}}}
                snapshot = _snapshot([{"id": "t", "status": "ok", "value": item_value}],
                                     pinned.digest)
                with self.subTest(action=repr(candidate_action)[:20],
                                  item=repr(item_value)[:20]):
                    try:
                        result = gate.evaluate(pinned, candidate, snapshot, registry)
                        self.assertIn(result.outcome, ("ALLOW", "BLOCK", "HOLD", "ERROR"))
                    except VerifyError as typed:
                        self.assertEqual(typed.outcome, "ERROR")
                    except Exception as untyped:
                        self.fail("%s crossed the boundary" % type(untyped).__name__)

    def test_programmer_defects_raise_rather_than_becoming_an_outcome(self):
        registry = _registry()
        pinned = _pin({"rulebook_id": "def", "version": "1.0.0", "adopted_at": FROZEN_AT,
                       "evidence": [], "rules": [{"id": "r", "when": 'candidate.kind == "x"',
                                                  "outcome": "ALLOW", "reason": "y"}],
                       "default_outcome": "HOLD"}, registry)
        for candidate, snapshot in ((None, {}), ("text", {}), ({}, None), ({}, [])):
            with self.subTest(candidate=repr(candidate), snapshot=repr(snapshot)):
                with self.assertRaises(TypeError):
                    gate.evaluate(pinned, candidate, snapshot, registry)


class NoWallClockOrFloat(unittest.TestCase):
    def test_the_module_imports_no_clock_or_random_source(self):
        source = (REPO_ROOT / "vfy" / "gate.py").read_text(encoding="utf-8")
        for banned in ("import time", "import datetime", "import random", "import os",
                       "import socket", "from time", "from datetime", "from random",
                       "open(", "float("):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)

    def test_numeric_comparison_never_builds_a_float(self):
        for left, right, expected in ((1, 2, -1), (2, 1, 1), (1, 1, 0),
                                      ("0.1", "0.2", -1), ("-0", "0", 0), ("-0.0", "0", 0),
                                      ("12.50", "12.5", 0), (12, "12.5", -1),
                                      ("1" * 40, "1" * 40 + ".1", -1)):
            with self.subTest(left=left, right=right):
                self.assertEqual(gate._compare_numeric(left, right), expected)

    def test_non_numeric_operands_report_no_ordering(self):
        for left, right in ((True, 1), (1, True), ("high", 1), ("12.5.0", 1), (None, 1)):
            with self.subTest(left=left, right=right):
                self.assertIsNone(gate._compare_numeric(left, right))


if __name__ == "__main__":
    unittest.main()


class GlobMatchingIsBoundedWork(unittest.TestCase):
    """`matches` is reachable from candidate values an adversary controls.

    The matcher's result is fixed by spec/expression-language.md; only its cost is at issue here.
    A backtracking walk with no memo is exponential in the number of `*` segments, so a short
    operator-authored pattern and a short attacker-supplied value can stall the evaluator.
    """

    PATHOLOGICAL = (
        ("*a" * 8 + "ZZZ", "a" * 200),
        ("*" * 6 + "z", "a" * 400),
        ("*[ab]" * 8 + "c", "ab" * 100),
        ("*a" * 14 + "b", "a" * 28),
    )

    def test_pathological_pattern_and_value_pairs_complete_promptly(self):
        for pattern, text in self.PATHOLOGICAL:
            with self.subTest(pattern=pattern[:24], value_length=len(text)):
                started = time.perf_counter()
                self.assertFalse(gate._glob(pattern, text))
                # Six orders of magnitude of headroom: the unbounded walk does not finish at all.
                self.assertLess(time.perf_counter() - started, 5.0)

    def test_results_are_unchanged_for_every_declared_shape(self):
        """Exhaustive differential check that only cost changed, never an answer."""
        alphabet = "ab"
        patterns = ["", "*", "?", "a", "*a", "a*", "*a*", "??", "[ab]", "[!a]", "a?b",
                    "**", "*?*", "[a-b]", "*[ab]*", "a*b", "[]a]", "[", "*a*b*"]
        values = [""] + ["".join(p) for n in range(1, 5)
                         for p in itertools.product(alphabet, repeat=n)]
        expected = {
            (pattern, value): _reference_glob(pattern, value)
            for pattern in patterns for value in values}
        for (pattern, value), answer in expected.items():
            with self.subTest(pattern=pattern, value=value):
                self.assertEqual(gate._glob(pattern, value), answer)


def _reference_glob(pattern, text):
    """The released 0.1.0a1 matcher, kept verbatim as the semantic reference."""
    return _reference_from(pattern, 0, text, 0)


def _reference_from(pattern, p, text, t):
    while p < len(pattern):
        character = pattern[p]
        if character == "*":
            for skip in range(t, len(text) + 1):
                if _reference_from(pattern, p + 1, text, skip):
                    return True
            return False
        if t >= len(text):
            return False
        if character == "?":
            p += 1
            t += 1
            continue
        if character == "[":
            end = gate._class_end(pattern, p)
            if end is None:
                if text[t] != "[":
                    return False
                p += 1
                t += 1
                continue
            if not gate._in_class(pattern[p + 1:end], text[t]):
                return False
            p = end + 1
            t += 1
            continue
        if text[t] != character:
            return False
        p += 1
        t += 1
    return t == len(text)


class BoundedNumericOperands(unittest.TestCase):
    """A numeric operand an adversary composes may not reach the host's arithmetic limits.

    `_numeric_parts` converted operand text with `int(whole + fraction)`. CPython refuses that
    conversion past `sys.set_int_max_str_digits` — 4300 digits by default — so a candidate
    carrying a 6000-digit decimal raised a bare `ValueError` out of the evaluator, and the CLI
    answered untrusted input with `internal error: ValueError`. Two things were wrong at once: a
    runtime flag decided which candidates were admissible, and a defect message stood where a
    decision belongs.

    The bound is now declared here (`MAX_NUMERIC_DIGITS`) and is far below the host's, so the
    host's limit is unreachable. An operand past it cannot settle, which the rulebook already
    knows how to answer.
    """

    def _compare(self, left, right):
        return gate._compare_numeric(left, right)

    def test_an_operand_past_the_declared_bound_is_unsettled_not_a_crash(self):
        """The bound counts every significant digit, integer part included."""
        over = gate.MAX_NUMERIC_DIGITS + 1
        for digits in (over, over + 1, 6000, 100_000):
            with self.subTest(total_digits=digits):
                # "0." + fraction carries one integer digit, so the fraction is one short.
                self.assertIsNone(self._compare("0." + "1" * digits, 5))
                self.assertIsNone(self._compare(5, "0." + "1" * digits))
                self.assertIsNone(self._compare("1" * digits, 5))
                self.assertIsNone(self._compare("-" + "1" * digits, 5))

    def test_the_boundary_is_exact_and_counts_every_significant_digit(self):
        bound = gate.MAX_NUMERIC_DIGITS
        # "0." + fraction: one integer digit plus the fraction.
        self.assertIsNotNone(self._compare("0." + "1" * (bound - 1), 5))
        self.assertIsNone(self._compare("0." + "1" * bound, 5))
        # An integer part alone is counted the same way.
        self.assertIsNotNone(self._compare("1" * bound, 5))
        self.assertIsNone(self._compare("1" * (bound + 1), 5))

    def test_the_host_integer_limit_can_no_longer_decide_admissibility(self):
        """The decisive property: move the host's limit, and nothing about the answer changes."""
        original = sys.get_int_max_str_digits()
        try:
            for limit in (640, 4300, 100_000):
                sys.set_int_max_str_digits(limit)
                with self.subTest(int_max_str_digits=limit):
                    self.assertEqual(self._compare("0." + "1" * 1000, 5), -1)
                    self.assertEqual(self._compare("9" * 1000, 5), 1)
                    self.assertIsNone(self._compare("0." + "1" * 6000, 5))
        finally:
            sys.set_int_max_str_digits(original)

    def test_no_operand_makes_the_evaluator_raise(self):
        hostile = ["0." + "1" * 5000, "9" * 5000, "-" + "9" * 5000, "-0." + "0" * 4999 + "1",
                   "0." + "0" * 9999 + "1", "1" * 3000 + "." + "1" * 3000,
                   "0", "-0", "0.0", "-0.0", "", " 1", "1.", ".1", "1e5", "+1", "abc",
                   True, False, None, [], {}, 0, -1, 2 ** 53 - 1]
        for left in hostile:
            for right in hostile:
                with self.subTest(left=repr(left)[:24], right=repr(right)[:24]):
                    self._compare(left, right)   # must not raise; value is asserted elsewhere

    def test_ordinary_comparison_semantics_are_unchanged(self):
        cases = [("1", "2", -1), ("2", "1", 1), ("1", "1", 0), ("1.0", "1", 0),
                 ("1.00", "1.0", 0), ("0.1", "0.10", 0), ("-1", "1", -1), ("1", "-1", 1),
                 ("-2", "-1", -1), ("0", "-0", 0), ("0.0", "-0.0", 0),
                 ("0.999", "1", -1), ("1000", "999.9", 1), ("123.456", "123.4560", 0),
                 ("-0.1", "0", -1), (0, "0.0", 0), (5, "5", 0), (-5, "-5.000", 0)]
        for left, right, expected in cases:
            with self.subTest(left=left, right=right):
                self.assertEqual(self._compare(left, right), expected)

    def test_no_power_of_ten_is_materialized_for_a_scale_difference(self):
        """The old form built `10 ** (scale - other_scale)` from operand-controlled scale.

        Inspected as code rather than as text, because the comments here deliberately quote the
        construct they replaced and a plain grep matches its own explanation.
        """
        code = _executable_source(REPO_ROOT / "vfy" / "gate.py")
        self.assertNotIn("10 **", code, "a power of ten is still built in the evaluator")
        self.assertNotIn("int ( whole", code, "operand text is still converted to an integer")

    def test_equality_still_never_coerces_across_spellings(self):
        """`==` is canonical equality, not numeric order. Repairing `<` must not change that."""
        self.assertFalse(gate._equal("1.0", "1.00"))
        self.assertFalse(gate._equal("1", 1))
        self.assertEqual(self._compare("1.0", "1.00"), 0)
