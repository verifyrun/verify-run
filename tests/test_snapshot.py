"""Closure Unit 7 — evidence boundary, snapshot construction, and freeze semantics."""

import copy
import dataclasses
import itertools
import json
import pathlib
import unittest

import yaml

from vfy import canon, gate, load, rulebook, schema, snapshot
from vfy.errors import VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
SNAP_DIR = REPO_ROOT / "fixtures" / "snapshots"
EVAL_DIR = REPO_ROOT / "fixtures" / "evaluation"
TEMPLATES = REPO_ROOT / "templates"

FROZEN_AT = "2026-08-05T00:00:00Z"
NANOS = 1000000000


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _pin(value, registry):
    return rulebook.load_rulebook_bytes(canon.canonicalize(value).encode("utf-8"), registry)


def _case(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _instant_text(age_seconds):
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


class AcceptedConstruction(unittest.TestCase):
    def test_every_accepted_fixture_builds_its_frozen_payload_and_digest(self):
        registry = _registry()
        paths = sorted(SNAP_DIR.glob("accept_*.json"))
        self.assertGreaterEqual(len(paths), 13)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = _pin(case["rulebook"], registry)
                frozen = snapshot.build_snapshot(pinned, case["snapshot_id"],
                                                 case["frozen_at"], case["acquisitions"],
                                                 registry)
                expected = dict(case["payload"])
                expected["rulebook_digest"] = pinned.digest
                built = frozen.value()
                payload = {k: v for k, v in built.items() if k != "snapshot_digest"}
                self.assertEqual(payload, expected)
                self.assertEqual(frozen.digest, canon.digest(expected))
                self.assertEqual([i["id"] for i in built["items"]], case["order"])
                self.assertEqual([i["order"] for i in built["items"]],
                                 list(range(len(built["items"]))))

    def test_every_built_snapshot_validates_against_its_schema(self):
        registry = _registry()
        for path in sorted(SNAP_DIR.glob("accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = _pin(case["rulebook"], registry)
                frozen = snapshot.build_snapshot(pinned, case["snapshot_id"],
                                                 case["frozen_at"], case["acquisitions"],
                                                 registry)
                self.assertIsNone(schema.validate(frozen.value(),
                                                  snapshot.SNAPSHOT_SCHEMA_ID, registry))

    def test_explicit_null_is_a_value_and_absent_is_not(self):
        registry = _registry()
        case = _case(SNAP_DIR / "accept_explicit_null_is_a_value.json")
        pinned = _pin(case["rulebook"], registry)
        frozen = snapshot.build_snapshot(pinned, "s", FROZEN_AT, case["acquisitions"], registry)
        item = frozen.value()["items"][0]
        self.assertIn("value", item)
        self.assertIsNone(item["value"])
        self.assertIn('"value":null', frozen.canonical)


class RejectedConstruction(unittest.TestCase):
    def test_every_construction_reject_carries_its_code(self):
        registry = _registry()
        paths = sorted(SNAP_DIR.glob("reject_*.json"))
        self.assertGreaterEqual(len(paths), 15)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = _pin(case["rulebook"], registry)
                with self.assertRaises(VerifyError) as caught:
                    snapshot.build_snapshot(pinned, case["snapshot_id"], case["frozen_at"],
                                            case["acquisitions"], registry)
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                self.assertEqual(caught.exception.outcome, "ERROR")

    def test_no_rejected_fixture_declares_a_digest(self):
        for path in sorted(SNAP_DIR.glob("reject_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                self.assertNotIn("payload", case)
                self.assertNotIn("snapshot_digest", case)


class Verification(unittest.TestCase):
    def _prepare(self, case, registry):
        pinned = _pin(case["rulebook"], registry)
        value = dict(case["snapshot"])
        if value.get("rulebook_digest") == "PINNED":
            value["rulebook_digest"] = pinned.digest
        if "snapshot_digest" not in value:
            payload = {k: v for k, v in value.items() if k != "snapshot_digest"}
            value["snapshot_digest"] = canon.digest(payload)
        return pinned, value

    def test_every_verification_reject_carries_its_code(self):
        registry = _registry()
        paths = sorted(SNAP_DIR.glob("verify_reject_*.json"))
        self.assertGreaterEqual(len(paths), 10)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned, value = self._prepare(case, registry)
                with self.assertRaises(VerifyError) as caught:
                    snapshot.verify_snapshot_value(value, pinned, registry)
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])

    def test_a_built_snapshot_verifies(self):
        registry = _registry()
        for path in sorted(SNAP_DIR.glob("accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = _pin(case["rulebook"], registry)
                frozen = snapshot.build_snapshot(pinned, case["snapshot_id"],
                                                 case["frozen_at"], case["acquisitions"],
                                                 registry)
                verified = snapshot.verify_snapshot_value(frozen.value(), pinned, registry)
                self.assertEqual(verified.canonical, frozen.canonical)
                self.assertEqual(verified.digest, frozen.digest)

    def test_the_embedded_digest_is_never_trusted(self):
        registry = _registry()
        pinned = _pin(_case(SNAP_DIR / "accept_one_ok_item.json")["rulebook"], registry)
        frozen = snapshot.build_snapshot(
            pinned, "s", FROZEN_AT,
            [{"id": "a", "status": "ok", "acquired_at": FROZEN_AT, "value": "v"}], registry)
        tampered = frozen.value()
        tampered["items"][0]["value"] = "tampered"      # digest left untouched
        with self.assertRaises(VerifyError) as caught:
            snapshot.verify_snapshot_value(tampered, pinned, registry)
        self.assertEqual(caught.exception.code, "snapshot_digest_mismatch")


class OriginalEvaluationFixtures(unittest.TestCase):
    """The four fixtures frozen before any code existed, now through the real builder."""

    def test_all_four_pass_with_snapshots_the_builder_made(self):
        registry = _registry()
        paths = sorted(EVAL_DIR.glob("eval_*.json"))
        self.assertEqual(len(paths), 4)
        for path in paths:
            case = _case(path)
            expected = case["expected"]
            with self.subTest(fixture=path.name):
                pinned = rulebook.load_rulebook_bytes(
                    (REPO_ROOT / case["rulebook_ref"]).read_bytes(), registry)
                overrides = case.get("evidence_overrides", {})
                acquisitions = []
                for identifier in sorted(overrides):
                    override = overrides[identifier]
                    acquisition = {"id": identifier, "status": override["status"],
                                   "acquired_at": _instant_text(
                                       override.get("age_seconds", 0))}
                    if "value" in override:
                        acquisition["value"] = override["value"]
                    acquisitions.append(acquisition)
                frozen = snapshot.build_snapshot(pinned, "s-1", FROZEN_AT, acquisitions,
                                                 registry)
                document = gate.evaluate(pinned, case["candidate"], frozen.value(),
                                         registry).value()
                self.assertEqual(document["outcome"], expected["outcome"])
                if "matched_rule" in expected:
                    self.assertEqual(document["matched_rule"], expected["matched_rule"])
                if "reason_code" in expected:
                    self.assertIn(expected["reason_code"],
                                  [r["code"] for r in document["reasons"]])


class CurrentTemplates(unittest.TestCase):
    def _pinned(self, name, registry, loader=None):
        source = (TEMPLATES / name).read_bytes()
        if loader is None:
            return rulebook.load_rulebook_bytes(source, registry)
        value = load.load_yaml_bytes(source, _loader_class=loader)
        return _pin(value, registry)

    def test_every_template_builds_a_snapshot_and_evaluates(self):
        registry = _registry()
        cases = {
            "agent-guard.yaml": ([], {"candidate_id": "c", "kind": "command",
                                      "action": {"summary": "ls", "argv": ["ls"]}}, "HOLD"),
            "pipeline-gate.yaml": ([{"id": "tests", "status": "ok", "value": "passed",
                                     "acquired_at": _instant_text(30)}],
                                   {"candidate_id": "c", "kind": "command",
                                    "action": {"summary": "deploy"},
                                    "identity": {"branch": "main"}}, "ALLOW"),
            "claims-gate.yaml": ([{"id": "coverage", "status": "ok", "value": "covered",
                                   "acquired_at": _instant_text(10)},
                                  {"id": "docs_complete", "status": "ok", "value": True,
                                   "acquired_at": _instant_text(10)},
                                  {"id": "authority_limit", "status": "ok", "value": "500.00",
                                   "acquired_at": _instant_text(10)}],
                                  {"candidate_id": "c", "kind": "custom",
                                   "action": {"summary": "settle",
                                              "params": {"amount": "100.00"}},
                                   "identity": {"claim_id": "k", "adjuster_id": "a"}}, "ALLOW"),
        }
        for name, (acquisitions, candidate, expected) in cases.items():
            with self.subTest(template=name):
                pinned = self._pinned(name, registry)
                frozen = snapshot.build_snapshot(pinned, "s-1", FROZEN_AT, acquisitions,
                                                 registry)
                self.assertEqual(frozen.value()["rulebook_digest"], pinned.digest)
                document = gate.evaluate(pinned, candidate, frozen.value(), registry).value()
                self.assertEqual(document["outcome"], expected)

    def test_agent_guard_omits_its_optional_declaration_when_unacquired(self):
        registry = _registry()
        pinned = self._pinned("agent-guard.yaml", registry)
        frozen = snapshot.build_snapshot(pinned, "s", FROZEN_AT, [], registry)
        self.assertEqual(frozen.value()["items"], [])

    def test_pipeline_gate_synthesizes_its_required_declaration(self):
        registry = _registry()
        pinned = self._pinned("pipeline-gate.yaml", registry)
        frozen = snapshot.build_snapshot(pinned, "s", FROZEN_AT, [], registry)
        items = frozen.value()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "tests")
        self.assertEqual(items[0]["status"], "missing")
        self.assertNotIn("value", items[0])

    def test_templates_build_identically_under_both_yaml_parsers(self):
        registry = _registry()
        loaders = [yaml.SafeLoader]
        if getattr(yaml, "__with_libyaml__", False):
            loaders.append(yaml.CSafeLoader)
        for name in ("agent-guard.yaml", "pipeline-gate.yaml", "claims-gate.yaml"):
            digests = {snapshot.build_snapshot(self._pinned(name, registry, loader),
                                               "s", FROZEN_AT, [], registry).digest
                       for loader in loaders}
            with self.subTest(template=name):
                self.assertEqual(len(digests), 1)


class StatusEvaluationBridge(unittest.TestCase):
    def test_every_status_reaches_the_evaluator_unchanged(self):
        registry = _registry()
        paths = sorted(SNAP_DIR.glob("bridge_*.json"))
        self.assertGreaterEqual(len(paths), 16)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = _pin(case["rulebook"], registry)
                frozen = snapshot.build_snapshot(pinned, case["snapshot_id"],
                                                 case["frozen_at"], case["acquisitions"],
                                                 registry)
                result = gate.evaluate(pinned, case["candidate"], frozen.value(), registry)
                self.assertEqual(result.outcome, case["expected_outcome"])

    def test_a_stale_item_keeps_its_value_and_still_does_not_settle(self):
        registry = _registry()
        value = {"rulebook_id": "stale-probe", "version": "1.0.0", "adopted_at": FROZEN_AT,
                 "evidence": [{"id": "a", "source": "file"}],
                 "rules": [{"id": "r", "when": 'evidence.a == "old"', "outcome": "ALLOW",
                            "reason": "ok"}],
                 "default_outcome": "BLOCK"}
        pinned = _pin(value, registry)
        frozen = snapshot.build_snapshot(
            pinned, "s", FROZEN_AT,
            [{"id": "a", "status": "stale", "acquired_at": FROZEN_AT, "value": "old"}],
            registry)
        self.assertEqual(frozen.value()["items"][0]["value"], "old")
        result = gate.evaluate(pinned, {"candidate_id": "c", "kind": "command",
                                        "action": {"summary": "s"}}, frozen.value(), registry)
        self.assertEqual(result.outcome, "HOLD")

    def test_an_omitted_optional_and_a_missing_item_evaluate_alike(self):
        registry = _registry()
        value = {"rulebook_id": "two-ways", "version": "1.0.0", "adopted_at": FROZEN_AT,
                 "evidence": [{"id": "a", "source": "file", "required": False}],
                 "rules": [{"id": "r", "when": "not present(a)", "outcome": "ALLOW",
                            "reason": "ok"}],
                 "default_outcome": "BLOCK"}
        pinned = _pin(value, registry)
        candidate = {"candidate_id": "c", "kind": "command", "action": {"summary": "s"}}
        omitted = snapshot.build_snapshot(pinned, "s", FROZEN_AT, [], registry)
        recorded = snapshot.build_snapshot(
            pinned, "s", FROZEN_AT,
            [{"id": "a", "status": "missing", "acquired_at": FROZEN_AT}], registry)
        self.assertNotEqual(omitted.digest, recorded.digest)
        self.assertEqual(gate.evaluate(pinned, candidate, omitted.value(), registry).outcome,
                         gate.evaluate(pinned, candidate, recorded.value(), registry).outcome)


class OrderingAndFreeze(unittest.TestCase):
    def _rulebook(self):
        return {"rulebook_id": "ord", "version": "1.0.0", "adopted_at": FROZEN_AT,
                "evidence": [{"id": "a", "source": "file"}, {"id": "b", "source": "file"},
                             {"id": "c", "source": "file"}],
                "rules": [{"id": "r", "when": 'candidate.kind == "command"',
                           "outcome": "ALLOW", "reason": "ok"}],
                "default_outcome": "HOLD"}

    def test_acquisition_order_is_content(self):
        registry = _registry()
        pinned = _pin(self._rulebook(), registry)
        base = [{"id": i, "status": "ok", "acquired_at": FROZEN_AT, "value": i}
                for i in ("a", "b", "c")]
        digests = set()
        for order in itertools.permutations(base):
            frozen = snapshot.build_snapshot(pinned, "s", FROZEN_AT, list(order), registry)
            digests.add(frozen.digest)
            self.assertEqual([i["id"] for i in frozen.value()["items"]],
                             [a["id"] for a in order])
            self.assertEqual([i["order"] for i in frozen.value()["items"]], [0, 1, 2])
        self.assertEqual(len(digests), 6)

    def test_the_same_order_always_gives_the_same_bytes(self):
        registry = _registry()
        pinned = _pin(self._rulebook(), registry)
        acquisitions = [{"id": i, "status": "ok", "acquired_at": FROZEN_AT, "value": i}
                        for i in ("c", "a", "b")]
        first = snapshot.build_snapshot(pinned, "s", FROZEN_AT, acquisitions, registry)
        second = snapshot.build_snapshot(pinned, "s", FROZEN_AT, acquisitions, registry)
        self.assertEqual(first.canonical, second.canonical)

    def test_freeze_boundary_before_equal_and_after(self):
        registry = _registry()
        pinned = _pin(self._rulebook(), registry)
        for acquired, ok in (("2026-08-04T23:59:59Z", True), (FROZEN_AT, True),
                             ("2026-08-05T00:00:01Z", False)):
            acquisitions = [{"id": "a", "status": "ok", "acquired_at": acquired, "value": 1}]
            with self.subTest(acquired=acquired):
                if ok:
                    snapshot.build_snapshot(pinned, "s", FROZEN_AT, acquisitions, registry)
                else:
                    with self.assertRaises(VerifyError) as caught:
                        snapshot.build_snapshot(pinned, "s", FROZEN_AT, acquisitions, registry)
                    self.assertEqual(caught.exception.code, "evidence_order_invalid")

    def test_offsets_denoting_one_instant_pass_the_freeze_check_and_stay_distinct(self):
        registry = _registry()
        pinned = _pin(self._rulebook(), registry)
        zulu = snapshot.build_snapshot(
            pinned, "s", FROZEN_AT,
            [{"id": "a", "status": "ok", "acquired_at": "2026-08-04T23:00:00Z", "value": 1}],
            registry)
        offset = snapshot.build_snapshot(
            pinned, "s", FROZEN_AT,
            [{"id": "a", "status": "ok", "acquired_at": "2026-08-05T00:00:00+01:00",
              "value": 1}], registry)
        self.assertNotEqual(zulu.digest, offset.digest)
        self.assertEqual(zulu.value()["items"][0]["acquired_at"], "2026-08-04T23:00:00Z")


class DigestRecomputation(unittest.TestCase):
    def test_the_digest_covers_the_payload_and_not_itself(self):
        registry = _registry()
        pinned = _pin({"rulebook_id": "dig", "version": "1.0.0", "adopted_at": FROZEN_AT,
                       "evidence": [{"id": "a", "source": "file"}],
                       "rules": [{"id": "r", "when": 'candidate.kind == "command"',
                                  "outcome": "ALLOW", "reason": "ok"}],
                       "default_outcome": "HOLD"}, registry)
        frozen = snapshot.build_snapshot(
            pinned, "s", FROZEN_AT,
            [{"id": "a", "status": "ok", "acquired_at": FROZEN_AT, "value": "v"}], registry)
        built = frozen.value()
        payload = {k: v for k, v in built.items() if k != "snapshot_digest"}
        self.assertEqual(canon.digest(payload), built["snapshot_digest"])
        # The completed snapshot's own digest is a different value, and is never called
        # the snapshot digest.
        self.assertNotEqual(canon.digest(built), built["snapshot_digest"])

    def test_a_semantic_change_changes_the_digest(self):
        registry = _registry()
        pinned = _pin({"rulebook_id": "dig2", "version": "1.0.0", "adopted_at": FROZEN_AT,
                       "evidence": [{"id": "a", "source": "file"}],
                       "rules": [{"id": "r", "when": 'candidate.kind == "command"',
                                  "outcome": "ALLOW", "reason": "ok"}],
                       "default_outcome": "HOLD"}, registry)
        digests = set()
        for value in ("v", "w", 1, None, True):
            digests.add(snapshot.build_snapshot(
                pinned, "s", FROZEN_AT,
                [{"id": "a", "status": "ok", "acquired_at": FROZEN_AT, "value": value}],
                registry).digest)
        self.assertEqual(len(digests), 5)


class ImmutabilityAndPurity(unittest.TestCase):
    def _case(self, registry):
        pinned = _pin({"rulebook_id": "imm", "version": "1.0.0", "adopted_at": FROZEN_AT,
                       "evidence": [{"id": "a", "source": "file"}],
                       "rules": [{"id": "r", "when": 'candidate.kind == "command"',
                                  "outcome": "ALLOW", "reason": "ok"}],
                       "default_outcome": "HOLD"}, registry)
        acquisitions = [{"id": "a", "status": "ok", "acquired_at": FROZEN_AT,
                         "value": {"nested": [1, 2]}}]
        return pinned, acquisitions

    def test_no_input_is_mutated(self):
        registry = _registry()
        pinned, acquisitions = self._case(registry)
        before = (copy.deepcopy(acquisitions), pinned.digest, copy.deepcopy(registry))
        snapshot.build_snapshot(pinned, "s", FROZEN_AT, acquisitions, registry)
        self.assertEqual(acquisitions, before[0])
        self.assertEqual(pinned.digest, before[1])
        self.assertEqual(registry, before[2])

    def test_the_snapshot_is_immutable(self):
        registry = _registry()
        pinned, acquisitions = self._case(registry)
        frozen = snapshot.build_snapshot(pinned, "s", FROZEN_AT, acquisitions, registry)
        self.assertTrue(dataclasses.is_dataclass(frozen))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frozen.digest = "tampered"
        borrowed = frozen.value()
        borrowed["items"][0]["value"]["nested"].append(3)
        borrowed["snapshot_id"] = "tampered"
        self.assertNotEqual(frozen.value(), borrowed)
        self.assertIsNot(frozen.value(), frozen.value())

    def test_the_module_reads_no_clock_or_external_source(self):
        source = (REPO_ROOT / "vfy" / "snapshot.py").read_text(encoding="utf-8")
        for banned in ("import time", "import datetime", "import random", "import os",
                       "import socket", "import subprocess", "open(", "float(",
                       "urllib", "requests"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)

    def test_no_freshness_logic_is_duplicated_here(self):
        source = (REPO_ROOT / "vfy" / "snapshot.py").read_text(encoding="utf-8")
        self.assertNotIn("max_age_seconds", source)


class ExceptionContainment(unittest.TestCase):
    def test_malformed_acquisition_shapes_are_typed(self):
        registry = _registry()
        pinned = _pin({"rulebook_id": "fuzz", "version": "1.0.0", "adopted_at": FROZEN_AT,
                       "evidence": [{"id": "a", "source": "file"}],
                       "rules": [{"id": "r", "when": 'candidate.kind == "command"',
                                  "outcome": "ALLOW", "reason": "ok"}],
                       "default_outcome": "HOLD"}, registry)
        shapes = [None, True, 5, "text", [], {}, {"id": "a"}, {"status": "ok"},
                  {"id": "a", "status": "ok"}, {"id": None, "status": "ok",
                                                "acquired_at": FROZEN_AT},
                  {"id": "a", "status": None, "acquired_at": FROZEN_AT},
                  {"id": "a", "status": "ok", "acquired_at": None, "value": 1},
                  {"id": "a", "status": "ok", "acquired_at": FROZEN_AT, "value": 1, "x": 2}]
        for shape in shapes:
            with self.subTest(shape=repr(shape)[:40]):
                try:
                    snapshot.build_snapshot(pinned, "s", FROZEN_AT, [shape], registry)
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                    self.assertIsNotNone(typed.code)
                except Exception as untyped:
                    self.fail("%s crossed the boundary" % type(untyped).__name__)

    def test_programmer_defects_raise_rather_than_producing_a_snapshot(self):
        registry = _registry()
        pinned = _pin({"rulebook_id": "def", "version": "1.0.0", "adopted_at": FROZEN_AT,
                       "evidence": [], "rules": [{"id": "r", "when": 'candidate.kind == "x"',
                                                  "outcome": "ALLOW", "reason": "y"}],
                       "default_outcome": "HOLD"}, registry)
        for snapshot_id, acquisitions in ((None, []), (5, []), ("s", None), ("s", "text")):
            with self.subTest(snapshot_id=repr(snapshot_id)):
                with self.assertRaises(TypeError):
                    snapshot.build_snapshot(pinned, snapshot_id, FROZEN_AT, acquisitions,
                                            registry)


if __name__ == "__main__":
    unittest.main()
