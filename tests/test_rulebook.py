"""Closure Unit 4 — rulebook loading, validation, applicability, and pinning."""

import base64
import copy
import dataclasses
import json
import pathlib
import unittest

import yaml

from vfy import canon, load, rulebook, schema
from vfy.errors import (
    RulebookSemanticInvalid,
    RulebookVersionCollision,
    VerifyError,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
RULEBOOK_DIR = REPO_ROOT / "fixtures" / "rulebooks"
TEMPLATES = REPO_ROOT / "templates"

# Frozen in Closure Unit 3A; this unit must not move them.
TEMPLATE_DIGESTS = {
    # agent-guard changed in 0.1.0a2: its destructive-command rule compared bare program names,
    # which `vfy run` never emits, so the rule could not fire on a gated command. A template is a
    # versioned starting point, not a signed artifact — receipts record the digest that governed
    # them, and every 0.1.0a1 receipt still replays against the rulebook stored beside it.
    # 0.1.0a1 was sha256:dfaeec83d2c67e3c56e0efc330a801edf727dcc0269c2325f81e80e87c8784aa.
    "agent-guard.yaml": "sha256:0a911c0ab2e7224b8a73fc20eb9947061f506fab5301d67304f8d3d11b72131e",
    "pipeline-gate.yaml": "sha256:eb851f1c213105876977484d3f41cd724811819fc65044a0c87cd29c829570ee",
    "claims-gate.yaml": "sha256:623eb952567e387fa8f713c9a70a12de9764d2a05e6cb5a528998f4336aba922",
}


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _case(path):
    case = json.loads(path.read_text(encoding="utf-8"))
    for key in ("source_base64", "first_base64", "second_base64"):
        if key in case:
            case[key.replace("_base64", "")] = base64.b64decode(case[key])
    return case


class AcceptedRulebooks(unittest.TestCase):
    def test_every_accepted_fixture_pins_to_its_frozen_value_and_digest(self):
        registry = _registry()
        paths = sorted(RULEBOOK_DIR.glob("accept_*.json"))
        self.assertGreaterEqual(len(paths), 13)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = rulebook.load_rulebook_bytes(case["source"], registry)
                self.assertEqual(pinned.value(), case["value"])
                self.assertEqual(pinned.canonical, case["canonical"])
                self.assertEqual(pinned.digest, case["digest"])
                self.assertEqual(pinned.digest, "sha256:" + case["sha256"])
                self.assertEqual(pinned.rulebook_id, case["rulebook_id"])
                self.assertEqual(pinned.version, case["version"])
                self.assertEqual(pinned.adopted_at, case["adopted_at"])

    def test_canonical_bytes_agree_with_the_canonical_text(self):
        registry = _registry()
        for path in sorted(RULEBOOK_DIR.glob("accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = rulebook.load_rulebook_bytes(case["source"], registry)
                self.assertEqual(pinned.canonical_bytes, case["canonical"].encode("utf-8"))
                self.assertEqual(canon.digest(pinned.value()), pinned.digest)

    def test_every_accepted_fixture_matches_its_declared_applicability(self):
        registry = _registry()
        for path in sorted(RULEBOOK_DIR.glob("accept_*.json")):
            case = _case(path)
            pinned = rulebook.load_rulebook_bytes(case["source"], registry)
            for instant, expected in case["applies"]:
                with self.subTest(fixture=path.name, instant=instant):
                    self.assertIs(rulebook.rulebook_applies(pinned, instant), expected)


class RejectedRulebooks(unittest.TestCase):
    def test_every_rejected_fixture_fails_with_its_declared_code(self):
        registry = _registry()
        paths = sorted(RULEBOOK_DIR.glob("reject_*.json"))
        self.assertGreaterEqual(len(paths), 15)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name, stage=case["stage"]):
                with self.assertRaises(VerifyError) as caught:
                    rulebook.load_rulebook_bytes(case["source"], registry)
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                self.assertEqual(caught.exception.outcome, "ERROR")

    def test_each_stage_keeps_its_own_code(self):
        registry = _registry()
        stages = {}
        for path in sorted(RULEBOOK_DIR.glob("reject_*.json")):
            case = _case(path)
            stages.setdefault(case["stage"], set()).add(case["expected"]["reason_code"])
        self.assertEqual(set(stages), {"source", "schema", "semantic"})
        self.assertEqual(stages["schema"], {"rulebook_schema_invalid"})
        self.assertEqual(stages["semantic"],
                         {"rulebook_semantic_invalid", "undeclared_evidence_id"})
        self.assertNotIn("rulebook_schema_invalid", stages["source"])

    def test_a_failed_load_produces_no_digest(self):
        registry = _registry()
        for path in sorted(RULEBOOK_DIR.glob("reject_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                self.assertNotIn("digest", case)
                self.assertNotIn("sha256", case)
                result = None
                try:
                    result = rulebook.load_rulebook_bytes(case["source"], registry)
                except VerifyError:
                    pass
                self.assertIsNone(result)


class CurrentTemplates(unittest.TestCase):
    def test_all_three_templates_pin(self):
        registry = _registry()
        paths = sorted(TEMPLATES.glob("*.yaml"))
        self.assertEqual(len(paths), 3)
        for path in paths:
            with self.subTest(template=path.name):
                pinned = rulebook.load_rulebook_bytes(path.read_bytes(), registry)
                self.assertEqual(pinned.version, "1.0.0")
                self.assertTrue(pinned.digest.startswith("sha256:"))
                self.assertEqual(len(pinned.digest), 71)

    def test_template_digests_match_the_values_frozen_in_closure_3a(self):
        registry = _registry()
        for name, digest in TEMPLATE_DIGESTS.items():
            with self.subTest(template=name):
                pinned = rulebook.load_rulebook_bytes((TEMPLATES / name).read_bytes(), registry)
                self.assertEqual(pinned.digest, digest)

    def test_templates_pin_identically_under_both_yaml_parsers(self):
        registry = _registry()
        loaders = [yaml.SafeLoader]
        if getattr(yaml, "__with_libyaml__", False):
            loaders.append(yaml.CSafeLoader)
        for name in TEMPLATE_DIGESTS:
            digests = set()
            for loader in loaders:
                value = load.load_yaml_bytes((TEMPLATES / name).read_bytes(),
                                             _loader_class=loader)
                digests.add(canon.digest(value))
            with self.subTest(template=name):
                self.assertEqual(len(digests), 1)
                self.assertEqual(digests.pop(), TEMPLATE_DIGESTS[name])


class SemanticEquivalence(unittest.TestCase):
    EQUIVALENT = ["accept_minimum", "accept_presentation_commented",
                  "accept_presentation_reordered", "accept_presentation_requoted"]

    def test_source_presentation_does_not_change_identity(self):
        registry = _registry()
        digests, canonicals = set(), set()
        for name in self.EQUIVALENT:
            case = _case(RULEBOOK_DIR / (name + ".json"))
            pinned = rulebook.load_rulebook_bytes(case["source"], registry)
            digests.add(pinned.digest)
            canonicals.add(pinned.canonical)
        self.assertEqual(len(digests), 1)
        self.assertEqual(len(canonicals), 1)

    def test_the_four_equivalent_sources_are_genuinely_different_bytes(self):
        sources = {_case(RULEBOOK_DIR / (name + ".json"))["source"]
                   for name in self.EQUIVALENT}
        self.assertEqual(len(sources), 4)

    def test_equal_strings_by_different_syntax_share_a_digest(self):
        registry = _registry()
        first = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_block_literal_strip.json")["source"], registry)
        second = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_block_equivalent_quoted.json")["source"], registry)
        self.assertEqual(first.digest, second.digest)

    def test_a_changed_string_changes_the_digest(self):
        registry = _registry()
        strip = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_block_literal_strip.json")["source"], registry)
        clip = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_block_literal_clip_differs.json")["source"], registry)
        self.assertNotEqual(strip.digest, clip.digest)
        self.assertEqual(strip.value()["description"] + "\n", clip.value()["description"])


class VersionCollision(unittest.TestCase):
    def test_the_collision_pair_loads_separately_and_is_refused_together(self):
        registry = _registry()
        case = _case(RULEBOOK_DIR / "collision_same_identity_different_content.json")
        first = rulebook.load_rulebook_bytes(case["first"], registry)
        second = rulebook.load_rulebook_bytes(case["second"], registry)
        self.assertEqual(first.identity, second.identity)
        self.assertNotEqual(first.digest, second.digest)
        with self.assertRaises(RulebookVersionCollision) as caught:
            rulebook.check_no_version_collision(first, second)
        self.assertEqual(caught.exception.code, "rulebook_version_collision")
        self.assertEqual(caught.exception.outcome, "ERROR")

    def test_identical_content_is_not_a_collision(self):
        registry = _registry()
        case = _case(RULEBOOK_DIR / "collision_same_identity_different_content.json")
        first = rulebook.load_rulebook_bytes(case["first"], registry)
        again = rulebook.load_rulebook_bytes(case["first"], registry)
        self.assertIsNone(rulebook.check_no_version_collision(first, again))

    def test_different_identity_is_not_a_collision(self):
        registry = _registry()
        agent = rulebook.load_rulebook_bytes((TEMPLATES / "agent-guard.yaml").read_bytes(), registry)
        pipeline = rulebook.load_rulebook_bytes((TEMPLATES / "pipeline-gate.yaml").read_bytes(),
                                                registry)
        self.assertIsNone(rulebook.check_no_version_collision(agent, pipeline))

    def test_presentation_variants_are_not_a_collision(self):
        registry = _registry()
        first = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_minimum.json")["source"], registry)
        second = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_presentation_commented.json")["source"], registry)
        self.assertEqual(first.identity, second.identity)
        self.assertIsNone(rulebook.check_no_version_collision(first, second))


class Immutability(unittest.TestCase):
    def test_the_pinned_record_cannot_be_reassigned(self):
        registry = _registry()
        pinned = rulebook.load_rulebook_bytes((TEMPLATES / "agent-guard.yaml").read_bytes(),
                                              registry)
        self.assertTrue(dataclasses.is_dataclass(pinned))
        for field in ("canonical", "digest", "rulebook_id", "version", "adopted_at"):
            with self.subTest(field=field):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(pinned, field, "tampered")

    def test_every_stored_field_is_a_string(self):
        registry = _registry()
        pinned = rulebook.load_rulebook_bytes((TEMPLATES / "claims-gate.yaml").read_bytes(),
                                              registry)
        for field in dataclasses.fields(pinned):
            with self.subTest(field=field.name):
                self.assertIsInstance(getattr(pinned, field.name), str)

    def test_mutating_a_reconstructed_value_cannot_affect_the_pinned_rulebook(self):
        registry = _registry()
        pinned = rulebook.load_rulebook_bytes((TEMPLATES / "pipeline-gate.yaml").read_bytes(),
                                              registry)
        digest_before = pinned.digest
        borrowed = pinned.value()
        borrowed["rulebook_id"] = "tampered"
        borrowed["rules"][0]["outcome"] = "ALLOW"
        borrowed["rules"].append({"id": "injected"})
        borrowed["evidence"][0]["max_age_seconds"] = 1
        self.assertEqual(pinned.digest, digest_before)
        self.assertEqual(pinned.rulebook_id, "pipeline-gate")
        self.assertNotEqual(pinned.value(), borrowed)
        self.assertEqual(canon.digest(pinned.value()), digest_before)

    def test_each_reconstruction_is_a_separate_object(self):
        registry = _registry()
        pinned = rulebook.load_rulebook_bytes((TEMPLATES / "agent-guard.yaml").read_bytes(),
                                              registry)
        first, second = pinned.value(), pinned.value()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["rules"], second["rules"])
        self.assertIsNot(first["rules"][0], second["rules"][0])


class NoMutationOfInput(unittest.TestCase):
    def test_loading_changes_neither_the_source_nor_the_registry(self):
        registry = _registry()
        registry_before = copy.deepcopy(registry)
        source = (TEMPLATES / "claims-gate.yaml").read_bytes()
        source_before = bytes(source)
        rulebook.load_rulebook_bytes(source, registry)
        self.assertEqual(source, source_before)
        self.assertEqual(registry, registry_before)

    def test_no_default_is_inserted(self):
        registry = _registry()
        case = _case(RULEBOOK_DIR / "accept_defaults_omitted.json")
        pinned = rulebook.load_rulebook_bytes(case["source"], registry)
        value = pinned.value()
        self.assertNotIn("required", value["evidence"][0])
        self.assertNotIn("ttl_seconds", value["authorization"])
        self.assertEqual(pinned.canonical, case["canonical"])

    def test_written_out_defaults_are_not_the_same_rulebook_as_omitted_ones(self):
        registry = _registry()
        explicit = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_defaults_written_out.json")["source"], registry)
        omitted = rulebook.load_rulebook_bytes(
            _case(RULEBOOK_DIR / "accept_defaults_omitted.json")["source"], registry)
        self.assertNotEqual(explicit.digest, omitted.digest)


class Applicability(unittest.TestCase):
    def _pinned(self, adopted_at="2026-08-05T00:00:00Z"):
        registry = _registry()
        source = ("rulebook_id: test-rulebook\nversion: 1.0.0\nadopted_at: \"%s\"\nevidence: []\n"
                  "rules:\n  - id: r\n    when: 'true'\n    outcome: ALLOW\n    reason: ok\n"
                  "default_outcome: HOLD\n" % adopted_at).encode("utf-8")
        return rulebook.load_rulebook_bytes(source, registry)

    def test_before_at_and_after_adoption(self):
        pinned = self._pinned()
        self.assertFalse(rulebook.rulebook_applies(pinned, "2026-08-04T23:59:59Z"))
        self.assertTrue(rulebook.rulebook_applies(pinned, "2026-08-05T00:00:00Z"))
        self.assertTrue(rulebook.rulebook_applies(pinned, "2026-08-05T00:00:01Z"))

    def test_boundary_is_exact_to_the_nanosecond(self):
        pinned = self._pinned("2026-08-05T00:00:00.500000000Z")
        self.assertFalse(rulebook.rulebook_applies(pinned, "2026-08-05T00:00:00.499999999Z"))
        self.assertTrue(rulebook.rulebook_applies(pinned, "2026-08-05T00:00:00.500000000Z"))
        self.assertTrue(rulebook.rulebook_applies(pinned, "2026-08-05T00:00:00.500000001Z"))

    def test_equivalent_instants_with_different_offsets_compare_equal(self):
        pinned = self._pinned("2026-08-05T00:00:00Z")
        self.assertTrue(rulebook.rulebook_applies(pinned, "2026-08-05T01:00:00+01:00"))
        self.assertTrue(rulebook.rulebook_applies(pinned, "2026-08-04T19:00:00-05:00"))
        self.assertFalse(rulebook.rulebook_applies(pinned, "2026-08-05T00:59:59+01:00"))

    def test_equivalent_instants_are_still_distinct_rulebook_content(self):
        # Same instant, two strings: equal for applicability, different for identity.
        zulu = self._pinned("2026-08-05T00:00:00Z")
        offset = self._pinned("2026-08-05T01:00:00+01:00")
        self.assertNotEqual(zulu.digest, offset.digest)
        self.assertNotEqual(zulu.adopted_at, offset.adopted_at)
        for instant in ("2026-08-05T00:00:00Z", "2026-08-05T01:00:00+01:00"):
            with self.subTest(instant=instant):
                self.assertIs(rulebook.rulebook_applies(zulu, instant),
                              rulebook.rulebook_applies(offset, instant))

    def test_leap_day_and_year_boundaries(self):
        pinned = self._pinned("2024-02-29T00:00:00Z")
        self.assertFalse(rulebook.rulebook_applies(pinned, "2024-02-28T23:59:59Z"))
        self.assertTrue(rulebook.rulebook_applies(pinned, "2024-03-01T00:00:00Z"))
        year_end = self._pinned("2027-01-01T00:00:00Z")
        self.assertFalse(rulebook.rulebook_applies(year_end, "2026-12-31T23:59:59Z"))
        self.assertTrue(rulebook.rulebook_applies(year_end, "2027-01-01T00:00:00Z"))

    def test_applicability_reads_no_clock(self):
        # The same question asked twice must give the same answer regardless of when it is
        # asked, and an instant far in the past or future is answered from the argument alone.
        pinned = self._pinned()
        self.assertFalse(rulebook.rulebook_applies(pinned, "1970-01-01T00:00:00Z"))
        self.assertTrue(rulebook.rulebook_applies(pinned, "2999-12-31T23:59:59Z"))
        self.assertEqual(rulebook.rulebook_applies(pinned, "2026-08-05T00:00:00Z"),
                         rulebook.rulebook_applies(pinned, "2026-08-05T00:00:00Z"))

    def test_a_malformed_instant_is_a_caller_contract_violation(self):
        pinned = self._pinned()
        for instant in (None, 0, "2026-08-05", "not-a-time", "2026-08-05T00:00:00",
                        "2026-08-05T00:00:00Z\n", b"2026-08-05T00:00:00Z"):
            with self.subTest(instant=repr(instant)):
                with self.assertRaises(TypeError):
                    rulebook.rulebook_applies(pinned, instant)


class NoExpressionParsing(unittest.TestCase):
    def test_a_rulebook_with_an_unparseable_expression_still_pins(self):
        # Expression validity belongs to the expression closure, not to pinning.
        registry = _registry()
        source = (b"rulebook_id: test-rulebook\nversion: 1.0.0\nadopted_at: \"2026-08-05T00:00:00Z\"\n"
                  b"evidence: []\nrules:\n  - id: r\n    when: '((( not an expression'\n"
                  b"    outcome: ALLOW\n    reason: ok\ndefault_outcome: HOLD\n")
        pinned = rulebook.load_rulebook_bytes(source, registry)
        self.assertEqual(pinned.value()["rules"][0]["when"], "((( not an expression")

    def test_an_expression_naming_undeclared_evidence_still_pins(self):
        # Only requires_evidence is checked here; expression references are the parser's.
        registry = _registry()
        source = (b"rulebook_id: test-rulebook\nversion: 1.0.0\nadopted_at: \"2026-08-05T00:00:00Z\"\n"
                  b"evidence: []\nrules:\n  - id: r\n    when: 'present(nowhere)'\n"
                  b"    outcome: ALLOW\n    reason: ok\ndefault_outcome: HOLD\n")
        self.assertIsNotNone(rulebook.load_rulebook_bytes(source, registry))


class LoadTimeSemantics(unittest.TestCase):
    def _load(self, body):
        registry = _registry()
        source = ("rulebook_id: test-rulebook\nversion: 1.0.0\nadopted_at: \"2026-08-05T00:00:00Z\"\n"
                  + body + "default_outcome: HOLD\n").encode("utf-8")
        return rulebook.load_rulebook_bytes(source, registry)

    RULE = "rules:\n  - id: r\n    when: 'true'\n    outcome: ALLOW\n    reason: ok\n"

    def test_evidence_identifier_grammar(self):
        for identifier in ("ok", "_ok", "Ok9", "a_b_c"):
            with self.subTest(accepted=identifier):
                self._load("evidence:\n  - {id: %s, source: file}\n" % identifier + self.RULE)
        for identifier in ("my-id", '"1e"', '"with space"', '"e.f"', '""'):
            with self.subTest(refused=identifier):
                with self.assertRaises(RulebookSemanticInvalid):
                    self._load("evidence:\n  - {id: %s, source: file}\n" % identifier + self.RULE)

    def test_rule_order_is_preserved_exactly(self):
        pinned = self._load(
            "evidence: []\nrules:\n"
            "  - {id: c, when: 'true', outcome: ALLOW, reason: x}\n"
            "  - {id: a, when: 'true', outcome: BLOCK, reason: y}\n"
            "  - {id: b, when: 'true', outcome: HOLD, reason: z}\n")
        self.assertEqual([rule["id"] for rule in pinned.value()["rules"]], ["c", "a", "b"])
        # Arrays are never sorted, so the canonical text carries the declared order too.
        self.assertLess(pinned.canonical.index('"id":"c"'), pinned.canonical.index('"id":"a"'))
        self.assertLess(pinned.canonical.index('"id":"a"'), pinned.canonical.index('"id":"b"'))


class ExceptionContainment(unittest.TestCase):
    def test_no_untyped_exception_crosses_the_public_api(self):
        registry = _registry()
        sources = [b"", b"---\n", b"- a\n", b"a: [1\n", b"\xff\xfe", b"\xef\xbb\xbfa: 1\n",
                   b"rulebook_id: test-rulebook\n", b"a: " + b"[" * 200 + b"]" * 200 + b"\n",
                   b"rulebook_id: test-rulebook\nversion: 1.0.0\nadopted_at: 2026-08-05\n"]
        for source in sources:
            with self.subTest(source=repr(source)[:40]):
                try:
                    rulebook.load_rulebook_bytes(source, registry)
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                    self.assertIsNotNone(typed.code)
                except Exception as untyped:
                    self.fail("%s crossed the boundary" % type(untyped).__name__)
                else:
                    self.fail("accepted malformed source %r" % source[:30])

    def test_the_boundary_takes_bytes(self):
        with self.assertRaises(TypeError):
            rulebook.load_rulebook_bytes("rulebook_id: t\n", _registry())


if __name__ == "__main__":
    unittest.main()
