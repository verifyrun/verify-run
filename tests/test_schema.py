"""Closure Unit 3B — bounded schema validation only.

Every expectation is stated in spec/schema-validation.md or frozen in fixtures/schema/.
"""

import copy
import itertools
import json
import pathlib
import unittest

from vfy import canon, load, schema
from vfy.errors import SchemaRegistryInvalid, VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
SCHEMA_DIR = REPO_ROOT / "fixtures" / "schema"
TEMPLATES = REPO_ROOT / "templates"

BASE = "https://verifyrun.com/spec/v1/"
CANDIDATE = BASE + "candidate.schema.json"
RULEBOOK = BASE + "rulebook.schema.json"
EVIDENCE = BASE + "evidence.schema.json"


def _registry():
    documents = [load.load_json_bytes(path.read_bytes())
                 for path in sorted(SPEC_DIR.glob("*.schema.json"))]
    return schema.build_registry(documents)


def _fixture(path):
    return json.loads(path.read_text(encoding="utf-8"))


class Registry(unittest.TestCase):
    def test_all_six_repository_schemas_load_into_one_registry(self):
        registry = _registry()
        self.assertEqual(len(registry), 6)
        for identifier in registry:
            self.assertIn(identifier, schema.CODE_BY_ID)

    def test_every_declared_id_is_unique(self):
        identifiers = [load.load_json_bytes(p.read_bytes())["$id"]
                       for p in sorted(SPEC_DIR.glob("*.schema.json"))]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_every_reference_resolves_offline(self):
        registry = _registry()
        references = []

        def walk(node, identifier):
            if isinstance(node, dict):
                if "$ref" in node:
                    references.append((node["$ref"], identifier))
                for value in node.values():
                    walk(value, identifier)
            elif isinstance(node, list):
                for value in node:
                    walk(value, identifier)

        for identifier, document in registry.items():
            walk(document, identifier)
        self.assertEqual(len(references), 3)
        for reference, identifier in references:
            with self.subTest(reference=reference):
                node, _document_id = schema._resolve(reference, identifier, registry)
                self.assertIsInstance(node, dict)

    def test_every_registry_reject_vector_is_typed(self):
        paths = sorted(SCHEMA_DIR.glob("registry_invalid_*.json"))
        self.assertGreaterEqual(len(paths), 11)
        for path in paths:
            case = _fixture(path)
            with self.subTest(fixture=path.name):
                with self.assertRaises(SchemaRegistryInvalid) as caught:
                    schema.build_registry(case["documents"])
                self.assertEqual(caught.exception.code, "schema_registry_invalid")

    def test_an_unsupported_keyword_is_never_silently_ignored(self):
        for keyword, value in (("maxProperties", 2), ("allOf", []), ("if", {}),
                               ("uniqueItems", True), ("multipleOf", 2),
                               ("patternProperties", {}), ("prefixItems", [])):
            with self.subTest(keyword=keyword):
                with self.assertRaises(SchemaRegistryInvalid):
                    schema.build_registry([{"$id": "x:1", "type": "object", keyword: value}])

    def test_remote_and_unknown_references_are_refused_without_fetching(self):
        for reference in ("https://example.invalid/s.json", "http://localhost/s.json",
                          "file:///etc/passwd", "../other.schema.json", "#/$defs/absent"):
            with self.subTest(reference=reference):
                with self.assertRaises(SchemaRegistryInvalid):
                    schema.build_registry(
                        [{"$id": "x:1", "properties": {"a": {"$ref": reference}}}]
                    )


class ValidInstances(unittest.TestCase):
    def test_every_valid_fixture_validates_and_keeps_its_frozen_digest(self):
        registry = _registry()
        paths = sorted(SCHEMA_DIR.glob("valid_*.json"))
        self.assertGreaterEqual(len(paths), 13)
        for path in paths:
            case = _fixture(path)
            with self.subTest(fixture=path.name):
                self.assertIsNone(schema.validate(case["value"], case["schema"], registry))
                self.assertEqual(canon.canonicalize(case["value"]), case["canonical"])
                self.assertEqual(canon.digest(case["value"]), "sha256:" + case["sha256"])

    def test_all_four_outcomes_have_a_valid_form(self):
        registry = _registry()
        seen = set()
        for path in sorted(SCHEMA_DIR.glob("valid_outcome_*.json")):
            case = _fixture(path)
            schema.validate(case["value"], case["schema"], registry)
            seen.add(case["value"]["outcome"])
        self.assertEqual(seen, {"ALLOW", "BLOCK", "HOLD", "ERROR"})


class InvalidInstances(unittest.TestCase):
    def test_every_invalid_fixture_fails_with_its_exact_code_path_and_keyword(self):
        registry = _registry()
        paths = sorted(SCHEMA_DIR.glob("invalid_*.json"))
        self.assertGreaterEqual(len(paths), 45)
        for path in paths:
            case = _fixture(path)
            expected = case["expected"]
            with self.subTest(fixture=path.name):
                with self.assertRaises(VerifyError) as caught:
                    schema.validate(case["value"], case["schema"], registry)
                failure = caught.exception
                self.assertEqual(failure.code, expected["reason_code"])
                self.assertEqual(failure.instance_path, expected["instance_path"])
                self.assertEqual(failure.schema_path, expected["schema_path"])
                self.assertEqual(failure.keyword, expected["keyword"])
                self.assertEqual(failure.outcome, "ERROR")

    def test_no_invalid_fixture_declares_a_success_digest(self):
        for path in sorted(SCHEMA_DIR.glob("invalid_*.json")):
            case = _fixture(path)
            with self.subTest(fixture=path.name):
                self.assertNotIn("sha256", case)
                self.assertNotIn("canonical", case)


class CurrentTemplates(unittest.TestCase):
    def test_all_three_templates_validate_against_the_rulebook_schema(self):
        registry = _registry()
        paths = sorted(TEMPLATES.glob("*.yaml"))
        self.assertEqual(len(paths), 3)
        for path in paths:
            with self.subTest(template=path.name):
                value = load.load_yaml_bytes(path.read_bytes())
                self.assertIsNone(schema.validate(value, RULEBOOK, registry))

    def test_validation_leaves_a_template_untouched(self):
        registry = _registry()
        for path in sorted(TEMPLATES.glob("*.yaml")):
            value = load.load_yaml_bytes(path.read_bytes())
            before = copy.deepcopy(value)
            digest_before = canon.digest(value)
            schema.validate(value, RULEBOOK, registry)
            with self.subTest(template=path.name):
                self.assertEqual(value, before)
                self.assertEqual(canon.digest(value), digest_before)


class NonMutation(unittest.TestCase):
    def test_validation_inserts_no_defaults(self):
        registry = _registry()
        # rulebook.schema.json declares default true for evidence.required and 300 for
        # ttl_seconds. Neither may appear after validation.
        value = {"rulebook_id": "r-1", "version": "1.0.0", "adopted_at": "2026-08-05T00:00:00Z",
                 "evidence": [{"id": "e", "source": "file"}],
                 "rules": [{"id": "a", "when": "true", "outcome": "ALLOW", "reason": "x"}],
                 "default_outcome": "HOLD", "authorization": {"single_use": True}}
        schema.validate(value, RULEBOOK, registry)
        self.assertNotIn("required", value["evidence"][0])
        self.assertNotIn("ttl_seconds", value["authorization"])

    def test_validation_changes_no_value_in_any_fixture(self):
        registry = _registry()
        for path in sorted(SCHEMA_DIR.glob("valid_*.json")):
            case = _fixture(path)
            before = copy.deepcopy(case["value"])
            with self.subTest(fixture=path.name):
                schema.validate(case["value"], case["schema"], registry)
                self.assertEqual(case["value"], before)
                self.assertEqual(canon.canonicalize(case["value"]), case["canonical"])

    def test_failure_also_leaves_the_value_untouched(self):
        registry = _registry()
        for path in sorted(SCHEMA_DIR.glob("invalid_*.json")):
            case = _fixture(path)
            before = copy.deepcopy(case["value"])
            with self.subTest(fixture=path.name):
                with self.assertRaises(VerifyError):
                    schema.validate(case["value"], case["schema"], registry)
                self.assertEqual(case["value"], before)


class TypeConfusion(unittest.TestCase):
    def test_a_boolean_never_satisfies_an_integer_schema(self):
        registry = _registry()
        for boolean in (True, False):
            value = {"snapshot_id": "s", "rulebook_digest": "sha256:" + "a" * 64,
                     "frozen_at": "2026-08-05T00:00:00Z", "snapshot_digest": "sha256:" + "a" * 64,
                     "items": [{"id": "e", "order": boolean,
                                "acquired_at": "2026-08-05T00:00:00Z", "status": "ok"}]}
            with self.subTest(boolean=boolean):
                with self.assertRaises(VerifyError) as caught:
                    schema.validate(value, EVIDENCE, registry)
                self.assertEqual(caught.exception.keyword, "type")

    def test_an_integer_never_satisfies_a_boolean_schema(self):
        registry = _registry()
        value = {"rulebook_id": "r-1", "version": "1.0.0", "adopted_at": "2026-08-05T00:00:00Z",
                 "evidence": [{"id": "e", "source": "file", "required": 1}],
                 "rules": [{"id": "a", "when": "t", "outcome": "ALLOW", "reason": "x"}],
                 "default_outcome": "HOLD"}
        with self.assertRaises(VerifyError) as caught:
            schema.validate(value, RULEBOOK, registry)
        self.assertEqual(caught.exception.keyword, "type")

    def test_enum_and_const_do_not_coerce(self):
        self.assertFalse(schema._equal(1, True))
        self.assertFalse(schema._equal(True, 1))
        self.assertFalse(schema._equal("1", 1))
        self.assertFalse(schema._equal(0, False))
        self.assertTrue(schema._equal({"a": [1, "x"]}, {"a": [1, "x"]}))
        self.assertFalse(schema._equal({"a": [1]}, {"a": [True]}))


class AdditionalProperties(unittest.TestCase):
    def test_undeclared_members_rejected_at_several_depths(self):
        registry = _registry()
        base = {"rulebook_id": "r-1", "version": "1.0.0", "adopted_at": "2026-08-05T00:00:00Z",
                "evidence": [{"id": "e", "source": "file"}],
                "rules": [{"id": "a", "when": "t", "outcome": "ALLOW", "reason": "x"}],
                "default_outcome": "HOLD"}
        cases = [
            (dict(base, zz=1), "$.zz"),
            ({**base, "evidence": [{"id": "e", "source": "file", "zz": 1}]}, "$.evidence[0].zz"),
            ({**base, "rules": [{"id": "a", "when": "t", "outcome": "ALLOW",
                                 "reason": "x", "zz": 1}]}, "$.rules[0].zz"),
            ({**base, "authorization": {"single_use": True, "zz": 1}}, "$.authorization.zz"),
        ]
        for value, path in cases:
            with self.subTest(path=path):
                with self.assertRaises(VerifyError) as caught:
                    schema.validate(value, RULEBOOK, registry)
                self.assertEqual(caught.exception.keyword, "additionalProperties")
                self.assertEqual(caught.exception.instance_path, path)

    def test_the_one_object_that_omits_additional_properties_stays_open(self):
        # candidate.action carries params whose shape is the caller's; this is deliberate.
        registry = _registry()
        value = {"candidate_id": "c", "kind": "command",
                 "action": {"summary": "x", "anything": {"nested": [1, 2]}}}
        self.assertIsNone(schema.validate(value, CANDIDATE, registry))


class PatternConformance(unittest.TestCase):
    VALID_ID = "agent-guard"
    DIGEST = "sha256:" + "a" * 64

    def test_a_trailing_newline_does_not_satisfy_an_anchored_pattern(self):
        # Python's `$` matches before a final newline; JavaScript's does not. Full-match closes
        # the divergence, which matters because digests carry the cryptographic contract.
        registry = _registry()
        value = {"snapshot_id": "s", "rulebook_digest": self.DIGEST + "\n",
                 "frozen_at": "2026-08-05T00:00:00Z", "items": [],
                 "snapshot_digest": self.DIGEST}
        with self.assertRaises(VerifyError) as caught:
            schema.validate(value, EVIDENCE, registry)
        self.assertEqual(caught.exception.keyword, "pattern")

    def test_pattern_vectors(self):
        registry = _registry()
        base = {"version": "1.0.0", "adopted_at": "2026-08-05T00:00:00Z", "evidence": [],
                "rules": [{"id": "a", "when": "t", "outcome": "ALLOW", "reason": "x"}],
                "default_outcome": "HOLD"}
        accepted = ["agent-guard", "a1", "z" * 64]
        refused = ["Agent-Guard", "-leading", "a", "x" * 65, "agent guard",
                   "agent-guard\n", "\nagent-guard", "agent\nguard", "agent_guard"]
        for identifier in accepted:
            with self.subTest(accepted=identifier):
                schema.validate(dict(base, rulebook_id=identifier), RULEBOOK, registry)
        for identifier in refused:
            with self.subTest(refused=identifier):
                with self.assertRaises(VerifyError):
                    schema.validate(dict(base, rulebook_id=identifier), RULEBOOK, registry)

    def test_every_registry_pattern_is_anchored_and_inside_the_subset(self):
        registry = _registry()
        patterns = []

        def walk(node):
            if isinstance(node, dict):
                if "pattern" in node:
                    patterns.append(node["pattern"])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        for document in registry.values():
            walk(document)
        self.assertGreaterEqual(len(patterns), 11)
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertTrue(pattern.startswith("^") and pattern.endswith("$"))
                for construct in schema._FORBIDDEN_REGEX:
                    self.assertNotIn(construct, pattern)


class DateTimeConformance(unittest.TestCase):
    ACCEPTED = ["2026-08-05T00:00:00Z", "2026-08-05T00:00:00.1Z",
                "2026-08-05T00:00:00.123456789Z", "2026-08-05T23:59:59+01:00",
                "2026-08-05T00:00:00-05:30", "2024-02-29T12:00:00Z", "2000-02-29T00:00:00Z"]
    REFUSED = ["2026-08-05", "2026-08-05 00:00:00Z", "2026-08-05t00:00:00z",
               "2026-08-05T00:00:00", "2026-08-05T00:00:00z", "2026-02-30T00:00:00Z",
               "2023-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-13-01T00:00:00Z",
               "2026-00-01T00:00:00Z", "2026-08-32T00:00:00Z", "2026-08-05T24:00:00Z",
               "2026-08-05T00:60:00Z", "2026-08-05T00:00:60Z", "2026-08-05T00:00:00+0100",
               "2026-08-05T00:00:00Z\n", " 2026-08-05T00:00:00Z", "2026-08-05T00:00:00.Z",
               "2026-08-05T00:00:00.1234567890Z", "not-a-time", ""]

    def test_accepted_vectors(self):
        for text in self.ACCEPTED:
            with self.subTest(accepted=text):
                self.assertTrue(schema._is_date_time(text))

    def test_refused_vectors(self):
        for text in self.REFUSED:
            with self.subTest(refused=text):
                self.assertFalse(schema._is_date_time(text))

    def test_the_string_is_not_converted_to_a_native_datetime(self):
        registry = _registry()
        value = {"snapshot_id": "s", "rulebook_digest": "sha256:" + "a" * 64,
                 "frozen_at": "2026-08-05T00:00:00Z", "items": [],
                 "snapshot_digest": "sha256:" + "a" * 64}
        schema.validate(value, EVIDENCE, registry)
        self.assertIsInstance(value["frozen_at"], str)


class DeterministicFailureOrder(unittest.TestCase):
    def test_first_failure_does_not_depend_on_insertion_order(self):
        registry = _registry()
        members = [("candidate_id", "c"), ("kind", "bogus"),
                   ("action", {"summary": "x"}), ("zz_extra", 1)]
        results = set()
        for order in itertools.permutations(members):
            with self.assertRaises(VerifyError) as caught:
                schema.validate(dict(order), CANDIDATE, registry)
            failure = caught.exception
            results.add((failure.code, failure.instance_path, failure.schema_path,
                         failure.keyword))
        self.assertEqual(len(results), 1)
        self.assertEqual(results.pop(),
                         ("candidate_schema_invalid", "$.kind",
                          "$.properties.kind.enum", "enum"))

    def test_required_is_reported_before_a_property_failure(self):
        registry = _registry()
        with self.assertRaises(VerifyError) as caught:
            schema.validate({"kind": "bogus", "action": {"summary": "x"}}, CANDIDATE, registry)
        self.assertEqual(caught.exception.keyword, "required")
        self.assertEqual(caught.exception.instance_path, "$.candidate_id")

    def test_properties_are_reported_before_additional_properties(self):
        registry = _registry()
        value = {"candidate_id": "c", "kind": "bogus", "action": {"summary": "x"}, "aaa": 1}
        with self.assertRaises(VerifyError) as caught:
            schema.validate(value, CANDIDATE, registry)
        self.assertEqual(caught.exception.keyword, "enum")


class PathNotation(unittest.TestCase):
    def test_unusual_member_names_are_escaped(self):
        self.assertEqual(schema._member("$", "plain"), "$.plain")
        self.assertEqual(schema._member("$", "_x1"), "$._x1")
        self.assertEqual(schema._member("$", "with.dot"), '$["with.dot"]')
        self.assertEqual(schema._member("$", "with space"), '$["with space"]')
        self.assertEqual(schema._member("$", '"'), '$["\\""]')
        self.assertEqual(schema._member("$", "\n"), '$["\\u000a"]')
        self.assertEqual(schema._member("$", "1leading"), '$["1leading"]')

    def test_unusual_member_names_appear_escaped_in_a_real_failure(self):
        registry = _registry()
        value = {"candidate_id": "c", "kind": "command", "action": {"summary": "x"},
                 "with.dot": 1}
        with self.assertRaises(VerifyError) as caught:
            schema.validate(value, CANDIDATE, registry)
        self.assertEqual(caught.exception.instance_path, '$["with.dot"]')


class ExceptionContainment(unittest.TestCase):
    def test_no_untyped_exception_crosses_the_public_api(self):
        registry = _registry()
        values = [None, True, 1, "text", [], {}, {"candidate_id": 1},
                  {"candidate_id": "c", "kind": "command", "action": None},
                  {"candidate_id": "c", "kind": "command", "action": {"summary": 1}},
                  {"candidate_id": "c", "kind": "command", "action": {"summary": "x"},
                   "identity": []}]
        for value in values:
            with self.subTest(value=repr(value)[:40]):
                try:
                    schema.validate(value, CANDIDATE, registry)
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                    self.assertIsNotNone(typed.code)
                except Exception as untyped:
                    self.fail("%s crossed the boundary" % type(untyped).__name__)

    def test_a_value_deeper_than_the_loader_admits_is_refused_not_crashed(self):
        registry = _registry()
        deep = {"summary": "x"}
        for _ in range(schema.MAX_DEPTH + 10):
            deep = {"summary": "x", "params": deep}
        value = {"candidate_id": "c", "kind": "command", "action": deep}
        try:
            schema.validate(value, CANDIDATE, registry)
        except VerifyError as typed:
            self.assertEqual(typed.outcome, "ERROR")
        except RecursionError:
            self.fail("RecursionError crossed the public validator boundary")

    def test_validating_against_an_unknown_schema_id_is_typed(self):
        with self.assertRaises(SchemaRegistryInvalid):
            schema.validate({}, "https://example.invalid/x.json", _registry())


if __name__ == "__main__":
    unittest.main()
