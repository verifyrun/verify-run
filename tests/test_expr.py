"""Closure Unit 5 — expression parsing, static validation, and canonical AST."""

import copy
import dataclasses
import itertools
import json
import pathlib
import unittest

from vfy import canon, expr, load, rulebook, schema
from vfy.errors import (
    ExpressionParseError,
    ExpressionTypeError,
    SurrogateNotPermitted,
    UndeclaredEvidenceId,
    VerifyError,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
EXPR_DIR = REPO_ROOT / "fixtures" / "expressions"
TEMPLATES = REPO_ROOT / "templates"
EVALUATION_DIR = REPO_ROOT / "fixtures" / "evaluation"


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _case(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _rulebook_with(evidence_ids, registry=None):
    declarations = "".join("  - {id: %s, source: file}\n" % i for i in evidence_ids)
    source = ("rulebook_id: probe\nversion: 1.0.0\nadopted_at: \"2026-08-05T00:00:00Z\"\n"
              "evidence:%s\nrules:\n  - id: r\n    when: 'x'\n    outcome: ALLOW\n"
              "    reason: ok\ndefault_outcome: HOLD\n"
              % ("\n" + declarations.rstrip("\n") if declarations else " []")).encode("utf-8")
    return rulebook.load_rulebook_bytes(source, registry or _registry())


class AcceptedExpressions(unittest.TestCase):
    def test_every_accepted_fixture_parses_to_its_frozen_ast(self):
        paths = sorted(EXPR_DIR.glob("accept_*.json"))
        self.assertGreaterEqual(len(paths), 43)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                parsed = expr.parse_expression(case["source"])
                self.assertEqual(parsed.ast(), case["ast"])
                self.assertEqual(parsed.canonical, case["canonical"])
                self.assertEqual(canon.canonicalize(parsed.ast()), case["canonical"])
                self.assertEqual(list(parsed.evidence_ids), case["evidence_ids"])

    def test_every_accepted_fixture_validates_against_its_declared_evidence(self):
        registry = _registry()
        for path in sorted(EXPR_DIR.glob("accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                parsed = expr.parse_expression(case["source"])
                pinned = _rulebook_with(case["declared_evidence"], registry)
                self.assertIsNone(expr.validate_expression(parsed, pinned))

    def test_the_ast_holds_only_canonical_value_types(self):
        permitted = (dict, list, str, int, bool)
        for path in sorted(EXPR_DIR.glob("accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                root = expr.parse_expression(case["source"]).ast()
                # Nodes carry a type tag; path segments are records, not nodes.
                self.assertIn("type", root)
                pending = [root]
                while pending:
                    item = pending.pop()
                    self.assertIsInstance(item, permitted)
                    self.assertNotIsInstance(item, float)
                    if isinstance(item, dict):
                        for key, member in item.items():
                            self.assertIsInstance(key, str)
                            pending.append(member)
                    elif isinstance(item, list):
                        pending.extend(item)


class RejectedExpressions(unittest.TestCase):
    def test_every_syntax_reject_is_a_parse_error(self):
        paths = sorted(EXPR_DIR.glob("reject_syntax_*.json"))
        self.assertGreaterEqual(len(paths), 33)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                with self.assertRaises(VerifyError) as caught:
                    expr.parse_expression(case["source"])
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                self.assertEqual(caught.exception.outcome, "ERROR")

    def test_every_type_reject_is_a_static_type_error(self):
        paths = sorted(EXPR_DIR.glob("reject_type_*.json"))
        self.assertGreaterEqual(len(paths), 14)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                with self.assertRaises(ExpressionTypeError) as caught:
                    expr.parse_expression(case["source"])
                self.assertEqual(caught.exception.code, "expression_type_error")

    def test_every_static_reject_names_the_undeclared_evidence_id(self):
        registry = _registry()
        paths = sorted(EXPR_DIR.glob("reject_static_*.json"))
        self.assertGreaterEqual(len(paths), 5)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                parsed = expr.parse_expression(case["source"])
                pinned = _rulebook_with(case["declared_evidence"], registry)
                with self.assertRaises(UndeclaredEvidenceId) as caught:
                    expr.validate_expression(parsed, pinned)
                self.assertEqual(caught.exception.code, "undeclared_evidence_id")
                self.assertIn(case["undeclared_id"], str(caught.exception))

    def test_a_lone_surrogate_escape_is_refused(self):
        case = _case(EXPR_DIR / "reject_syntax_lone_surrogate.json")
        with self.assertRaises(SurrogateNotPermitted):
            expr.parse_expression(case["source"])


class CurrentTemplateExpressions(unittest.TestCase):
    def test_every_template_expression_parses_and_validates(self):
        registry = _registry()
        count = 0
        for path in sorted(TEMPLATES.glob("*.yaml")):
            pinned = rulebook.load_rulebook_bytes(path.read_bytes(), registry)
            for rule in pinned.value()["rules"]:
                with self.subTest(template=path.name, rule=rule["id"]):
                    parsed = expr.parse_expression(rule["when"])
                    self.assertIsNone(expr.validate_expression(parsed, pinned))
                    count += 1
        self.assertEqual(count, 10)

    def test_evaluation_fixture_rulebooks_have_parseable_expressions(self):
        registry = _registry()
        referenced = set()
        # eval_* only: probe_* and walk_* carry inline rulebooks, not a reference.
        for path in sorted(EVALUATION_DIR.glob("eval_*.json")):
            referenced.add(_case(path)["rulebook_ref"])
        self.assertTrue(referenced)
        for reference in sorted(referenced):
            pinned = rulebook.load_rulebook_bytes((REPO_ROOT / reference).read_bytes(), registry)
            for rule in pinned.value()["rules"]:
                with self.subTest(rulebook=reference, rule=rule["id"]):
                    parsed = expr.parse_expression(rule["when"])
                    self.assertIsNone(expr.validate_expression(parsed, pinned))


class WhitespaceEquivalence(unittest.TestCase):
    def test_formatting_variants_share_one_ast(self):
        paths = sorted(EXPR_DIR.glob("equivalent_*.json"))
        self.assertGreaterEqual(len(paths), 4)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                canonicals = {expr.parse_expression(s).canonical for s in case["sources"]}
                self.assertEqual(len(canonicals), 1)
                self.assertEqual(canonicals.pop(), case["canonical"])
                self.assertGreater(len(set(case["sources"])), 1)

    def test_a_meaningful_change_does_change_the_ast(self):
        base = expr.parse_expression('candidate.a == "x"').canonical
        for changed in ('candidate.a != "x"', 'candidate.b == "x"', 'candidate.a == "y"',
                        'candidate.a == 5', 'identity.a == "x"', 'candidate.a[0] == "x"'):
            with self.subTest(changed=changed):
                self.assertNotEqual(expr.parse_expression(changed).canonical, base)


class Precedence(unittest.TestCase):
    def test_and_binds_tighter_than_or(self):
        parsed = expr.parse_expression('present(a) or present(b) and present(c)')
        tree = parsed.ast()
        self.assertEqual(tree["type"], "or")
        self.assertEqual(tree["operands"][1]["type"], "and")

    def test_not_binds_tighter_than_and(self):
        tree = expr.parse_expression('not present(a) and present(b)').ast()
        self.assertEqual(tree["type"], "and")
        self.assertEqual(tree["operands"][0]["type"], "not")

    def test_parentheses_override_precedence(self):
        grouped = expr.parse_expression('(present(a) or present(b)) and present(c)').ast()
        self.assertEqual(grouped["type"], "and")
        self.assertEqual(grouped["operands"][0]["type"], "or")

    def test_associative_runs_flatten_in_source_order(self):
        tree = expr.parse_expression('present(a) and present(b) and present(c)').ast()
        self.assertEqual(tree["type"], "and")
        self.assertEqual([o["evidence_id"] for o in tree["operands"]], ["a", "b", "c"])

    def test_operand_order_is_never_rearranged(self):
        left = expr.parse_expression('present(b) and present(a)').canonical
        right = expr.parse_expression('present(a) and present(b)').canonical
        self.assertNotEqual(left, right)

    def test_redundant_parentheses_leave_no_trace(self):
        plain = expr.parse_expression('candidate.a == "x"').canonical
        for wrapped in ('(candidate.a == "x")', '((candidate.a == "x"))',
                        '(((candidate.a == "x")))'):
            with self.subTest(wrapped=wrapped):
                self.assertEqual(expr.parse_expression(wrapped).canonical, plain)

    def test_nothing_is_simplified(self):
        # x and true, double negation, and duplicates are all preserved as written.
        tree = expr.parse_expression('present(a) and present(a)').ast()
        self.assertEqual(len(tree["operands"]), 2)
        double = expr.parse_expression('not (not present(a))').ast()
        self.assertEqual(double["type"], "not")
        self.assertEqual(double["operand"]["type"], "not")


class Paths(unittest.TestCase):
    def test_paths_are_structural(self):
        tree = expr.parse_expression('candidate.action.argv[0] == "rm"').ast()
        path = tree["left"]
        self.assertEqual(path["root"], "candidate")
        self.assertEqual(path["segments"],
                         [{"member": "action"}, {"member": "argv"}, {"index": 0}])

    def test_all_three_roots_are_accepted(self):
        for root in ("candidate", "evidence", "identity"):
            with self.subTest(root=root):
                tree = expr.parse_expression('%s.x == "y"' % root).ast()
                self.assertEqual(tree["left"]["root"], root)

    def test_a_path_that_will_not_resolve_is_not_a_parse_failure(self):
        # Existence is a runtime question; spec/rulebook-language.md answers it with `absent`.
        for source in ('candidate.nothing.at.all == "x"', 'candidate.a[99] == "x"',
                       'identity.absent_field != "main"'):
            with self.subTest(source=source):
                self.assertIsNotNone(expr.parse_expression(source))


class Functions(unittest.TestCase):
    def test_arity_failures_are_static_type_errors_in_both_directions(self):
        for source in ('fresh()', 'fresh(a, b)', 'present()', 'present(a, b)',
                       'matches(candidate.a)', 'matches(candidate.a, "p", "q")'):
            with self.subTest(source=source):
                with self.assertRaises(ExpressionTypeError):
                    expr.parse_expression(source)

    def test_unknown_functions_are_parse_errors(self):
        for source in ('stale(a)', 'exists(a)', 'match(candidate.a, "p")'):
            with self.subTest(source=source):
                with self.assertRaises(ExpressionParseError):
                    expr.parse_expression(source)

    def test_the_pattern_is_preserved_verbatim_and_not_interpreted(self):
        tree = expr.parse_expression('matches(candidate.a, "^[a-z]+$.*")').ast()
        self.assertEqual(tree["pattern"], "^[a-z]+$.*")


class StaticEvidenceReferences(unittest.TestCase):
    def test_ids_are_collected_in_source_order_without_duplicates(self):
        parsed = expr.parse_expression(
            'fresh(b) and evidence.a == "x" and present(b) and evidence.c == "y"')
        self.assertEqual(list(parsed.evidence_ids), ["b", "a", "c"])

    def test_nothing_is_inferred_from_string_contents(self):
        parsed = expr.parse_expression('candidate.a == "tests" and matches(candidate.b, "fresh")')
        self.assertEqual(list(parsed.evidence_ids), [])

    def test_candidate_and_identity_paths_are_not_evidence_references(self):
        parsed = expr.parse_expression('candidate.evidence == "x" and identity.tests == "y"')
        self.assertEqual(list(parsed.evidence_ids), [])

    def test_the_first_undeclared_reference_is_reported(self):
        registry = _registry()
        pinned = _rulebook_with(["known"], registry)
        parsed = expr.parse_expression('fresh(known) and present(missing_one) and '
                                       'evidence.missing_two == "x"')
        with self.assertRaises(UndeclaredEvidenceId) as caught:
            expr.validate_expression(parsed, pinned)
        self.assertIn("missing_one", str(caught.exception))
        self.assertNotIn("missing_two", str(caught.exception))

    def test_validation_does_not_mutate_the_rulebook(self):
        registry = _registry()
        pinned = _rulebook_with(["known"], registry)
        digest_before = pinned.digest
        parsed = expr.parse_expression('fresh(known)')
        expr.validate_expression(parsed, pinned)
        self.assertEqual(pinned.digest, digest_before)


class Immutability(unittest.TestCase):
    def test_the_parsed_record_is_frozen(self):
        parsed = expr.parse_expression('candidate.a == "x"')
        self.assertTrue(dataclasses.is_dataclass(parsed))
        for field in ("source", "canonical", "evidence_ids"):
            with self.subTest(field=field):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(parsed, field, "tampered")

    def test_evidence_ids_are_an_immutable_sequence(self):
        parsed = expr.parse_expression('fresh(a)')
        self.assertIsInstance(parsed.evidence_ids, tuple)

    def test_mutating_a_reconstructed_ast_cannot_affect_the_parsed_expression(self):
        parsed = expr.parse_expression('candidate.a == "x"')
        canonical_before = parsed.canonical
        borrowed = parsed.ast()
        borrowed["type"] = "tampered"
        borrowed["left"]["segments"].append({"member": "injected"})
        self.assertEqual(parsed.canonical, canonical_before)
        self.assertNotEqual(parsed.ast(), borrowed)

    def test_each_reconstruction_is_a_separate_object(self):
        parsed = expr.parse_expression('candidate.a[0] == "x"')
        first, second = parsed.ast(), parsed.ast()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["left"]["segments"], second["left"]["segments"])

    def test_parsing_does_not_mutate_its_input(self):
        source = 'candidate.a == "x" and present(b)'
        before = copy.deepcopy(source)
        expr.parse_expression(source)
        self.assertEqual(source, before)


class ExceptionContainment(unittest.TestCase):
    def test_no_raw_parser_exception_crosses_the_public_boundary(self):
        alphabet = ['candidate.a', '==', '"x"', '(', ')', '[', ']', ',', 'and', 'not',
                    'fresh', '5', '.', 'in', '"', '\\', '-', '<', '>=']
        probes = set()
        for length in (1, 2, 3):
            for combination in itertools.product(alphabet, repeat=length):
                probes.add(" ".join(combination))
        accepted = 0
        for source in sorted(probes):
            try:
                expr.parse_expression(source)
                accepted += 1
            except VerifyError as typed:
                self.assertEqual(typed.outcome, "ERROR")
                self.assertIsNotNone(typed.code)
            except Exception as untyped:
                self.fail("%s crossed the boundary for %r"
                          % (type(untyped).__name__, source))
        self.assertGreater(len(probes), 6000)
        self.assertGreater(accepted, 0)

    def test_the_boundary_takes_a_string(self):
        for value in (None, 5, b'candidate.a == "x"', ["candidate.a"]):
            with self.subTest(value=repr(value)):
                with self.assertRaises(TypeError):
                    expr.parse_expression(value)

    def test_deeply_nested_parentheses_do_not_crash_the_boundary(self):
        for depth in (10, 100, 400):
            source = "(" * depth + 'candidate.a == "x"' + ")" * depth
            with self.subTest(depth=depth):
                try:
                    expr.parse_expression(source)
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                except RecursionError:
                    self.fail("RecursionError crossed the public parser boundary")


class FailureLocation(unittest.TestCase):
    def test_offsets_line_and_column_are_reported(self):
        with self.assertRaises(ExpressionParseError) as caught:
            expr.parse_expression('candidate.a == "x" candidate.b')
        failure = caught.exception
        self.assertEqual(failure.offset, 19)
        self.assertEqual(failure.line, 1)
        self.assertEqual(failure.column, 20)
        self.assertEqual(failure.expected, "end of expression")

    def test_an_empty_source_points_at_the_end(self):
        with self.assertRaises(ExpressionParseError) as caught:
            expr.parse_expression("")
        self.assertEqual(caught.exception.offset, 0)
        self.assertEqual(caught.exception.line, 1)
        self.assertEqual(caught.exception.column, 1)

    def test_line_and_column_track_newlines(self):
        with self.assertRaises(ExpressionParseError) as caught:
            expr.parse_expression('candidate.a == "x"\nand candidate.b')
        self.assertEqual(caught.exception.line, 2)

    def test_offsets_count_unicode_scalars_not_bytes(self):
        with self.assertRaises(ExpressionParseError) as caught:
            expr.parse_expression('candidate.a == "é𝄞" bad')
        # 15 scalars of prefix, a 4-scalar string literal, one space.
        self.assertEqual(caught.exception.offset, 20)

    def test_every_parse_failure_carries_a_complete_location(self):
        for path in sorted(EXPR_DIR.glob("reject_syntax_*.json")):
            case = _case(path)
            if case["expected"]["reason_code"] != "expression_parse_error":
                continue
            with self.subTest(fixture=path.name):
                with self.assertRaises(ExpressionParseError) as caught:
                    expr.parse_expression(case["source"])
                failure = caught.exception
                self.assertIsInstance(failure.offset, int)
                self.assertGreaterEqual(failure.offset, 0)
                self.assertGreaterEqual(failure.line, 1)
                self.assertGreaterEqual(failure.column, 1)
                self.assertIsInstance(failure.expected, str)
                self.assertTrue(failure.expected)


class NoEvaluation(unittest.TestCase):
    def test_a_constant_comparison_is_not_reduced(self):
        tree = expr.parse_expression('candidate.a == candidate.a').ast()
        self.assertEqual(tree["type"], "compare")

    def test_parsing_reports_no_truth_value(self):
        parsed = expr.parse_expression('candidate.a == "x"')
        for name in ("outcome", "result", "value", "settled", "truth"):
            self.assertFalse(hasattr(parsed, name))


if __name__ == "__main__":
    unittest.main()
