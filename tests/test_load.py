"""Closure Unit 3A — strict JSON loading only.

Every expectation is stated in spec/document-loading.md or frozen in fixtures/loading/.
"""

import base64
import datetime
import json
import pathlib
import sys
import unittest

import yaml

from vfy import canon, load
from vfy.errors import (
    CanonicalFormInvalid,
    FloatNotPermitted,
    SourceConstructUnsupported,
    SourceEncodingInvalid,
    SourceSyntaxInvalid,
    SourceTooDeep,
    VerifyError,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
LOADING_DIR = REPO_ROOT / "fixtures" / "loading"


def _load_fixture(path):
    case = json.loads(path.read_text(encoding="utf-8"))
    case["source"] = base64.b64decode(case["source_base64"])
    return case


class AcceptedSourceVectors(unittest.TestCase):
    def test_every_accepted_vector_loads_to_its_frozen_value_text_and_digest(self):
        paths = sorted(LOADING_DIR.glob("load_json_accept_*.json"))
        self.assertGreaterEqual(len(paths), 6)
        for path in paths:
            case = _load_fixture(path)
            with self.subTest(fixture=path.name):
                value = load.load_json_bytes(case["source"])
                self.assertEqual(value, case["value"])
                self.assertEqual(canon.canonicalize(value), case["canonical"])
                self.assertEqual(canon.digest(value), "sha256:" + case["sha256"])

    def test_every_accepted_vector_survives_load_canonicalize_reload(self):
        for path in sorted(LOADING_DIR.glob("load_json_accept_*.json")):
            case = _load_fixture(path)
            with self.subTest(fixture=path.name):
                value = load.load_json_bytes(case["source"])
                text = canon.canonicalize(value)
                # canonical text is itself loadable source, and loading it changes nothing
                reloaded = load.load_json_bytes(text.encode("utf-8"))
                self.assertEqual(reloaded, value)
                self.assertEqual(canon.canonicalize(reloaded), text)
                self.assertEqual(canon.canonical_bytes(reloaded), text.encode("utf-8"))

    def test_every_loaded_value_lies_inside_the_canonical_value_model(self):
        permitted = (dict, list, str, int, bool, type(None))
        for path in sorted(LOADING_DIR.glob("load_json_accept_*.json")):
            case = _load_fixture(path)
            with self.subTest(fixture=path.name):
                pending = [load.load_json_bytes(case["source"])]
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


class RejectedSourceVectors(unittest.TestCase):
    def test_every_rejected_vector_raises_its_declared_code_in_the_error_class(self):
        paths = sorted(LOADING_DIR.glob("load_json_reject_*.json"))
        self.assertGreaterEqual(len(paths), 16)
        for path in paths:
            case = _load_fixture(path)
            with self.subTest(fixture=path.name):
                with self.assertRaises(VerifyError) as caught:
                    load.load_json_bytes(case["source"])
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                self.assertEqual(caught.exception.outcome, case["expected"]["outcome"])
                self.assertEqual(case["expected"]["outcome"], "ERROR")

    def test_a_rejected_vector_declares_no_value_canonical_form_or_digest(self):
        for path in sorted(LOADING_DIR.glob("load_json_reject_*.json")):
            case = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(fixture=path.name):
                for absent in ("value", "canonical", "sha256"):
                    self.assertNotIn(absent, case)


class DuplicateKeys(unittest.TestCase):
    """The check the canonicalizer is forbidden to claim, because the duplicate is gone by then."""

    def test_a_duplicate_is_refused_at_every_depth(self):
        sources = [
            b'{"a":1,"a":2}',
            b'{"outer":{"a":1,"a":2}}',
            b'{"outer":{"inner":{"a":1,"a":2}}}',
            b'{"list":[{"a":1,"a":2}]}',
            b'{"list":[[[{"deep":{"a":1,"a":2}}]]]}',
        ]
        for source in sources:
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(CanonicalFormInvalid) as caught:
                    load.load_json_bytes(source)
                self.assertEqual(caught.exception.code, "canonical_form_invalid")

    def test_the_permissive_parser_really_would_have_lost_it(self):
        # Proves the check has to live here: by the time a mapping exists, the first member is
        # gone and no later stage could see the duplicate.
        self.assertEqual(json.loads('{"a":1,"a":2}'), {"a": 2})

    def test_distinct_keys_that_merely_look_similar_are_not_duplicates(self):
        value = load.load_json_bytes('{"e":1,"\\u00e9":2,"e\\u0301":3}'.encode("utf-8"))
        self.assertEqual(len(value), 3)


class EncodingBoundary(unittest.TestCase):
    def test_malformed_utf8_is_typed(self):
        for source in (b'{"a":"\xff"}', b'{"a":"\xc3"}', b'\x80{"a":1}'):
            with self.subTest(source=repr(source)):
                with self.assertRaises(SourceEncodingInvalid) as caught:
                    load.load_json_bytes(source)
                self.assertEqual(caught.exception.code, "source_encoding_invalid")

    def test_byte_order_marks_are_refused(self):
        for source in (b"\xef\xbb\xbf{\"a\":1}", b"\xff\xfe{\x00", b"\xfe\xff\x00{"):
            with self.subTest(source=repr(source)):
                with self.assertRaises(SourceEncodingInvalid):
                    load.load_json_bytes(source)

    def test_valid_non_ascii_source_is_preserved_exactly(self):
        value = load.load_json_bytes('{"k":"héllo"}'.encode("utf-8"))
        self.assertEqual(value, {"k": "héllo"})

    def test_the_boundary_takes_bytes_not_text(self):
        # A caller contract violation, not an input class: no reason code, not an ERROR outcome.
        with self.assertRaises(TypeError):
            load.load_json_bytes('{"a":1}')


class Bounds(unittest.TestCase):
    def test_nesting_at_the_declared_limit_is_accepted(self):
        source = (b"[" * load.MAX_DEPTH) + (b"]" * load.MAX_DEPTH)
        value = load.load_json_bytes(source)
        self.assertEqual(canon.canonicalize(value).count("["), load.MAX_DEPTH)

    def test_nesting_one_past_the_limit_is_refused(self):
        source = (b"[" * (load.MAX_DEPTH + 1)) + (b"]" * (load.MAX_DEPTH + 1))
        with self.assertRaises(SourceTooDeep) as caught:
            load.load_json_bytes(source)
        self.assertEqual(caught.exception.code, "source_too_deep")

    def test_object_nesting_is_bounded_the_same_way(self):
        source = (b'{"a":' * (load.MAX_DEPTH + 1)) + b"1" + (b"}" * (load.MAX_DEPTH + 1))
        with self.assertRaises(SourceTooDeep):
            load.load_json_bytes(source)

    def test_brackets_inside_strings_do_not_count_toward_depth(self):
        source = b'{"k":"[[[[[[[[[[ {{{{{{{{{{ \\" [[[[[ "}'
        self.assertEqual(load.load_json_bytes(source), {"k": '[[[[[[[[[[ {{{{{{{{{{ " [[[[[ '})

    def test_depth_rejection_does_not_depend_on_the_host_recursion_limit(self):
        source = (b"[" * 500) + (b"]" * 500)
        original = sys.getrecursionlimit()
        with self.assertRaises(SourceTooDeep):
            load.load_json_bytes(source)
        try:
            sys.setrecursionlimit(original * 4)
            with self.assertRaises(SourceTooDeep):
                load.load_json_bytes(source)
        finally:
            sys.setrecursionlimit(original)

    def test_no_recursion_error_escapes_for_deeply_nested_source(self):
        for depth in (100, 1000, 20000):
            with self.subTest(depth=depth):
                source = (b"[" * depth) + (b"]" * depth)
                try:
                    load.load_json_bytes(source)
                except SourceTooDeep:
                    pass
                except RecursionError:
                    self.fail("RecursionError crossed the public loader boundary")


class ParserExceptionContainment(unittest.TestCase):
    """No parser-library exception may reach the caller for a declared input class."""

    DECLARED_MALFORMED = [
        b"", b"   ", b"{", b"[1,", b'{"a"}', b"{'a':1}", b'{"a":1,}', b"[1,2,]",
        b'{"a":01}', b'{"a":+1}', b'{"a":.5}', b'{"a":1.}', b'{"a":undefined}',
        b'{"a":1} trailing', b'{"a":1}{"b":2}', b'{"n":NaN}', b'{"n":Infinity}',
        b'{"n":-Infinity}', b'{"n":1.5}', b'{"n":1e3}', b'{"n":9007199254740992}',
        b'{"a":1,"a":2}', b'{"s":"\\ud800"}', b'\xef\xbb\xbf{"a":1}', b'{"a":"\xff"}',
        b"[" * 200 + b"]" * 200,
    ]

    def test_only_typed_verify_errors_cross_the_boundary(self):
        for source in self.DECLARED_MALFORMED:
            with self.subTest(source=repr(source)[:60]):
                try:
                    load.load_json_bytes(source)
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                    self.assertIsNotNone(typed.code)
                    self.assertNotIsInstance(typed, json.JSONDecodeError)
                    self.assertNotIsInstance(typed, UnicodeDecodeError)
                    self.assertNotIsInstance(typed, ValueError)
                except Exception as untyped:
                    self.fail(
                        "%s crossed the boundary for %r"
                        % (type(untyped).__name__, source[:40])
                    )
                else:
                    self.fail("accepted malformed source %r" % source[:40])


class ValueModelBoundary(unittest.TestCase):
    def test_floats_never_enter_however_written(self):
        for source in (b'{"n":1.5}', b'{"n":1e3}', b'{"n":2.0}', b'{"n":-0.0}', b'{"n":1E-3}'):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(FloatNotPermitted) as caught:
                    load.load_json_bytes(source)
                self.assertEqual(caught.exception.code, "float_not_permitted")

    def test_non_json_constants_are_a_syntax_failure_not_a_value_failure(self):
        # Different fix from a float: the source is not JSON at all.
        for source in (b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}'):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(SourceSyntaxInvalid):
                    load.load_json_bytes(source)

    def test_integer_interval_ends(self):
        self.assertEqual(
            load.load_json_bytes(b'{"n":9007199254740991}'), {"n": canon.MAX_SAFE_INTEGER}
        )
        self.assertEqual(
            load.load_json_bytes(b'{"n":-9007199254740991}'), {"n": canon.MIN_SAFE_INTEGER}
        )
        for source in (b'{"n":9007199254740992}', b'{"n":-9007199254740992}'):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(CanonicalFormInvalid):
                    load.load_json_bytes(source)

    def test_a_lone_surrogate_escape_is_refused(self):
        for source in (b'{"s":"\\ud800"}', b'{"s":"\\udfff"}', b'{"\\ud800":1}'):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(VerifyError) as caught:
                    load.load_json_bytes(source)
                self.assertEqual(caught.exception.code, "surrogate_not_permitted")

    def test_a_paired_surrogate_escape_denotes_its_scalar_and_is_accepted(self):
        self.assertEqual(
            load.load_json_bytes(b'{"s":"\\ud834\\udd1e"}'), {"s": chr(0x1D11E)}
        )

    def test_booleans_stay_booleans_and_null_stays_null(self):
        value = load.load_json_bytes(b'{"t":true,"f":false,"n":null}')
        self.assertIs(value["t"], True)
        self.assertIs(value["f"], False)
        self.assertIsNone(value["n"])

    def test_no_normalization_is_applied_to_loaded_strings(self):
        value = load.load_json_bytes('{"a":"\\u00e9","b":"e\\u0301"}'.encode("utf-8"))
        self.assertNotEqual(value["a"], value["b"])


YAML_LOADERS = [("pure-Python", yaml.SafeLoader)]
if getattr(yaml, "__with_libyaml__", False):
    YAML_LOADERS.append(("libyaml", yaml.CSafeLoader))

TEMPLATES = REPO_ROOT / "templates"


class AcceptedYamlVectors(unittest.TestCase):
    def test_every_accepted_vector_loads_to_its_frozen_value_text_and_digest(self):
        paths = sorted(LOADING_DIR.glob("load_yaml_accept_*.json"))
        self.assertGreaterEqual(len(paths), 9)
        for path in paths:
            case = _load_fixture(path)
            for label, loader in YAML_LOADERS:
                with self.subTest(fixture=path.name, parser=label):
                    value = load.load_yaml_bytes(case["source"], _loader_class=loader)
                    self.assertEqual(value, case["value"])
                    self.assertEqual(canon.canonicalize(value), case["canonical"])
                    self.assertEqual(canon.digest(value), "sha256:" + case["sha256"])

    def test_every_loaded_yaml_value_lies_inside_the_canonical_value_model(self):
        permitted = (dict, list, str, int, bool, type(None))
        for path in sorted(LOADING_DIR.glob("load_yaml_accept_*.json")):
            case = _load_fixture(path)
            with self.subTest(fixture=path.name):
                pending = [load.load_yaml_bytes(case["source"])]
                while pending:
                    item = pending.pop()
                    self.assertIsInstance(item, permitted)
                    self.assertNotIsInstance(item, (float, datetime.date, bytes, set, tuple))
                    if isinstance(item, dict):
                        for key, member in item.items():
                            self.assertIsInstance(key, str)
                            pending.append(member)
                    elif isinstance(item, list):
                        pending.extend(item)


class RejectedYamlVectors(unittest.TestCase):
    def test_every_rejected_vector_raises_its_declared_code_under_both_parsers(self):
        paths = sorted(LOADING_DIR.glob("load_yaml_reject_*.json"))
        self.assertGreaterEqual(len(paths), 46)
        for path in paths:
            case = _load_fixture(path)
            for label, loader in YAML_LOADERS:
                with self.subTest(fixture=path.name, parser=label):
                    with self.assertRaises(VerifyError) as caught:
                        load.load_yaml_bytes(case["source"], _loader_class=loader)
                    self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                    self.assertEqual(caught.exception.outcome, "ERROR")


class CurrentTemplates(unittest.TestCase):
    def test_all_three_templates_load_under_the_strict_subset(self):
        paths = sorted(TEMPLATES.glob("*.yaml"))
        self.assertEqual(len(paths), 3)
        for path in paths:
            for label, loader in YAML_LOADERS:
                with self.subTest(template=path.name, parser=label):
                    value = load.load_yaml_bytes(path.read_bytes(), _loader_class=loader)
                    self.assertIsInstance(value, dict)
                    self.assertIn("rulebook_id", value)
                    self.assertIn("rules", value)

    def test_templates_canonicalize_identically_under_both_parsers(self):
        for path in sorted(TEMPLATES.glob("*.yaml")):
            digests = {
                canon.digest(load.load_yaml_bytes(path.read_bytes(), _loader_class=loader))
                for _label, loader in YAML_LOADERS
            }
            with self.subTest(template=path.name):
                self.assertEqual(len(digests), 1)

    def test_no_template_value_is_a_parser_specific_type(self):
        for path in sorted(TEMPLATES.glob("*.yaml")):
            pending = [load.load_yaml_bytes(path.read_bytes())]
            while pending:
                item = pending.pop()
                self.assertNotIsInstance(item, (float, datetime.date, bytes, set, tuple))
                if isinstance(item, dict):
                    pending.extend(item.values())
                elif isinstance(item, list):
                    pending.extend(item)


class PlainScalarStyleTrap(unittest.TestCase):
    """A plain scalar is style None under one parser and "" under the other."""

    def test_both_spellings_of_plain_are_recognised(self):
        self.assertIn(None, load._PLAIN_STYLES)
        self.assertIn("", load._PLAIN_STYLES)

    def test_the_two_parsers_disagree_about_plain_style(self):
        if len(YAML_LOADERS) < 2:
            self.skipTest("libyaml not available on this host")
        styles = set()
        for _label, loader in YAML_LOADERS:
            for event in yaml.parse("a: 1\n", Loader=loader):
                if isinstance(event, yaml.ScalarEvent):
                    styles.add(event.style)
        # If this ever collapses to one value the trap is gone, but the loader stays correct.
        self.assertTrue(styles.issubset({None, ""}))

    def test_a_plain_true_is_a_boolean_under_both_parsers(self):
        for label, loader in YAML_LOADERS:
            with self.subTest(parser=label):
                value = load.load_yaml_bytes(b"k: true\nn: 5\n", _loader_class=loader)
                self.assertIs(value["k"], True)
                self.assertIsInstance(value["n"], int)


class YamlScalarTyping(unittest.TestCase):
    def test_only_lowercase_true_false_null_are_typed(self):
        value = load.load_yaml_bytes(b"a: true\nb: false\nc: null\n")
        self.assertEqual(value, {"a": True, "b": False, "c": None})

    def test_every_other_boolean_and_null_spelling_is_refused(self):
        for token in ("True", "False", "TRUE", "FALSE", "yes", "Yes", "YES", "no", "No",
                      "NO", "on", "On", "ON", "off", "Off", "OFF", "~", "Null", "NULL"):
            with self.subTest(token=token):
                with self.assertRaises(SourceConstructUnsupported):
                    load.load_yaml_bytes(("k: " + token + "\n").encode("utf-8"))

    def test_single_letters_y_and_n_are_ordinary_strings(self):
        value = load.load_yaml_bytes(b"y: n\nn: y\n")
        self.assertEqual(value, {"y": "n", "n": "y"})

    def test_non_canonical_integer_notation_is_refused(self):
        for token in ("0x1F", "0o17", "017", "0b101", "1:30", "+1", "01", "-01"):
            with self.subTest(token=token):
                with self.assertRaises(SourceConstructUnsupported):
                    load.load_yaml_bytes(("k: " + token + "\n").encode("utf-8"))

    def test_timestamps_are_refused_and_never_become_dates(self):
        for token in ("2026-08-05", "2026-08-05T00:00:00Z", "2026-8-5 12:30:00"):
            with self.subTest(token=token):
                with self.assertRaises(SourceConstructUnsupported):
                    load.load_yaml_bytes(("k: " + token + "\n").encode("utf-8"))

    def test_floats_and_non_finite_forms_are_refused_as_floats(self):
        for token in ("1.5", "1e3", "1E3", "1.0e3", "-1.5", ".inf", "-.inf", "+.inf",
                      ".nan", ".NaN", ".INF"):
            with self.subTest(token=token):
                with self.assertRaises(FloatNotPermitted):
                    load.load_yaml_bytes(("k: " + token + "\n").encode("utf-8"))

    def test_canonical_integers_and_the_interval(self):
        self.assertEqual(load.load_yaml_bytes(b"k: 0\n"), {"k": 0})
        self.assertEqual(load.load_yaml_bytes(b"k: -1\n"), {"k": -1})
        self.assertEqual(
            load.load_yaml_bytes(b"k: 9007199254740991\n"), {"k": canon.MAX_SAFE_INTEGER}
        )
        with self.assertRaises(CanonicalFormInvalid):
            load.load_yaml_bytes(b"k: 9007199254740992\n")

    def test_ordinary_punctuated_scalars_stay_strings(self):
        source = (b"a: 1.0.0\nb: ./claim/authority.json\nc: .vfy/approvals.json\n"
                  b"d: https://api.internal.example/coverage\ne: ALLOW\n"
                  b"f: Tests green on main within freshness bound.\n"
                  b"g: Coverage excludes this category. This is a denial, not an unknown.\n")
        value = load.load_yaml_bytes(source)
        for member in value.values():
            self.assertIsInstance(member, str)
        self.assertEqual(value["a"], "1.0.0")

    def test_quoted_scalars_are_always_strings(self):
        value = load.load_yaml_bytes(b'a: "12.50"\nb: \'true\'\nc: "2026-08-05"\nd: "1e3"\n')
        self.assertEqual(value, {"a": "12.50", "b": "true", "c": "2026-08-05", "d": "1e3"})


class BlockScalars(unittest.TestCase):
    EXPECTED = {
        "clip_lit": "a\nb\n", "strip_lit": "a\nb", "keep_lit": "a\nb\n\n",
        "clip_fold": "a b\n", "strip_fold": "a b", "keep_fold": "a b\n\n",
    }

    def test_all_six_chomping_forms_produce_their_exact_strings(self):
        source = (b"clip_lit: |\n  a\n  b\nstrip_lit: |-\n  a\n  b\nkeep_lit: |+\n  a\n  b\n\n"
                  b"clip_fold: >\n  a\n  b\nstrip_fold: >-\n  a\n  b\nkeep_fold: >+\n  a\n  b\n\n")
        for label, loader in YAML_LOADERS:
            with self.subTest(parser=label):
                self.assertEqual(load.load_yaml_bytes(source, _loader_class=loader), self.EXPECTED)

    def test_folding_replaces_a_line_break_with_a_space_and_clip_keeps_one_newline(self):
        self.assertEqual(self.EXPECTED["clip_fold"], "a b\n")
        self.assertEqual(self.EXPECTED["clip_lit"], "a\nb\n")

    def test_the_claims_gate_description_keeps_its_trailing_newline(self):
        value = load.load_yaml_bytes((TEMPLATES / "claims-gate.yaml").read_bytes())
        description = value["description"]
        self.assertTrue(description.endswith("guessing.\n"))
        self.assertNotIn("\n", description[:-1])
        self.assertIn("authority, fresh documentation", description)


class YamlStructuralSubset(unittest.TestCase):
    def test_duplicate_keys_refused_at_every_depth(self):
        for source in (b"a: 1\na: 2\n",
                       b"o:\n  a: 1\n  a: 2\n",
                       b"o:\n  i:\n    a: 1\n    a: 2\n",
                       b"l:\n  - a: 1\n    a: 2\n",
                       b"o: {a: 1, a: 2}\n"):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(CanonicalFormInvalid):
                    load.load_yaml_bytes(source)

    def test_non_string_keys_refused(self):
        for source in (b"1: a\n", b"true: a\n", b"null: a\n", b"-5: a\n"):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(CanonicalFormInvalid):
                    load.load_yaml_bytes(source)

    def test_anchors_aliases_and_merge_keys_refused(self):
        for source in (b"k: &A 1\n", b"a: &A 1\nb: *A\n", b"d:\n  <<: {b: 2}\n",
                       b"a: &A\n  b: *A\n"):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(SourceConstructUnsupported):
                    load.load_yaml_bytes(source)

    def test_explicit_tags_refused(self):
        for source in (b"k: !!int 7\n", b"k: !!str 7\n", b"k: !!timestamp 2026-08-05\n",
                       b"k: !!binary aGk=\n", b"k: !custom v\n", b"!!set\n? a\n",
                       b"k: !!omap\n- a: 1\n", b"k: !!pairs\n- a: 1\n"):
            with self.subTest(source=source.decode("ascii")):
                with self.assertRaises(SourceConstructUnsupported):
                    load.load_yaml_bytes(source)

    def test_document_structure(self):
        with self.assertRaises(SourceSyntaxInvalid):
            load.load_yaml_bytes(b"")
        with self.assertRaises(SourceSyntaxInvalid):
            load.load_yaml_bytes(b"---\n")
        with self.assertRaises(SourceSyntaxInvalid):
            load.load_yaml_bytes(b"a: 1\n---\nb: 2\n")
        with self.assertRaises(SourceConstructUnsupported):
            load.load_yaml_bytes(b"- a\n- b\n")

    def test_comments_and_whitespace_carry_no_meaning(self):
        with_comments = load.load_yaml_bytes(
            b"# top\n\na: 1  # trailing\n\n# mid\nb:\n  - x\n\n"
        )
        without = load.load_yaml_bytes(b"a: 1\nb:\n  - x\n")
        self.assertEqual(with_comments, without)
        self.assertEqual(canon.digest(with_comments), canon.digest(without))

    def test_yaml_depth_bound(self):
        at_limit = b"a: " + b"[" * (load.MAX_DEPTH - 1) + b"]" * (load.MAX_DEPTH - 1) + b"\n"
        load.load_yaml_bytes(at_limit)
        past = b"a: " + b"[" * load.MAX_DEPTH + b"]" * load.MAX_DEPTH + b"\n"
        with self.assertRaises(SourceTooDeep):
            load.load_yaml_bytes(past)

    def test_yaml_depth_bound_does_not_depend_on_the_host_recursion_limit(self):
        past = b"a: " + b"[" * 200 + b"]" * 200 + b"\n"
        original = sys.getrecursionlimit()
        with self.assertRaises(SourceTooDeep):
            load.load_yaml_bytes(past)
        try:
            sys.setrecursionlimit(original * 4)
            with self.assertRaises(SourceTooDeep):
                load.load_yaml_bytes(past)
        finally:
            sys.setrecursionlimit(original)

    def test_yaml_encoding_boundary(self):
        with self.assertRaises(SourceEncodingInvalid):
            load.load_yaml_bytes(b'k: "\xff"\n')
        with self.assertRaises(SourceEncodingInvalid):
            load.load_yaml_bytes(b"\xef\xbb\xbfa: 1\n")

    def test_the_yaml_boundary_takes_bytes_not_text(self):
        with self.assertRaises(TypeError):
            load.load_yaml_bytes("a: 1\n")


class YamlParserExceptionContainment(unittest.TestCase):
    MALFORMED = [
        b"", b"---\n", b"a: [1, 2\n", b"a:\n\tb: 1\n", b"a: 1\n---\nb: 2\n", b"- a\n",
        b"{", b"a: *missing\n", b"a: !!int notanint\n", b"a: 1\na: 2\n", b"1: a\n",
        b"k: 2026-08-05\n", b"k: 1.5\n", b"k: 0x1F\n", b"k: ~\n", b"k:\n",
        b"\xef\xbb\xbfa: 1\n", b'k: "\xff"\n', b"a: " + b"[" * 200 + b"]" * 200 + b"\n",
    ]

    def test_no_untyped_pyyaml_exception_crosses_the_boundary(self):
        for label, loader in YAML_LOADERS:
            for source in self.MALFORMED:
                with self.subTest(parser=label, source=repr(source)[:50]):
                    try:
                        load.load_yaml_bytes(source, _loader_class=loader)
                    except VerifyError as typed:
                        self.assertEqual(typed.outcome, "ERROR")
                        self.assertIsNotNone(typed.code)
                        self.assertNotIsInstance(typed, yaml.YAMLError)
                    except Exception as untyped:
                        self.fail("%s crossed the boundary for %r"
                                  % (type(untyped).__name__, source[:40]))
                    else:
                        self.fail("accepted malformed source %r" % source[:40])


class JsonYamlSemanticEquivalence(unittest.TestCase):
    """The same document written in either format must mean the same thing."""

    PAIRS = [
        (b'{"t":true,"f":false,"n":null}', b"t: true\nf: false\nn: null\n"),
        (b'{"a":{"z":1},"b":[1,2]}', b"a:\n  z: 1\nb:\n  - 1\n  - 2\n"),
        (b'{"amount":"12.50","version":"1.0.0"}', b'amount: "12.50"\nversion: 1.0.0\n'),
        (b'{"max":9007199254740991}', b"max: 9007199254740991\n"),
        (b'{"s":"h\\u00e9llo"}', b"s: h\xc3\xa9llo\n"),
    ]

    def test_equivalent_sources_produce_identical_values_and_digests(self):
        for json_source, yaml_source in self.PAIRS:
            with self.subTest(json=json_source.decode("utf-8")):
                from_json = load.load_json_bytes(json_source)
                from_yaml = load.load_yaml_bytes(yaml_source)
                self.assertEqual(from_json, from_yaml)
                self.assertEqual(canon.canonicalize(from_json), canon.canonicalize(from_yaml))
                self.assertEqual(canon.digest(from_json), canon.digest(from_yaml))

    def test_yaml_canonical_text_reloads_as_json_unchanged(self):
        for path in sorted(LOADING_DIR.glob("load_yaml_accept_*.json")):
            case = _load_fixture(path)
            with self.subTest(fixture=path.name):
                value = load.load_yaml_bytes(case["source"])
                text = canon.canonicalize(value)
                reloaded = load.load_json_bytes(text.encode("utf-8"))
                self.assertEqual(reloaded, value)
                self.assertEqual(canon.canonicalize(reloaded), text)


if __name__ == "__main__":
    unittest.main()
