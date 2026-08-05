"""Closure Unit 1 — canonical serialization only.

Every expectation here is stated in spec/canonicalization.md or frozen in
fixtures/canonicalization/.
"""

import datetime
import decimal
import itertools
import json
import pathlib
import sys
import unicodedata
import unittest

from vfy import canon
from vfy.errors import (
    CanonicalFormInvalid,
    FloatNotPermitted,
    SurrogateNotPermitted,
    VerifyError,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CANON_DIR = REPO_ROOT / "fixtures" / "canonicalization"
CANON_CASE_1 = CANON_DIR / "canon_case_1.json"

HIGH_SURROGATE = chr(0xD834)
LOW_SURROGATE = chr(0xDD1E)
FIRST_SURROGATE = chr(0xD800)
LAST_SURROGATE = chr(0xDFFF)
BELOW_SURROGATES = chr(0xD7FF)
ABOVE_SURROGATES = chr(0xE000)
SUPPLEMENTARY_SCALAR = chr(0x1D11E)


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class CanonCase1(unittest.TestCase):
    """The frozen golden vector."""

    def setUp(self):
        self.case = json.loads(CANON_CASE_1.read_text(encoding="utf-8"))

    def test_canonical_text_matches_the_fixture(self):
        self.assertEqual(canon.canonicalize(self.case["input"]), self.case["canonical"])

    def test_frozen_digest_is_the_digest_of_the_fixture_canonical_text(self):
        # Derived from the fixture's own canonical string, so the frozen constant is
        # independent of canonicalize(). The two paths must agree.
        self.assertEqual(
            canon.hex_digest_of_text(self.case["canonical"]), self.case["sha256"]
        )

    def test_digest_of_the_input_carries_the_prefix(self):
        self.assertEqual(canon.digest(self.case["input"]), "sha256:" + self.case["sha256"])

    def test_frozen_digest_is_64_lowercase_hex_digits(self):
        self.assertRegex(self.case["sha256"], r"\A[0-9a-f]{64}\Z")

    def test_canonical_bytes_are_the_utf8_of_the_canonical_text(self):
        self.assertEqual(
            canon.canonical_bytes(self.case["input"]),
            self.case["canonical"].encode("utf-8"),
        )

    def test_canonical_bytes_carry_no_byte_order_mark(self):
        self.assertFalse(canon.canonical_bytes(self.case["input"]).startswith(b"\xef\xbb\xbf"))


class Determinism(unittest.TestCase):
    def test_insertion_order_does_not_change_the_bytes(self):
        one = {"b": 2, "a": {"z": "s", "m": ["1", "2"]}, "amount": "12.50"}
        other = {"amount": "12.50", "a": {"m": ["1", "2"], "z": "s"}, "b": 2}
        self.assertEqual(canon.canonicalize(one), canon.canonicalize(other))

    def test_canonicalizing_reparsed_canonical_text_is_stable(self):
        value = {"b": 2, "a": {"z": "s", "m": ["1", "2"]}, "amount": "12.50"}
        once = canon.canonicalize(value)
        self.assertEqual(canon.canonicalize(json.loads(once)), once)

    def test_repeated_calls_return_the_same_text(self):
        value = {"b": [1, 2], "a": "x"}
        self.assertEqual(canon.canonicalize(value), canon.canonicalize(value))

    def test_arrays_keep_their_order(self):
        self.assertEqual(canon.canonicalize(["b", "a", "c"]), '["b","a","c"]')

    def test_keys_sort_by_code_point_and_not_by_locale(self):
        self.assertEqual(canon.canonicalize({"Z": 1, "a": 2, "A": 3}), '{"A":3,"Z":1,"a":2}')

    def test_non_ascii_keys_sort_by_code_point_and_not_by_locale(self):
        self.assertEqual(canon.canonicalize({"é": 1, "z": 2}), '{"z":2,"é":1}')

    def test_nested_objects_are_sorted_at_every_depth(self):
        value = {"b": {"z": 1, "a": {"y": 1, "b": 2}}, "a": 1}
        self.assertEqual(canon.canonicalize(value), '{"a":1,"b":{"a":{"b":2,"y":1},"z":1}}')

    def test_no_insignificant_whitespace(self):
        self.assertEqual(
            canon.canonicalize({"a": [1, 2], "b": {"c": 3}}), '{"a":[1,2],"b":{"c":3}}'
        )

    def test_empty_containers(self):
        self.assertEqual(canon.canonicalize({"a": {}, "b": []}), '{"a":{},"b":[]}')


class Types(unittest.TestCase):
    def test_null(self):
        self.assertEqual(canon.canonicalize(None), "null")

    def test_booleans_are_not_written_as_integers(self):
        self.assertEqual(canon.canonicalize({"t": True, "f": False}), '{"f":false,"t":true}')

    def test_integers_have_no_sign_padding_or_exponent(self):
        self.assertEqual(canon.canonicalize([0, -1, 10, 1000000]), "[0,-1,10,1000000]")

    def test_largest_exactly_representable_integer_is_accepted(self):
        self.assertEqual(canon.canonicalize(canon.MAX_SAFE_INTEGER), "9007199254740991")

    def test_smallest_exactly_representable_integer_is_accepted(self):
        self.assertEqual(canon.canonicalize(canon.MIN_SAFE_INTEGER), "-9007199254740991")

    def test_integer_above_the_range_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid) as caught:
            canon.canonicalize(canon.MAX_SAFE_INTEGER + 1)
        self.assertEqual(caught.exception.code, "canonical_form_invalid")

    def test_integer_below_the_range_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid):
            canon.canonicalize(canon.MIN_SAFE_INTEGER - 1)


class Floats(unittest.TestCase):
    def test_a_float_is_refused(self):
        with self.assertRaises(FloatNotPermitted) as caught:
            canon.canonicalize(1.5)
        self.assertEqual(caught.exception.code, "float_not_permitted")

    def test_a_whole_valued_float_is_still_refused(self):
        with self.assertRaises(FloatNotPermitted):
            canon.canonicalize(2.0)

    def test_a_float_nested_in_an_object_is_refused(self):
        with self.assertRaises(FloatNotPermitted):
            canon.canonicalize({"amount": 12.50})

    def test_a_float_nested_in_an_array_is_refused(self):
        with self.assertRaises(FloatNotPermitted):
            canon.canonicalize(["ok", 0.1])

    def test_a_decimal_string_is_carried_through_untouched(self):
        self.assertEqual(canon.canonicalize({"amount": "12.50"}), '{"amount":"12.50"}')


class Escaping(unittest.TestCase):
    def test_quote_and_backslash(self):
        self.assertEqual(canon.canonicalize('a"b\\c'), '"a\\"b\\\\c"')

    def test_named_control_escapes(self):
        self.assertEqual(canon.canonicalize("\b\t\n\f\r"), '"\\b\\t\\n\\f\\r"')

    def test_other_c0_controls_use_four_lowercase_hex_digits(self):
        self.assertEqual(canon.canonicalize("\x00\x0b\x1f"), '"\\u0000\\u000b\\u001f"')

    def test_solidus_is_not_escaped(self):
        self.assertEqual(canon.canonicalize("./workspace/*"), '"./workspace/*"')

    def test_non_ascii_is_emitted_literally(self):
        self.assertEqual(canon.canonicalize("héllo"), '"héllo"')

    def test_non_ascii_survives_the_round_trip_to_bytes(self):
        self.assertEqual(canon.canonical_bytes("héllo"), b'"h\xc3\xa9llo"')

    def test_delete_is_not_a_c0_control_and_is_emitted_literally(self):
        self.assertEqual(canon.canonicalize("\x7f"), '"\x7f"')

    def test_keys_are_escaped_the_same_way_as_values(self):
        self.assertEqual(canon.canonicalize({'a"b': 1}), '{"a\\"b":1}')


class NonJsonInput(unittest.TestCase):
    def test_a_native_date_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid) as caught:
            canon.canonicalize({"adopted_at": datetime.date(2026, 8, 5)})
        self.assertEqual(caught.exception.code, "canonical_form_invalid")

    def test_a_native_datetime_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid):
            canon.canonicalize(datetime.datetime(2026, 8, 5, 0, 0, 0))

    def test_a_set_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid):
            canon.canonicalize({"a", "b"})

    def test_a_byte_string_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid):
            canon.canonicalize(b"bytes")

    def test_a_tuple_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid):
            canon.canonicalize(("a", "b"))

    def test_a_decimal_object_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid):
            canon.canonicalize(decimal.Decimal("12.50"))

    def test_a_non_string_key_is_refused(self):
        with self.assertRaises(CanonicalFormInvalid) as caught:
            canon.canonicalize({1: "a"})
        self.assertEqual(caught.exception.code, "canonical_form_invalid")

    def test_a_non_string_key_is_refused_before_any_output_is_committed(self):
        with self.assertRaises(CanonicalFormInvalid):
            canon.canonicalize({"a": 1, 2: "b"})


class CanonCaseVectors(unittest.TestCase):
    """Every canon_case_* vector, including the frozen case 1."""

    def test_every_case_vector_matches_its_frozen_canonical_text_and_digest(self):
        paths = sorted(CANON_DIR.glob("canon_case_*.json"))
        self.assertGreaterEqual(len(paths), 3)
        for path in paths:
            case = _load(path)
            with self.subTest(fixture=path.name):
                self.assertEqual(canon.canonicalize(case["input"]), case["canonical"])
                self.assertEqual(
                    canon.hex_digest_of_text(case["canonical"]), case["sha256"]
                )
                self.assertEqual(canon.digest(case["input"]), "sha256:" + case["sha256"])
                self.assertEqual(
                    canon.canonical_bytes(case["input"]),
                    case["canonical"].encode("utf-8"),
                )
                self.assertRegex(case["sha256"], r"\A[0-9a-f]{64}\Z")

    def test_every_case_vector_round_trips(self):
        for path in sorted(CANON_DIR.glob("canon_case_*.json")):
            case = _load(path)
            with self.subTest(fixture=path.name):
                text = canon.canonicalize(case["input"])
                raw = canon.canonical_bytes(case["input"])
                # canonical bytes decode as UTF-8
                self.assertEqual(raw.decode("utf-8"), text)
                # the canonical text parses back to the same canonical value
                reparsed = json.loads(text)
                # canonicalizing the parsed canonical JSON returns identical bytes. Stated this
                # way, not as canonicalize(canonicalize(v)): the second input would be a JSON
                # string, not the value.
                self.assertEqual(canon.canonicalize(reparsed), text)
                self.assertEqual(canon.canonical_bytes(reparsed), raw)
                # the digest matches the frozen canonical bytes
                self.assertEqual(
                    canon.digest(reparsed), "sha256:" + case["sha256"]
                )


class CanonRejectVectors(unittest.TestCase):
    """Every canon_reject_* vector: a value with no canonical form."""

    def test_every_reject_vector_raises_its_declared_code_in_the_error_class(self):
        paths = sorted(CANON_DIR.glob("canon_reject_*.json"))
        self.assertGreaterEqual(len(paths), 2)
        for path in paths:
            case = _load(path)
            with self.subTest(fixture=path.name):
                with self.assertRaises(Exception) as caught:
                    canon.canonicalize(case["input"])
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                self.assertEqual(caught.exception.outcome, case["expected"]["outcome"])
                self.assertEqual(case["expected"]["outcome"], "ERROR")

    def test_a_rejected_vector_declares_no_canonical_form_and_no_digest(self):
        for path in sorted(CANON_DIR.glob("canon_reject_*.json")):
            case = _load(path)
            with self.subTest(fixture=path.name):
                self.assertNotIn("canonical", case)
                self.assertNotIn("sha256", case)


class Surrogates(unittest.TestCase):
    """spec/canonicalization.md: no code point in U+D800-U+DFFF, in a key or a value."""

    def test_a_lone_high_surrogate_is_refused(self):
        with self.assertRaises(SurrogateNotPermitted) as caught:
            canon.canonicalize(HIGH_SURROGATE)
        self.assertEqual(caught.exception.code, "surrogate_not_permitted")

    def test_a_lone_low_surrogate_is_refused(self):
        with self.assertRaises(SurrogateNotPermitted):
            canon.canonicalize(LOW_SURROGATE)

    def test_both_ends_of_the_surrogate_range_are_refused(self):
        for value in (FIRST_SURROGATE, LAST_SURROGATE):
            with self.subTest(code_point=hex(ord(value))):
                with self.assertRaises(SurrogateNotPermitted):
                    canon.canonicalize(value)

    def test_code_points_adjacent_to_the_surrogate_range_are_accepted(self):
        self.assertEqual(canon.canonicalize(BELOW_SURROGATES), '"' + BELOW_SURROGATES + '"')
        self.assertEqual(canon.canonicalize(ABOVE_SURROGATES), '"' + ABOVE_SURROGATES + '"')

    def test_a_surrogate_in_an_object_key_is_refused(self):
        with self.assertRaises(SurrogateNotPermitted):
            canon.canonicalize({HIGH_SURROGATE: 1})

    def test_a_surrogate_nested_deep_in_a_value_is_refused(self):
        with self.assertRaises(SurrogateNotPermitted):
            canon.canonicalize({"a": [{"b": "text" + LOW_SURROGATE}]})

    def test_an_unjoined_surrogate_pair_in_a_python_string_is_refused(self):
        # A parser joins the escapes into one scalar. A string that still holds the two halves
        # has no UTF-8 representation and is not a canonical input.
        with self.assertRaises(SurrogateNotPermitted):
            canon.canonicalize(HIGH_SURROGATE + LOW_SURROGATE)

    def test_the_scalar_a_joined_pair_denotes_is_accepted(self):
        self.assertEqual(
            canon.canonicalize(SUPPLEMENTARY_SCALAR), '"' + SUPPLEMENTARY_SCALAR + '"'
        )

    def test_a_surrogate_is_never_repaired_into_an_accepted_value(self):
        # No replacement character, no \ud800 escape, no dropped code point: the call raises
        # instead of returning anything at all.
        for value in ("a" + HIGH_SURROGATE + "b", {"k": LOW_SURROGATE}, [FIRST_SURROGATE]):
            with self.subTest(value=ascii(value)):
                with self.assertRaises(SurrogateNotPermitted):
                    canon.canonicalize(value)
                with self.assertRaises(SurrogateNotPermitted):
                    canon.canonical_bytes(value)

    def test_unicode_encode_error_never_escapes_a_public_entry_point(self):
        entry_points = (
            ("canonicalize", lambda v: canon.canonicalize(v)),
            ("canonical_bytes", lambda v: canon.canonical_bytes(v)),
            ("digest", lambda v: canon.digest(v)),
            ("hex_digest_of_text", lambda v: canon.hex_digest_of_text(v)),
        )
        for name, call in entry_points:
            with self.subTest(entry_point=name):
                try:
                    call(HIGH_SURROGATE)
                except SurrogateNotPermitted as typed:
                    self.assertEqual(typed.code, "surrogate_not_permitted")
                    self.assertEqual(typed.outcome, "ERROR")
                    self.assertNotIsInstance(typed, UnicodeEncodeError)
                except UnicodeEncodeError:
                    self.fail(name + " leaked UnicodeEncodeError across the boundary")
                else:
                    self.fail(name + " accepted a surrogate")

    def test_the_typed_failure_is_error_and_never_hold_or_block(self):
        try:
            canon.canonicalize(HIGH_SURROGATE)
        except SurrogateNotPermitted as typed:
            self.assertEqual(typed.outcome, "ERROR")
            self.assertNotIn(typed.outcome, ("HOLD", "BLOCK", "ALLOW"))


def _deep_object(depth):
    value = {}
    for _ in range(depth):
        value = {"a": value}
    return value


class KeyOrdering(unittest.TestCase):
    """spec/canonicalization.md: scalar-value order, identical to UTF-8 byte order."""

    KEYS = ["A", "Z", "a", "e", chr(0x00DF), chr(0x00E9), chr(0xFFFD), chr(0x1D11E)]

    def test_scalar_value_order_equals_utf8_byte_order(self):
        by_scalar = sorted(self.KEYS)
        by_utf8 = sorted(self.KEYS, key=lambda key: key.encode("utf-8"))
        self.assertEqual(by_scalar, by_utf8)

    def test_utf16_order_differs_so_the_vector_actually_discriminates(self):
        # Without a key between U+E000 and U+FFFF the three candidate rules agree and prove
        # nothing. U+FFFD against a supplementary-plane key is what separates them.
        pair = [chr(0xFFFD), chr(0x1D11E)]
        by_utf16 = sorted(pair, key=lambda key: key.encode("utf-16-be"))
        self.assertEqual(sorted(pair), [chr(0xFFFD), chr(0x1D11E)])
        self.assertEqual(by_utf16, [chr(0x1D11E), chr(0xFFFD)])
        self.assertNotEqual(sorted(pair), by_utf16)

    def test_emitted_keys_appear_in_scalar_value_order(self):
        text = canon.canonicalize({key: 1 for key in self.KEYS})
        positions = [text.index('"' + key + '"') for key in sorted(self.KEYS)]
        self.assertEqual(positions, sorted(positions))

    def test_every_insertion_order_yields_the_same_bytes(self):
        items = [("b", 1), ("a", 2), (chr(0x00E9), 3), ("Z", 4), (chr(0x1D11E), 5)]
        expected = canon.canonicalize(dict(items))
        for order in itertools.permutations(items):
            with self.subTest(order=[key for key, _ in order]):
                self.assertEqual(canon.canonicalize(dict(order)), expected)


class Normalization(unittest.TestCase):
    """spec/canonicalization.md: no normalization, ever."""

    PRECOMPOSED = chr(0x00E9)
    DECOMPOSED = "e" + chr(0x0301)

    def test_the_two_forms_really_are_unicode_equivalent(self):
        # Proves the test below is meaningful rather than comparing two unrelated strings.
        self.assertEqual(
            unicodedata.normalize("NFC", self.DECOMPOSED), self.PRECOMPOSED
        )
        self.assertNotEqual(self.PRECOMPOSED, self.DECOMPOSED)

    def test_the_two_forms_canonicalize_to_different_bytes(self):
        self.assertNotEqual(
            canon.canonical_bytes(self.PRECOMPOSED), canon.canonical_bytes(self.DECOMPOSED)
        )
        self.assertNotEqual(
            canon.digest({"k": self.PRECOMPOSED}), canon.digest({"k": self.DECOMPOSED})
        )

    def test_the_two_forms_remain_distinct_object_members(self):
        both = {self.PRECOMPOSED: 1, self.DECOMPOSED: 2}
        self.assertEqual(len(both), 2)
        self.assertEqual(canon.canonicalize(both).count(":"), 2)

    def test_no_case_folding_or_trimming(self):
        self.assertEqual(canon.canonicalize(" A "), '" A "')
        self.assertNotEqual(canon.canonicalize("a"), canon.canonicalize("A"))


class LiteralCharacters(unittest.TestCase):
    """The characters a shim is most likely to escape wrongly."""

    def test_solidus_del_and_line_and_paragraph_separators_stay_literal(self):
        for code_point in (0x2F, 0x7F, 0x2028, 0x2029):
            character = chr(code_point)
            with self.subTest(code_point=hex(code_point)):
                self.assertEqual(canon.canonicalize(character), '"' + character + '"')
                self.assertNotIn("\\", canon.canonicalize(character))


class NestingAndSize(unittest.TestCase):
    """spec/canonicalization.md: no depth, size, length, or cardinality limit."""

    def test_deep_nesting_does_not_raise_an_untyped_recursion_error(self):
        try:
            text = canon.canonicalize(_deep_object(5000))
        except RecursionError:
            self.fail("canonicalization is bounded by the host recursion limit")
        self.assertEqual(text.count("{"), 5001)

    def test_acceptance_does_not_depend_on_the_host_recursion_limit(self):
        value = _deep_object(5000)
        original = sys.getrecursionlimit()
        first = canon.canonicalize(value)
        try:
            sys.setrecursionlimit(original * 4)
            second = canon.canonicalize(value)
        finally:
            sys.setrecursionlimit(original)
        self.assertEqual(first, second)

    def test_deep_arrays_and_wide_containers(self):
        deep_array = []
        for _ in range(5000):
            deep_array = [deep_array]
        self.assertEqual(canon.canonicalize(deep_array).count("["), 5001)
        wide = {("k%05d" % index): index for index in range(5000)}
        self.assertEqual(canon.canonicalize(wide).count(":"), 5000)
        self.assertEqual(canon.canonicalize(list(range(5000))).count(","), 4999)


class HostTypeBoundary(unittest.TestCase):
    """Host values that can reach the Python API but are not JSON values."""

    def test_every_prohibited_host_type_is_refused_with_a_typed_error(self):
        class Custom:
            pass

        prohibited = [
            ("float", 1.5),
            ("bytes", b"x"),
            ("bytearray", bytearray(b"x")),
            ("set", {"a"}),
            ("frozenset", frozenset(["a"])),
            ("tuple", ("a",)),
            ("datetime", datetime.datetime(2026, 8, 5)),
            ("date", datetime.date(2026, 8, 5)),
            ("decimal", decimal.Decimal("12.50")),
            ("complex", complex(1, 2)),
            ("custom object", Custom()),
        ]
        for name, value in prohibited:
            for position, wrap in (
                ("top level", lambda v: v),
                ("in an array", lambda v: [v]),
                ("in an object", lambda v: {"k": v}),
            ):
                with self.subTest(host_type=name, position=position):
                    with self.assertRaises(VerifyError) as caught:
                        canon.canonicalize(wrap(value))
                    self.assertEqual(caught.exception.outcome, "ERROR")
                    self.assertIn(
                        caught.exception.code,
                        ("float_not_permitted", "canonical_form_invalid"),
                    )

    def test_non_string_keys_of_several_types_are_refused(self):
        for key in (1, 1.5, None, True, ("a",)):
            with self.subTest(key=repr(key)):
                with self.assertRaises(CanonicalFormInvalid):
                    canon.canonicalize({key: "v"})

    def test_booleans_serialize_as_booleans_not_integers(self):
        self.assertEqual(canon.canonicalize([True, False]), "[true,false]")
        self.assertNotEqual(canon.canonicalize(True), canon.canonicalize(1))
        self.assertNotEqual(canon.canonicalize(False), canon.canonicalize(0))


if __name__ == "__main__":
    unittest.main()
