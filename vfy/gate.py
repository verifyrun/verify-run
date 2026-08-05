"""Deterministic evaluation, per spec/evaluation.md.

A pinned rulebook, a validated candidate, and a frozen evidence snapshot in; one ALLOW, BLOCK,
HOLD, or ERROR out, with an ordered reason trace.

CLAUDE.md names this module and its law: the evaluator is a PURE FUNCTION. No clock, no
randomness, no filesystem, no network, no float comparisons, no environment reads, no locale or
timezone dependence, stable iteration order. Nothing is authorized, signed, persisted, or actuated.
"""

import re
from dataclasses import dataclass

from vfy import canon, expr, load, rulebook, schema
from vfy.errors import VerifyError

EVALUATOR_VERSION = 1
OUTCOME_SCHEMA_ID = "https://verifyrun.com/spec/v1/outcome.schema.json"
CANDIDATE_SCHEMA_ID = "https://verifyrun.com/spec/v1/candidate.schema.json"
SNAPSHOT_SCHEMA_ID = "https://verifyrun.com/spec/v1/evidence.schema.json"

TRUE = "true"
FALSE = "false"
UNSETTLED = "unsettled"


class _Absent:
    """A path that does not resolve. A settled fact, never an unknown."""

    def __repr__(self):
        return "ABSENT"


ABSENT = _Absent()

_DECIMAL = re.compile(r"\A(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?\Z")

_FIXED_MESSAGES = {
    "evidence_unsettled": "Evidence could not settle this rule.",
    "operand_unsettled": "An operand could not settle this rule.",
    "default_outcome_block": "No rule matched.",
    "default_outcome_hold": "No rule matched.",
}
_RULE_CODES = {"ALLOW": "rule_allow", "BLOCK": "rule_block", "HOLD": "rule_hold"}
_DEFAULT_CODES = {"BLOCK": "default_outcome_block", "HOLD": "default_outcome_hold"}


@dataclass(frozen=True)
class EvaluationResult:
    """One terminal result. Canonical text is the authority; `value()` rebuilds a fresh copy."""

    canonical: str
    outcome: str

    @property
    def canonical_bytes(self):
        return self.canonical.encode("utf-8")

    def value(self):
        return load.load_json_bytes(self.canonical_bytes)


def evaluate(pinned, candidate, snapshot, registry):
    """Return the terminal result for one candidate against one pinned rulebook and snapshot."""
    if not isinstance(candidate, dict) or not isinstance(snapshot, dict):
        raise TypeError("evaluate takes canonical mappings for candidate and snapshot")

    failure = _prepare(pinned, candidate, snapshot, registry)
    if failure is not None:
        return _result(registry, "ERROR", [failure], None, None)

    context = _Context(pinned.value(), candidate, snapshot)
    return _walk(context, registry)


def _prepare(pinned, candidate, snapshot, registry):
    """Run the fixed preparation order; return the first failure reason or None."""
    for value, schema_id in ((candidate, CANDIDATE_SCHEMA_ID), (snapshot, SNAPSHOT_SCHEMA_ID)):
        try:
            schema.validate(value, schema_id, registry)
        except VerifyError as invalid:
            return {"code": invalid.code, "message": str(invalid)}

    frozen_at = snapshot["frozen_at"]
    for item in snapshot["items"]:
        if rulebook._instant(item["acquired_at"]) > rulebook._instant(frozen_at):
            return {"code": "evidence_order_invalid",
                    "message": "Evidence was acquired after the freeze.",
                    "evidence_id": item["id"]}

    if not rulebook.rulebook_applies(pinned, frozen_at):
        return {"code": "rulebook_not_adopted",
                "message": "The rulebook was not adopted when this run started."}

    for rule in pinned.value()["rules"]:
        try:
            parsed = expr.parse_expression(rule["when"])
            expr.validate_expression(parsed, pinned)
        except VerifyError as invalid:
            return {"code": invalid.code, "message": str(invalid), "rule_id": rule["id"]}
    return None


class _Context:
    """Immutable view of the recorded inputs. Nothing here is written."""

    def __init__(self, rulebook_value, candidate, snapshot):
        self.rulebook = rulebook_value
        self.candidate = candidate
        self.snapshot = snapshot
        self.declarations = {d["id"]: d for d in rulebook_value["evidence"]}
        self.items = {i["id"]: i for i in snapshot["items"]}
        self.frozen_at = rulebook._instant(snapshot["frozen_at"])
        self.unsettled_causes = []

    def note(self, code, **fields):
        entry = dict(fields)
        entry["code"] = code
        if entry not in self.unsettled_causes:
            self.unsettled_causes.append(entry)


def _walk(context, registry):
    trace = []
    for ordinal, rule in enumerate(context.rulebook["rules"]):
        context.unsettled_causes = []
        state = _rule_state(context, rule)
        trace.append("%d:%s:%s" % (ordinal, rule["id"], state))
        if state == TRUE:
            outcome = rule["outcome"]
            reason = {"code": _RULE_CODES[outcome], "message": rule["reason"],
                      "rule_id": rule["id"]}
            return _result(registry, outcome, [reason], rule["id"], trace)
        if state == UNSETTLED:
            reasons = []
            for cause in context.unsettled_causes:
                reason = {"code": cause["code"], "message": _FIXED_MESSAGES[cause["code"]],
                          "rule_id": rule["id"]}
                if "evidence_id" in cause:
                    reason["evidence_id"] = cause["evidence_id"]
                reasons.append(reason)
            return _result(registry, "HOLD", reasons, None, trace)

    outcome = context.rulebook["default_outcome"]
    code = _DEFAULT_CODES[outcome]
    return _result(registry, outcome, [{"code": code, "message": _FIXED_MESSAGES[code]}],
                   None, trace)


def _rule_state(context, rule):
    for identifier in rule.get("requires_evidence", []):
        item = context.items.get(identifier)
        if item is None or item["status"] != "ok":
            context.note("evidence_unsettled", evidence_id=identifier)
            return UNSETTLED
    return _evaluate_node(context, expr.parse_expression(rule["when"]).ast(), rule["id"])


# --- expression evaluation --------------------------------------------------------------------

def _evaluate_node(context, node, rule_id):
    kind = node["type"]
    if kind == "and":
        return _combine(context, node["operands"], rule_id, all_true=True)
    if kind == "or":
        return _combine(context, node["operands"], rule_id, all_true=False)
    if kind == "not":
        inner = _evaluate_node(context, node["operand"], rule_id)
        if inner == UNSETTLED:
            return UNSETTLED
        return FALSE if inner == TRUE else TRUE
    if kind == "present":
        return TRUE if _item_ok(context, node["evidence_id"]) else FALSE
    if kind == "fresh":
        return TRUE if _is_fresh(context, node["evidence_id"]) else FALSE
    if kind == "matches":
        return _evaluate_matches(context, node, rule_id)
    if kind == "membership":
        return _evaluate_membership(context, node, rule_id)
    if kind == "compare":
        return _evaluate_compare(context, node, rule_id)
    raise AssertionError("unknown node type: " + kind)


def _combine(context, operands, rule_id, all_true):
    """Evaluate every operand left to right; unsettled is absorbing, never short-circuited."""
    states = [_evaluate_node(context, operand, rule_id) for operand in operands]
    if UNSETTLED in states:
        return UNSETTLED
    if all_true:
        return TRUE if all(state == TRUE for state in states) else FALSE
    return TRUE if any(state == TRUE for state in states) else FALSE


def _evaluate_compare(context, node, rule_id):
    left = _resolve(context, node["left"], rule_id)
    right = _resolve(context, node["right"], rule_id)
    if left is UNSETTLED or right is UNSETTLED:
        return UNSETTLED
    operator = node["operator"]
    if operator in ("==", "!="):
        equal = _equal(left, right)
        return TRUE if (equal if operator == "==" else not equal) else FALSE

    order = _compare_numeric(left, right)
    if order is None:
        context.note("operand_unsettled")
        return UNSETTLED
    if operator == "<":
        settled = order < 0
    elif operator == "<=":
        settled = order <= 0
    elif operator == ">":
        settled = order > 0
    else:
        settled = order >= 0
    return TRUE if settled else FALSE


def _evaluate_membership(context, node, rule_id):
    operand = _resolve(context, node["operand"], rule_id)
    if operand is UNSETTLED:
        return UNSETTLED
    members = node["list"]["value"]
    found = any(_equal(operand, member) for member in members)
    if node["operator"] == "in":
        return TRUE if found else FALSE
    return FALSE if found else TRUE


def _evaluate_matches(context, node, rule_id):
    value = _resolve(context, node["path"], rule_id)
    if value is UNSETTLED:
        return UNSETTLED
    if value is ABSENT:
        return FALSE
    if not isinstance(value, str):
        context.note("operand_unsettled")
        return UNSETTLED
    return TRUE if _glob(node["pattern"], value) else FALSE


def _resolve(context, node, rule_id):
    if node["type"] == "literal":
        return node["value"]
    root = node["root"]
    segments = node["segments"]
    if root == "evidence":
        identifier = segments[0]["member"]
        item = context.items.get(identifier)
        if item is None or item["status"] != "ok" or "value" not in item:
            context.note("evidence_unsettled", evidence_id=identifier)
            return UNSETTLED
        return _descend(item["value"], segments[1:])
    if root == "identity":
        return _descend(context.candidate.get("identity", ABSENT), segments)
    return _descend(context.candidate, segments)


def _descend(value, segments):
    for segment in segments:
        if value is ABSENT:
            return ABSENT
        if "member" in segment:
            if not isinstance(value, dict) or segment["member"] not in value:
                return ABSENT
            value = value[segment["member"]]
        else:
            index = segment["index"]
            if not isinstance(value, list) or index >= len(value):
                return ABSENT
            value = value[index]
    return value


# --- evidence ---------------------------------------------------------------------------------

def _item_ok(context, identifier):
    item = context.items.get(identifier)
    return item is not None and item["status"] == "ok"


def _is_fresh(context, identifier):
    if not _item_ok(context, identifier):
        return False
    declaration = context.declarations.get(identifier, {})
    if "max_age_seconds" not in declaration:
        return True
    acquired = rulebook._instant(context.items[identifier]["acquired_at"])
    age_nanoseconds = context.frozen_at - acquired
    return age_nanoseconds <= declaration["max_age_seconds"] * 1000000000


# --- exact values -----------------------------------------------------------------------------

def _equal(left, right):
    """Exact canonical equality. Never coerces; a boolean is never an integer."""
    if left is ABSENT or right is ABSENT:
        return left is ABSENT and right is ABSENT
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, (dict, list)) or isinstance(right, (dict, list)):
        return type(left) is type(right) and left == right
    return type(left) is type(right) and left == right


def _numeric_parts(value):
    """Return (sign, digits, scale) for an exact numeric, or None. No float is ever built."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return (-1 if value < 0 else 1, abs(value), 0)
    if not isinstance(value, str):
        return None
    match = _DECIMAL.match(value)
    if match is None:
        return None
    sign, whole, fraction = match.group(1), match.group(2), match.group(3) or ""
    digits = int(whole + fraction) if fraction else int(whole)
    return (-1 if sign == "-" and digits != 0 else 1, digits, len(fraction))


def _compare_numeric(left, right):
    """Return -1, 0, 1 by exact integer arithmetic, or None when either side is not numeric."""
    first, second = _numeric_parts(left), _numeric_parts(right)
    if first is None or second is None:
        return None
    scale = max(first[2], second[2])
    left_units = first[0] * first[1] * 10 ** (scale - first[2])
    right_units = second[0] * second[1] * 10 ** (scale - second[2])
    if left_units < right_units:
        return -1
    return 0 if left_units == right_units else 1


# --- portable glob ----------------------------------------------------------------------------

def _glob(pattern, text):
    """Whole-string, case-sensitive glob. Implemented directly: no regex, no platform fnmatch."""
    return _glob_from(pattern, 0, text, 0)


def _glob_from(pattern, p, text, t):
    while p < len(pattern):
        character = pattern[p]
        if character == "*":
            for skip in range(t, len(text) + 1):
                if _glob_from(pattern, p + 1, text, skip):
                    return True
            return False
        if t >= len(text):
            return False
        if character == "?":
            p += 1
            t += 1
            continue
        if character == "[":
            end = _class_end(pattern, p)
            if end is None:            # an unclosed [ is a literal [
                if text[t] != "[":
                    return False
                p += 1
                t += 1
                continue
            if not _in_class(pattern[p + 1:end], text[t]):
                return False
            p = end + 1
            t += 1
            continue
        if text[t] != character:
            return False
        p += 1
        t += 1
    return t == len(text)


def _class_end(pattern, start):
    index = start + 1
    if index < len(pattern) and pattern[index] == "!":
        index += 1
    if index < len(pattern) and pattern[index] == "]":
        index += 1
    while index < len(pattern):
        if pattern[index] == "]":
            return index
        index += 1
    return None


def _in_class(body, character):
    negated = body.startswith("!")
    if negated:
        body = body[1:]
    matched = False
    index = 0
    while index < len(body):
        if index + 2 < len(body) and body[index + 1] == "-":
            if body[index] <= character <= body[index + 2]:
                matched = True
            index += 3
        else:
            if body[index] == character:
                matched = True
            index += 1
    return matched != negated


# --- result -----------------------------------------------------------------------------------

def _result(registry, outcome, reasons, matched_rule, trace):
    document = {"outcome": outcome, "reasons": reasons}
    if matched_rule is not None:
        document["matched_rule"] = matched_rule
    if trace is not None:
        document["trace"] = trace
    schema.validate(document, OUTCOME_SCHEMA_ID, registry)
    return EvaluationResult(canonical=canon.canonicalize(document), outcome=outcome)
