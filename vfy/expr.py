"""Expression parsing and static validation, per spec/expression-language.md.

A `when` string becomes one deterministic, immutable, language-neutral tree. Nothing is evaluated:
no candidate, evidence, or identity value is resolved, nothing is settled, and no outcome is
produced. This completes spec/execution-chain.md step 2.

Pure: no filesystem, no network, no clock, no environment, no randomness, no locale.
"""

import re
from dataclasses import dataclass

from vfy import canon, load
from vfy.errors import (
    ExpressionParseError,
    ExpressionTypeError,
    SurrogateNotPermitted,
    UndeclaredEvidenceId,
)

EXPRESSION_PARSER_VERSION = 1

# Parenthesis nesting is bounded so that a deeply nested source is refused with a typed failure
# instead of exhausting the host stack, whose limit is mutable and would otherwise decide
# acceptance differently on different machines. Same number the document loader declares.
MAX_NESTING = 64

PATH_ROOTS = ("candidate", "evidence", "identity")
FUNCTIONS = ("fresh", "present", "matches")
KEYWORDS = frozenset(["and", "or", "not", "in", "true", "false"]) | frozenset(FUNCTIONS)
COMPARISON_OPERATORS = ("==", "!=", "<=", ">=", "<", ">")

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INTEGER = re.compile(r"-?(0|[1-9][0-9]*)")
_INDEX = re.compile(r"0|[1-9][0-9]*")
_DECIMAL_STRING = re.compile(r"\A-?(0|[1-9][0-9]*)(\.[0-9]+)?\Z")
_WHITESPACE = " \t\r\n"

_STRING_ESCAPES = {'"': '"', "\\": "\\", "b": "\b", "t": "\t",
                   "n": "\n", "f": "\f", "r": "\r"}

MAX_SAFE_INTEGER = canon.MAX_SAFE_INTEGER
MIN_SAFE_INTEGER = canon.MIN_SAFE_INTEGER


@dataclass(frozen=True)
class ParsedExpression:
    """A parsed expression. The canonical AST text is the authority.

    `ast()` reconstructs a fresh tree rather than sharing one, because the frozen value model
    admits only dict and list, so a recursively frozen structure would be refused by
    canonicalization itself.
    """

    source: str
    canonical: str
    evidence_ids: tuple

    def ast(self):
        return load.load_json_bytes(self.canonical.encode("utf-8"))


def parse_expression(source):
    """Return the parsed expression for one `when` string.

    Raises ExpressionParseError for a syntax failure and ExpressionTypeError for a mismatch the
    text alone proves. Evidence declarations are not consulted here.
    """
    if not isinstance(source, str):
        raise TypeError("parse_expression takes a string, not " + type(source).__name__)
    parser = _Parser(source)
    tree = parser.parse()
    referenced = []
    _collect_evidence_ids(tree, referenced)
    return ParsedExpression(
        source=source,
        canonical=canon.canonicalize(tree),
        evidence_ids=tuple(referenced),
    )


def validate_expression(parsed, loaded_rulebook):
    """Check every statically identifiable evidence reference against the pinned rulebook.

    Returns None. Raises UndeclaredEvidenceId naming the first undeclared id in source order.
    `requires_evidence` is not re-checked; rulebook loading owns it.
    """
    declared = {item["id"] for item in loaded_rulebook.value()["evidence"]}
    for identifier in parsed.evidence_ids:
        if identifier not in declared:
            raise UndeclaredEvidenceId(
                "An expression names an evidence id the rulebook does not declare: " + identifier
            )


def _collect_evidence_ids(node, out):
    """Walk the tree in source order, appending each statically named evidence id once."""
    kind = node["type"]
    if kind in ("fresh", "present"):
        _append_once(out, node["evidence_id"])
    elif kind == "path":
        if node["root"] == "evidence" and node["segments"]:
            first = node["segments"][0]
            if "member" in first:
                _append_once(out, first["member"])
    elif kind in ("and", "or"):
        for operand in node["operands"]:
            _collect_evidence_ids(operand, out)
    elif kind == "not":
        _collect_evidence_ids(node["operand"], out)
    elif kind == "compare":
        _collect_evidence_ids(node["left"], out)
        _collect_evidence_ids(node["right"], out)
    elif kind == "membership":
        _collect_evidence_ids(node["operand"], out)
    elif kind == "matches":
        _collect_evidence_ids(node["path"], out)


def _append_once(out, identifier):
    if identifier not in out:
        out.append(identifier)


class _Parser:
    """A hand-written lexer and recursive-descent parser over the declared grammar."""

    def __init__(self, source):
        self.source = source
        self.position = 0
        self.nesting = 0

    # --- failures -----------------------------------------------------------------------------

    def _line_column(self, offset):
        prefix = self.source[:offset]
        line = prefix.count("\n") + 1
        column = offset - (prefix.rfind("\n") + 1) + 1
        return line, column

    def _fail(self, message, expected, offset=None, token=None):
        offset = self.position if offset is None else offset
        line, column = self._line_column(offset)
        if token is None:
            token = self.source[offset:offset + 1]
        raise ExpressionParseError(message, offset, line, column, token, expected)

    def _type_fail(self, message, offset, token):
        line, column = self._line_column(offset)
        raise ExpressionTypeError(message, offset, line, column, token)

    # --- lexing -------------------------------------------------------------------------------

    def _skip_whitespace(self):
        while self.position < len(self.source) and self.source[self.position] in _WHITESPACE:
            self.position += 1

    def _at_end(self):
        self._skip_whitespace()
        return self.position >= len(self.source)

    def _peek_word(self):
        """Return the identifier or keyword at the cursor without consuming it."""
        self._skip_whitespace()
        match = _IDENTIFIER.match(self.source, self.position)
        return match.group(0) if match else None

    def _take_word(self):
        word = self._peek_word()
        if word is None:
            self._fail("An identifier was expected.", "identifier")
        self.position += len(word)
        return word

    def _peek_symbol(self, symbol):
        self._skip_whitespace()
        return self.source.startswith(symbol, self.position)

    def _take_symbol(self, symbol, expected):
        if not self._peek_symbol(symbol):
            self._fail("%r was expected." % symbol, expected)
        self.position += len(symbol)

    def _take_keyword_if(self, word):
        """Consume a keyword only when it stands alone, never as a prefix of an identifier."""
        if self._peek_word() == word:
            self.position += len(word)
            return True
        return False

    # --- grammar ------------------------------------------------------------------------------

    def parse(self):
        if self._at_end():
            self._fail("An expression was expected.", "expression", offset=len(self.source),
                       token="")
        tree = self._or_expression()
        if not self._at_end():
            self._fail("Unexpected trailing input.", "end of expression")
        return tree

    def _or_expression(self):
        operands = [self._and_expression()]
        while self._take_keyword_if("or"):
            operands.append(self._and_expression())
        if len(operands) == 1:
            return operands[0]
        return {"type": "or", "operands": operands}

    def _and_expression(self):
        operands = [self._not_expression()]
        while self._take_keyword_if("and"):
            operands.append(self._not_expression())
        if len(operands) == 1:
            return operands[0]
        return {"type": "and", "operands": operands}

    def _not_expression(self):
        negated = self._take_keyword_if("not")
        if negated and self._peek_word() == "not":
            self._fail("`not not` is not derivable; write `not (not …)`.", "predicate")
        if self._peek_symbol("("):
            if self.nesting >= MAX_NESTING:
                self._fail("Expression nests deeper than the declared maximum of %d."
                           % MAX_NESTING, "expression")
            self.position += 1
            self.nesting += 1
            inner = self._or_expression()
            self.nesting -= 1
            self._take_symbol(")", "closing parenthesis")
            node = inner
        else:
            node = self._comparison()
        if negated:
            return {"type": "not", "operand": node}
        return node

    def _comparison(self):
        word = self._peek_word()
        if word in FUNCTIONS:
            return self._function()

        start = self.position
        left = self._operand()

        if self._take_keyword_if("not"):
            if not self._take_keyword_if("in"):
                self._fail("`in` was expected after `not`.", "in")
            return self._membership(left, "not in")
        if self._take_keyword_if("in"):
            return self._membership(left, "in")

        self._skip_whitespace()
        for operator in COMPARISON_OPERATORS:
            if self.source.startswith(operator, self.position):
                operator_offset = self.position
                self.position += len(operator)
                right = self._operand()
                self._reject_chained_comparison()
                node = {"type": "compare", "operator": operator, "left": left, "right": right}
                self._check_literal_comparison(node, operator_offset, operator)
                return node

        self._fail("A bare operand is not a predicate.", "comparison operator", offset=start,
                   token=self.source[start:self.position].strip() or
                   self.source[start:start + 1])

    def _reject_chained_comparison(self):
        self._skip_whitespace()
        for operator in COMPARISON_OPERATORS:
            if self.source.startswith(operator, self.position):
                self._fail("Comparisons do not chain.", "end of comparison")

    def _membership(self, operand, operator):
        self._skip_whitespace()
        if not self._peek_symbol("["):
            self._type_fail("The right operand of `%s` must be a list literal." % operator,
                            self.position, self.source[self.position:self.position + 1])
        members = self._list_literal()
        return {"type": "membership", "operator": operator, "operand": operand,
                "list": {"type": "literal", "value": members}}

    def _function(self):
        start = self.position
        name = self._take_word()
        self._take_symbol("(", "opening parenthesis")
        if name in ("fresh", "present"):
            self._skip_whitespace()
            argument_offset = self.position
            word = self._peek_word()
            if word is None or word in KEYWORDS:
                self._type_fail("`%s` takes one evidence identifier." % name,
                                argument_offset,
                                self.source[argument_offset:argument_offset + 1])
            self.position += len(word)
            self._skip_whitespace()
            if self._peek_symbol(".") or self._peek_symbol("["):
                self._type_fail("`%s` names a declared evidence id, not a path." % name,
                                argument_offset, word)
            self._reject_extra_arguments(name, 1)
            self._close_call(name, 1)
            return {"type": name, "evidence_id": word}

        # matches(path, string)
        self._skip_whitespace()
        argument_offset = self.position
        word = self._peek_word()
        if word not in PATH_ROOTS:
            self._type_fail("`matches` takes a path as its first argument.", argument_offset,
                            self.source[argument_offset:argument_offset + 1])
        path = self._path()
        self._skip_whitespace()
        if not self._peek_symbol(","):
            # A missing second argument is wrong arity, which is a static mismatch rather than
            # a syntax failure, so too-few and too-many are classified alike.
            self._type_fail("`matches` takes exactly 2 arguments.", self.position,
                            self.source[self.position:self.position + 1])
        self.position += 1
        self._skip_whitespace()
        pattern_offset = self.position
        if not self._peek_symbol('"'):
            self._type_fail("`matches` takes a string pattern as its second argument.",
                            pattern_offset, self.source[pattern_offset:pattern_offset + 1])
        pattern = self._string_literal()
        self._reject_extra_arguments("matches", 2)
        self._close_call("matches", 2)
        _ = start
        return {"type": "matches", "path": path, "pattern": pattern}

    def _close_call(self, name, arity):
        self._skip_whitespace()
        if not self._peek_symbol(")"):
            self._type_fail("`%s` takes exactly %d argument(s)." % (name, arity),
                            self.position, self.source[self.position:self.position + 1])
        self.position += 1

    def _reject_extra_arguments(self, name, arity):
        self._skip_whitespace()
        if self._peek_symbol(","):
            self._type_fail("`%s` takes exactly %d argument(s)." % (name, arity),
                            self.position, ",")

    def _operand(self):
        self._skip_whitespace()
        word = self._peek_word()
        if word in PATH_ROOTS:
            return self._path()
        if word in ("true", "false"):
            self.position += len(word)
            return {"type": "literal", "value": word == "true"}
        if self._peek_symbol('"'):
            return {"type": "literal", "value": self._string_literal()}
        if self._peek_symbol("["):
            return {"type": "literal", "value": self._list_literal()}
        self._skip_whitespace()
        match = _INTEGER.match(self.source, self.position)
        if match:
            return {"type": "literal", "value": self._integer_literal(match)}
        self._fail("An operand was expected.", "operand")

    def _integer_literal(self, match):
        text = match.group(0)
        offset = self.position
        self.position += len(text)
        following = self.source[self.position:self.position + 1]
        if following in (".", "e", "E"):
            self._fail("Numbers are integers only; carry decimals as quoted strings.",
                       "integer", offset=offset, token=text + following)
        value = int(text)
        if value < MIN_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            self._fail("Integer outside the range every implementation holds exactly.",
                       "integer", offset=offset, token=text)
        return value

    def _path(self):
        root = self._take_word()
        segments = []
        self._take_symbol(".", "dot")
        segments.append({"member": self._take_word()})
        while True:
            if self._peek_symbol("."):
                self.position += 1
                segments.append({"member": self._take_word()})
            elif self._peek_symbol("["):
                self.position += 1
                self._skip_whitespace()
                match = _INDEX.match(self.source, self.position)
                if not match:
                    self._fail("An index must be a non-negative canonical integer.", "index")
                self.position += len(match.group(0))
                segments.append({"index": int(match.group(0))})
                self._take_symbol("]", "closing bracket")
            else:
                break
        return {"type": "path", "root": root, "segments": segments}

    def _string_literal(self):
        self._skip_whitespace()
        start = self.position
        self._take_symbol('"', "string")
        pieces = []
        while True:
            if self.position >= len(self.source):
                self._fail("Unterminated string literal.", "closing quote", offset=start,
                           token='"')
            character = self.source[self.position]
            if character == '"':
                self.position += 1
                return "".join(pieces)
            if character == "\n":
                self._fail("A literal newline is not permitted inside a string.",
                           "string content")
            if character == "\\":
                self.position += 1
                if self.position >= len(self.source):
                    self._fail("Unterminated escape sequence.", "escape")
                marker = self.source[self.position]
                if marker in _STRING_ESCAPES:
                    pieces.append(_STRING_ESCAPES[marker])
                    self.position += 1
                    continue
                if marker == "u":
                    digits = self.source[self.position + 1:self.position + 5]
                    if len(digits) < 4 or any(d not in "0123456789abcdefABCDEF" for d in digits):
                        self._fail("A \\u escape needs four hexadecimal digits.", "escape")
                    code_point = int(digits, 16)
                    if 0xD800 <= code_point <= 0xDFFF:
                        raise SurrogateNotPermitted(
                            "A string may not carry a code point in U+D800-U+DFFF."
                        )
                    pieces.append(chr(code_point))
                    self.position += 5
                    continue
                self._fail("Unsupported escape sequence.", "escape",
                           token="\\" + marker)
            pieces.append(character)
            self.position += 1

    def _list_literal(self):
        self._take_symbol("[", "opening bracket")
        members = []
        self._skip_whitespace()
        if self._peek_symbol("]"):
            self.position += 1
            return members
        while True:
            members.append(self._list_member())
            self._skip_whitespace()
            if self._peek_symbol(","):
                self.position += 1
                self._skip_whitespace()
                if self._peek_symbol("]"):
                    self._fail("A trailing comma is not permitted in a list.", "literal")
                continue
            self._take_symbol("]", "closing bracket or comma")
            return members

    def _list_member(self):
        self._skip_whitespace()
        word = self._peek_word()
        if word in ("true", "false"):
            self.position += len(word)
            return word == "true"
        if self._peek_symbol('"'):
            return self._string_literal()
        if self._peek_symbol("["):
            return self._list_literal()
        match = _INTEGER.match(self.source, self.position)
        if match:
            return self._integer_literal(match)
        self._fail("A list holds literals only.", "literal")

    # --- static checks ------------------------------------------------------------------------

    def _check_literal_comparison(self, node, offset, operator):
        left, right = node["left"], node["right"]
        if left["type"] != "literal" or right["type"] != "literal":
            return
        first, second = left["value"], right["value"]
        if _canonical_kind(first) != _canonical_kind(second):
            self._type_fail(
                "A literal is compared to a literal of another type.", offset, operator)
        if operator in ("<", "<=", ">", ">="):
            if not (_is_numeric(first) and _is_numeric(second)):
                self._type_fail(
                    "An ordering comparison needs numeric operands.", offset, operator)


def _canonical_kind(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    return "list"


def _is_numeric(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, str) and bool(_DECIMAL_STRING.match(value))
