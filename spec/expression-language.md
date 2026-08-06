# Expression language — executable contract
    expression_parser_version: 1

`spec/rulebook-language.md` declares what expressions mean. This file declares exactly how the
text becomes a tree: lexing, precedence, the abstract syntax tree, the static checks decidable
without runtime values, and where a failure points. It adds no operator and changes no meaning.

Parsing decides nothing. It resolves no candidate, evidence, or identity value, settles nothing,
and produces no outcome. It completes `spec/execution-chain.md` step 2, which pins a rulebook and
parses every `when` before anything is evaluated.

## Lexing
Deterministic and locale-independent.

- Whitespace between tokens is insignificant: space, tab, carriage return, and newline. Nothing
  else is whitespace.
- Identifiers are `[A-Za-z_][A-Za-z0-9_]*`, matched greedily. **A keyword is never recognised as a
  prefix inside an identifier**: `nothing`, `andover`, `orbit`, `inside`, `freshness`, and
  `presently` are identifiers, not `not`/`and`/`or`/`in` followed by text.
- Keywords are `and`, `or`, `not`, `in`, `true`, `false`, and the function names `fresh`,
  `present`, `matches`. All are lowercase; matching is case-sensitive, so `AND` and `True` are
  identifiers and fail elsewhere.
- `not in` is one operator written as two words separated by whitespace.
- Punctuation: `( ) [ ] , .` and the operators `== != <= >= < >`. Two-character operators are
  matched before one-character ones, so `<=` is never `<` then `=`.
- Integers are canonical: optional `-`, no `+`, no leading zero except `0` itself, no decimal
  point, no exponent, within −(2^53−1) … 2^53−1.
- Any other character is a lexical failure, including `=` alone, `&`, `|`, `!`, `+`, `*`, `%`,
  `;`, `:`, `{`, `}`, and `'`.

## Strings
Double-quoted only. A single-quoted token is a lexical failure — YAML's own quoting is what puts
an expression into a `when` field, and the expression language has one string syntax.

Escapes are exactly those canonical form emits: `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, and
`\u` followed by four hexadecimal digits. Any other escape is a failure. A literal newline inside
a string is a failure — a newline is whitespace between tokens, never string content.

A `\u` escape that produces a code point in U+D800–U+DFFF is refused with
`surrogate_not_permitted`: the resulting scalar must lie inside the frozen value model, and a lone
surrogate has no UTF-8 representation. A properly paired escape denotes its scalar and is valid.

## Grammar
As declared in `spec/rulebook-language.md`, with nothing added:

    expr        := or_expr
    or_expr     := and_expr { "or" and_expr }
    and_expr    := not_expr { "and" not_expr }
    not_expr    := [ "not" ] ( comparison | "(" expr ")" )
    comparison  := operand op operand | membership | freshness | presence | glob
    op          := "==" | "!=" | "<" | "<=" | ">" | ">="
    membership  := operand ( "in" | "not in" ) list
    freshness   := "fresh(" evidence_id ")"
    presence    := "present(" evidence_id ")"
    glob        := "matches(" path "," string ")"
    operand     := literal | path
    path        := ("candidate." | "evidence." | "identity.") ident { "." ident | "[" index "]" }
    literal     := string | integer | true | false | list
    list        := "[" [ literal { "," literal } ] "]"

Nesting is bounded at **64**, the same number `spec/document-loading.md` declares for
source depth. A deeper expression is refused with `expression_parse_error` rather than exhausting
the host stack, whose limit is mutable and would otherwise let the same text parse on one machine
and fail on another.

## Precedence and associativity
Lowest to highest: `or`, then `and`, then unary `not`, then comparison, membership, and the three
functions, then parentheses, paths, and literals. That order is the production chain itself, not an
added convention.

`or` and `and` are declared as repetition, so a run of them is one flat ordered sequence, not a
nesting. Operand order is the source order and is never rearranged.

Three consequences follow from the grammar as written, and all three are enforced:

- **Comparisons do not chain.** `comparison` takes exactly two operands, so `a == b == c` is not
  derivable and is refused.
- **`not not x` is not derivable.** `not` attaches to a comparison or to a parenthesized
  expression, not to another `not_expr`. `not (not x)` is legal and means the same thing; write
  that instead.
- **A bare operand is not a predicate.** `expr` reduces to `comparison`, and every comparison
  alternative is a relation. `true`, `"main"`, `5`, `[1]`, and `candidate.kind` alone are all
  refused. A `when` must be a predicate.

## Paths
Three roots and no others: `candidate.`, `evidence.`, `identity.`. `identity.x` is exactly
`candidate.identity.x` (`spec/rulebook-language.md`), and the parser preserves the written root.

A path is structural, never one opaque string. `candidate.action.argv[0]` is the root `candidate`
followed by the members `action` and `argv` and the index `0`.

An index is a non-negative canonical integer, `0` or `[1-9][0-9]*`. A negative index, an empty
index, a non-integer index, and a quoted member name are all refused. An index may follow any
segment, and indexes may repeat.

**A path that will not resolve at runtime is not a parse failure.** Whether
`candidate.action.tool` exists depends on the candidate, and `spec/rulebook-language.md` already
answers it: the path yields `absent`. Parsing checks shape, not existence.

## Functions
Exactly three, with fixed shapes:

- `fresh(evidence_id)` and `present(evidence_id)` take one bare identifier. A path, a literal, or
  any expression in that position is a static failure — the argument names a declaration, not a
  value.
- `matches(path, string)` takes a path and a string literal, in that order and no other. The
  pattern is preserved verbatim; it is fnmatch text, it is not a regular expression, and it is not
  interpreted here.

An unknown function name, a wrong argument count, and a nested call in an argument position are
all refused.

## Static checks
Only what the expression text alone proves, per `spec/rulebook-language.md`'s Error-vs-Hold split.
Everything data-dependent belongs to evaluation.

Refused with `expression_type_error`:
- wrong arity for any of the three functions;
- a non-path first argument to `matches()`, or a non-string pattern;
- a non-identifier argument to `fresh()` or `present()`;
- a right operand of `in` or `not in` that is not a list literal;
- a comparison between two literals of different canonical types, such as `1 == "1"` or
  `true != 1`;
- an ordering comparison between two literals where either is not numeric — not an integer and
  not a canonical decimal string — such as `"abc" > 5`.

Deferred to evaluation, because a value decides it: any comparison with a path operand, the
numeric usability of a value a path yields, and every absent or unsettled reference.

Refused with `undeclared_evidence_id`, against the pinned rulebook:
- `fresh(id)` or `present(id)` naming an id the rulebook does not declare;
- `evidence.<id>` whose first segment is not a declared id.

Evidence ids are identified only from those three syntactic positions. Nothing is inferred from
the contents of a string literal. `requires_evidence` is not re-checked here — rulebook loading
owns it.

## Abstract syntax tree
One language-neutral tree built only from canonical values — objects, arrays, strings, integers,
and booleans — so it canonicalizes through the frozen canonicalizer unchanged and a shim can
reproduce it exactly. No Python class appears in it.

    {"type":"or","operands":[…]}
    {"type":"and","operands":[…]}
    {"type":"not","operand":…}
    {"type":"compare","operator":"==","left":…,"right":…}
    {"type":"membership","operator":"in","operand":…,"list":…}
    {"type":"fresh","evidence_id":"tests"}
    {"type":"present","evidence_id":"approvals"}
    {"type":"matches","path":…,"pattern":"*rm -rf*"}
    {"type":"path","root":"candidate","segments":[{"member":"action"},{"index":0}]}
    {"type":"literal","value":"main"}

Parentheses leave no trace: grouping is structural. Whitespace leaves no trace. `and` and `or`
carry ordered operand arrays in source order. Literal values are preserved exactly, including a
string that happens to look like a number.

**A decimal string is a string literal.** The grammar's `decimal-as-string` names which strings
are usable as numbers, not a separate token class; `"12.50"` is `{"type":"literal","value":"12.50"}`
and its numeric usability is decided where numbers are compared.

**Nothing is simplified.** `x and true`, a double negation written as `not (not x)`, a duplicated
predicate, and a constant comparison are all preserved as written. Simplification could change
which rule reports which reason, and the trace is part of the contract.

## Identity
There is **no expression digest**. The pinned rulebook's digest already covers the canonical
rulebook value, which contains every `when` string verbatim, so a rulebook commits to its
expressions exactly. A separate digest would be a second name for the same commitment. Canonical
AST text exists and is pinned by fixtures; it is not an artifact field.

The parsed expression is immutable. As with a pinned rulebook, the canonical text is the
authority and the tree is reconstructed on request, because the frozen value model admits only
`dict` and `list` — a recursively frozen structure would be refused by canonicalization itself.

## Failure location
A parse failure carries `code`, the 0-based character `offset`, the 1-based `line` and `column`,
the offending `token` text, and `expected`, a stable identifier for what could have appeared.
Offsets index Unicode scalars, not bytes. Messages are fixed per failure kind and never contain
instance data beyond the token.

A static failure carries `code` and the same location where one applies, plus the offending
evidence id or function name. No raw lexer or parser exception ever reaches a caller.


## Declared bounds
    expression_parser_version: 1 — bounds stated explicitly in 0.1.0a2; no accepted expression
    changed meaning.

A rulebook is written by an operator; the values an expression is evaluated against are composed by
whoever proposes the candidate. So the cost of parsing and of matching are both part of the
contract, and neither may depend on the host.

**Nesting — every recursive path, one number.** The bound of 64 applies to parentheses *and* to
list literals, which nest through `[ [ ] ]` and are the other recursive production in the grammar.
Before 0.1.0a2 only parentheses were counted, so a deeply nested list was accepted or refused
according to `sys.setrecursionlimit` — a mutable host setting deciding whether a declared input
class is admissible, which is exactly what a bound exists to prevent. A parsed expression is also
required to reload through the strict loader, so an accepted expression is always a usable one
rather than one that fails later inside the evaluator on the loader's own depth bound. Refusals are
`expression_parse_error` or `source_too_deep`; a `RecursionError` never crosses the boundary.

**Matching — bounded by the product of the lengths.** `matches` walks the pattern and the value
iteratively, and its cost is bounded by `|pattern| x |value|`. The natural recursive reading of
`*` — try every split — is exponential in the number of `*` segments, and both operands are
reachable from a candidate an adversary composes: measured on the released 0.1.0a1 matcher, an
eleven-character pattern with four stars against a two-hundred-character value took over nine
seconds, and a six-star pattern did not finish. Results are unchanged; only the cost is.
