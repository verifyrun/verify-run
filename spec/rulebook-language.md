# Rulebook expression language (restricted; the evaluator's whole world)
`when` expressions are the ONLY logic a rulebook may contain. No arbitrary code, ever.

## Grammar (EBNF-ish)
expr    := or_expr
or_expr := and_expr { "or" and_expr }
and_expr:= not_expr { "and" not_expr }
not_expr:= [ "not" ] ( comparison | "(" expr ")" )
comparison := operand op operand | membership | freshness | presence | glob
op      := "==" | "!=" | "<" | "<=" | ">" | ">="
membership := operand "in" list | operand "not in" list   # list is a literal list, never a string
freshness  := "fresh(" evidence_id ")"          # total: true iff status==ok and within max_age_seconds
presence   := "present(" evidence_id ")"        # total: true iff status==ok
glob       := "matches(" path "," string ")"    # fnmatch, case-sensitive, whole-string
operand := literal | path
path    := ("candidate." | "evidence." | "identity.") ident { "." ident | "[" index "]" }
ident   := [A-Za-z_][A-Za-z0-9_]*               # evidence ids and identity keys must lex as this
index   := "0" | [1-9][0-9]*                    # non-negative, no sign, no leading zeros
literal := string | integer | decimal-as-string | true | false | list
list    := "[" [ literal { "," literal } ] "]"
evidence_id := ident                            # must name a declared evidence id
string  := double-quoted; escapes per spec/canonicalization.md
integer, decimal-as-string := canonical forms per spec/canonicalization.md

Whitespace between tokens is insignificant.

`spec/expression-language.md` is the executable form of this grammar: lexing, precedence, the
abstract syntax tree, the static checks, and failure locations. It adds no operator and changes no
meaning declared here.

## Semantics
- Rules evaluate in listed order; first match wins; no match → default_outcome (BLOCK or HOLD only).
  An unsettled rule stops the walk — see "Settlement".
- Ordering operators (`<`, `<=`, `>`, `>=`) require BOTH operands to be numeric — a canonical
  integer or a canonical decimal string — and compare them as exact decimals (Python Decimal).
  A non-numeric operand is a type mismatch — see "Error vs Hold". Floats never enter digests or
  comparisons; non-integer numbers are carried as canonical decimal strings.
- `==` and `!=` never coerce. Values of different canonical types are unequal (`2 != "2"`), and
  strings compare byte-exactly, so `"12.50" != "12.5"`. Use an ordering operator to compare
  numerically. `in` and `not in` compare list elements by that same exact rule.
- Referencing evidence that is missing/stale/error does NOT throw and does NOT silently pass:
  the reference is `unsettled`. See "Settlement" for how that resolves.
- `fresh()` uses acquired_at vs the snapshot's frozen_at and the rulebook's max_age_seconds —
  never the wall clock at evaluation time. The evaluator has no clock.
- String comparison is exact and case-sensitive. Globs allowed only via `matches(path, "pattern")`:
  fnmatch syntax (`*`, `?`, `[seq]`, `[!seq]`), case-sensitive on every platform, matched against
  the whole string. Implementations must not use a case-normalizing fnmatch variant. `*` matches
  any run of characters including `/`: `matches` is textual and does not normalize or resolve
  paths. A non-string operand is a type mismatch — see "Error vs Hold".
- An evidence declaration with no `max_age_seconds` has no freshness bound, so `fresh(id)` is
  then exactly `present(id)`.
- No regex in v1. No arithmetic in v1. Add only with new spec_version + fixtures.

## Path resolution
A path names a value inside one of the recorded canonical inputs: the candidate (`candidate.`),
the frozen evidence snapshot (`evidence.`), or the candidate's `identity` map (`identity.`).
Nothing else is reachable. There is no other channel into the evaluator.

- `evidence.<id>` resolves to that snapshot item's `value`; later segments index into that value.
- `candidate.…` resolves inside the canonical candidate document. `identity.x` is exactly
  `candidate.identity.x`.
- `.ident` selects an object member. `[n]` selects the n-th element of an array, 0-based.
- A path that does not resolve — missing member, index past the end, index applied to a
  non-array, member applied to a non-object — yields `absent`.

`absent` is a settled fact, not an unknown: the candidate genuinely does not carry that field.
Evidence, which describes the world rather than the proposal, is the only channel that can be
unknown, and it says so through its item `status`.

- `==` with an `absent` operand is `false` and `!=` is `true`; two `absent` operands are equal.
- `in` is `false`, `not in` is `true`, and `matches()` is `false`, when the operand is `absent`.
- Ordering operators with an `absent` operand are `unsettled`, reason code `operand_unsettled`:
  "is nothing greater than 500" is not a question the recorded inputs answer.
- An evidence path is checked for settlement first. If the item is not `ok`, the reference is
  `unsettled` whether or not the path would have resolved.

## Settlement — three values
Every comparison and every expression evaluates to exactly one of `true`, `false`, or `unsettled`.
`unsettled` means the recorded evidence does not determine the answer. It is not a failure and not
a denial. Operands resolve to values, and one of those values is `absent`, above.

- A value reference (`evidence.<id>`, and any path beneath it) is `unsettled` when the snapshot
  carries no item for that id, or the item's status is not `ok`. Status decides settlement; the
  shape of the path does not. An id the rulebook never declared is ERROR, not `unsettled`.
- `fresh(id)` and `present(id)` are total: they return `true` or `false` and are never
  `unsettled`. They are the only way to reference non-ok evidence without unsettling the rule.
- `unsettled` is absorbing. If any operand is `unsettled`, the comparison, membership, glob, or
  boolean expression containing it is `unsettled`. There is no short-circuit: every operand is
  evaluated, left to right, so the reason trace is identical on every machine.

Rule resolution walks the rules in listed order and stops at the first rule that is not `false`:
- `true` → that rule's `outcome`; `matched_rule` is its id.
- `unsettled` → HOLD, `rule_id` set, `matched_rule` absent, with the reason code(s) below.
- no such rule → `default_outcome`, `matched_rule` absent.

An `unsettled` rule stops the walk; a later rule never overrides an earlier rule that could not be
settled. The model is one-directional: an `unsettled` reference can only weaken a result toward
HOLD, and can never produce an ALLOW that fully settled evidence would not have produced.

One reason is emitted per distinct cause, ordered by first occurrence left to right in the rule's
`when` text: `evidence_unsettled` with `evidence_id` set, or `operand_unsettled` with `rule_id`
alone.

## Error vs Hold at the language layer
- Expression fails to parse / references undeclared evidence id / STATIC type mismatch → ERROR
  (the rulebook is malformed; nothing was decided).
- Expression parses but the recorded inputs cannot settle it → HOLD.
This distinction is load-bearing. Do not blur it.

A type mismatch is static when the expression text alone proves it: wrong arity, a non-path first
argument to `matches()`, a literal compared to a literal of another type. Static mismatches are
caught when the rulebook is pinned, before any evidence is frozen → ERROR
`expression_type_error`.

A type mismatch is data-dependent when a well-formed expression meets a value it cannot use — an
amount that arrives as `"high"`, an ordering operator over an `absent` path. The rulebook is not
malformed and evaluation validly began, so this is never ERROR: the operand is `unsettled` →
HOLD, reason code `operand_unsettled`. It does not silently become `false`.

Every ERROR and every HOLD carries a code from the closed set in spec/reason-codes.md.
