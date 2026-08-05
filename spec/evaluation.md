# Evaluation — frozen inputs to one terminal outcome
    evaluator_version: 1

The pure step. A pinned rulebook, a validated candidate, and a frozen evidence snapshot go in; one
ALLOW, BLOCK, HOLD, or ERROR comes out, with an ordered reason trace.

Nothing else enters. No clock, no network, no filesystem, no environment, no randomness, no
locale, no process state — `CLAUDE.md`'s dependency law, restated where it is enforced. Nothing is
authorized, signed, persisted, or actuated here.

## Inputs
    evaluate(rulebook, candidate, snapshot) -> EvaluationResult

**There is no identity argument.** `spec/rulebook-language.md` declares that `identity.x` is
exactly `candidate.identity.x`, so identity is a projection of the candidate. A separate parameter
would be a second source for the same values, and the two could disagree.

What the evaluator may trust, because a closed unit already established it: the rulebook is pinned,
schema-valid, and semantically checked (Unit 4); its expressions parse and their static evidence
references are declared (Unit 5); every value is inside the frozen canonical model (Unit 3A).

What it must still establish, in this order, before any rule is walked:

1. the candidate is schema-valid → else ERROR `candidate_schema_invalid`;
2. the snapshot is schema-valid → else ERROR `snapshot_schema_invalid`;
3. every item's `acquired_at` is at or before `frozen_at` → else ERROR `evidence_order_invalid`;
4. the rulebook applies at `snapshot.frozen_at` → else ERROR `rulebook_not_adopted`;
5. every `when` parses and validates → else ERROR `expression_parse_error`,
   `expression_type_error`, or `undeclared_evidence_id`.

That order is fixed, so a document invalid in several ways always reports the same first failure.

**ERROR is produced only by that preparation.** `spec/execution-chain.md` says the evaluation step
never produces ERROR, and it does not: once the walk begins, every result is ALLOW, BLOCK, or HOLD.
A programmer defect — a non-mapping candidate, a missing argument — raises `TypeError` instead and
is not an outcome at all. Caller-invalid input and underdetermined evidence never mix.

## Runtime values
Two sentinels exist inside evaluation and neither ever appears in output:

- **`absent`** — a candidate or identity path that does not resolve. A settled fact: the candidate
  genuinely does not carry that field.
- **`unsettled`** — the recorded evidence does not determine the answer.

They are never conflated. Absence is knowledge; unsettledness is its lack.

## Three-valued algebra
Every comparison and expression is `true`, `false`, or `unsettled`. **`unsettled` is absorbing in
every operator**, and there is no short-circuit: every operand is evaluated, left to right.

| `not` | | `and` | true | false | unsettled | | `or` | true | false | unsettled |
|---|---|---|---|---|---|---|---|---|---|---|
| true → false | | **true** | true | false | unsettled | | **true** | true | true | unsettled |
| false → true | | **false** | false | false | unsettled | | **false** | true | false | unsettled |
| unsettled → unsettled | | **unsettled** | unsettled | unsettled | unsettled | | **unsettled** | unsettled | unsettled | unsettled |

`false and unsettled` is `unsettled`, not `false`. `true or unsettled` is `unsettled`, not `true`.
Ordinary short-circuit logic would answer both differently, and it is not used: the whole point is
that an unsettled reference can only ever weaken a result toward HOLD, never let one through.

## Path resolution
`candidate.…` resolves inside the candidate; `identity.x` resolves at `candidate.identity.x`;
`evidence.<id>` resolves to that snapshot item's `value`.

A member selects from an object, an index selects from an array. A path that does not resolve —
missing member, index past the end, index into a non-array, member of a non-object — yields
`absent`.

For evidence, **status decides settlement before shape does**: if the snapshot carries no item for
a declared id, or the item's status is not `ok`, the reference is `unsettled` whether or not the
path would have resolved. Only within an `ok` item's value does path shape produce `absent`. An
undeclared id cannot reach here; Unit 5 rejects it statically.

Operations on `absent`:

- `==` is `false`, `!=` is `true`; two `absent` operands are equal;
- `in` is `false`, `not in` is `true`, `matches()` is `false`;
- an ordering operator is **`unsettled`**, reason `operand_unsettled` — "is nothing greater than
  500" is not a question the recorded inputs answer.

## Evidence
`present(id)` and `fresh(id)` are **total**: `true` or `false`, never `unsettled`. They are the
only way to reference non-ok evidence without unsettling the rule, which is what makes a rule like
`not present(approvals)` expressible at all.

- `present(id)` is `true` exactly when the snapshot carries that item with status `ok`.
- `fresh(id)` is `true` exactly when the item exists, its status is `ok`, and its age is within the
  declaration's bound.

Age is `frozen_at − acquired_at`, computed from recorded values by exact integer arithmetic —
never a clock. The bound is **inclusive**: an age exactly equal to `max_age_seconds` is within it,
which is what "within" means. A declaration with no `max_age_seconds` has no bound, so `fresh(id)`
is then exactly `present(id)`.

Timestamps carrying different offsets that denote the same instant compare equal; the strings stay
distinct, only the instants are compared.

A rule's `requires_evidence` runs **before** its `when`: if any listed id is absent from the
snapshot or not `ok`, the rule is `unsettled` and its expression is not evaluated at all
(`spec/execution-chain.md`). Freshness is irrelevant to that check — only status.

## Numbers
No float, anywhere. An integer is exact; a canonical decimal string may participate in ordering.
Comparison is exact integer arithmetic over sign, digits, and scale — no `float`, no arithmetic on
values, and no library context that could round.

- `==` and `!=` **never coerce**. Different canonical types are unequal, so `1 != "1"` and
  `1 != true`, and strings compare byte-exactly, so `"12.50" != "12.5"`.
- Ordering operators require **both** operands numeric — an integer or a string matching
  `-?(0|[1-9][0-9]*)(\.[0-9]+)?`. `"12.50" <= "12.5"` is `true`, because ordering compares
  numerically what equality compares textually. That asymmetry is deliberate and declared.
- `-0` and `-0.0` equal `0` numerically, and trailing fractional zeros do not change value.
  Magnitude and precision are unbounded.
- A boolean is never numeric. A decimal-looking string that does not match the form is an ordinary
  string.
- An ordering operator whose runtime operand is non-numeric or `absent` is **`unsettled`**, reason
  `operand_unsettled` — never ERROR, because the rulebook is well formed and only this value
  cannot answer.

## Pattern matching
`matches(path, pattern)` uses one portable glob, implemented directly rather than delegated,
because a platform fnmatch may normalize case.

- `*` matches any run of characters **including `/`**;
- `?` matches exactly one character;
- `[seq]` matches one character in the set, `[!seq]` one outside it, and a range is `a-z`;
- `]` immediately after `[` or `[!` is a literal `]`;
- an unclosed `[` is a literal `[`;
- everything else is literal, and the match is **whole-string and case-sensitive on every
  platform**.

No regular expression is ever compiled from a pattern. A resolved value that is `absent` gives
`false`; one that is a non-string gives `unsettled`.

## Membership
`in` and `not in` search the list literal in source order, comparing by the same exact
type-sensitive equality as `==`. No coercion. An `unsettled` operand makes the membership
`unsettled`; an `absent` operand gives `false` for `in` and `true` for `not in`.

## Rule walk
Rules are walked in listed order. The walk stops at the first rule that is not `false`:

| First non-`false` rule | Result |
|---|---|
| `true` | that rule's declared `outcome`; `matched_rule` is its id |
| `unsettled` | HOLD; `rule_id` is set, `matched_rule` is **absent** |
| none | `default_outcome`; `matched_rule` is **absent** |

An unsettled rule stops the walk — a later rule never overrides an earlier one that could not be
settled. ALLOW is never a default: `default_outcome` admits only BLOCK or HOLD.

## Result
One outcome document, validated against `spec/outcome.schema.json` before it is returned.

Reason codes come from the closed set, with the messages `spec/reason-codes.md` fixes: `rule_allow`,
`rule_block`, and `rule_hold` carry the matched rule's `reason` verbatim; `evidence_unsettled` and
`operand_unsettled` carry fixed text; `default_outcome_block` and `default_outcome_hold` carry "No
rule matched."

For an unsettled rule, one reason is emitted per distinct cause in first-occurrence order:
`evidence_unsettled` with `evidence_id` set, or `operand_unsettled` with `rule_id` alone.

`trace` carries one entry per rule evaluated, in order, ending where the walk stopped:

    "<ordinal>:<rule_id>:<true|false|unsettled>"

No timestamps, no values, no host data — the trace is a function of the recorded inputs alone,
which is what makes byte-identical replay checkable.

The result is immutable: canonical text is the authority and the outcome is reconstructed on
request, the pattern Units 4 and 5 established. No input is mutated.
