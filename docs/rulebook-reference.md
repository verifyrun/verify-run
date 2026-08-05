# Rulebook reference

A rulebook is YAML. It is loaded through a strict subset — no anchors, aliases, merge keys, tags,
or ambiguous plain scalars — validated against `spec/rulebook.schema.json`, canonicalized, and
digested. That digest is what every receipt and authorization binds to, so presentation never
changes identity: two files differing only in formatting pin to the same rulebook.

## Top level

```yaml
rulebook_id: minimal-gate           # required
version: 1.0.0                      # required
adopted_at: "2026-08-05T00:00:00Z"  # required
description: The smallest complete rulebook.
track: [branch]                     # identity fields the receipt binds
evidence: []                        # what may be consulted
rules:                              # tried in order
  - id: only-from-main
    when: 'identity.branch == "main"'
    outcome: ALLOW
    reason: Deploys from main are allowed.
default_outcome: HOLD               # BLOCK or HOLD; never ALLOW
authorization: {ttl_seconds: 300, single_use: true}
```

That is a complete, loadable rulebook — every YAML example in this document is, and a test pins
each one through the real loader.

`default_outcome` may not be ALLOW. A gate that permits by default is not a gate.

`adopted_at` governs when the rulebook takes effect. A snapshot frozen before it is refused. A
rulebook change creates a new version governing **future runs only** — receipts record which
version governed, and a rule change is never applied to a run already evaluated.

## Evidence declarations

```yaml
evidence:
  - {id: tests, source: exec, ref: "./ci/last-test-result.sh", max_age_seconds: 900}
  - {id: approvals, source: file, ref: .vfy/approvals.json, max_age_seconds: 86400, required: false}
```

| Field | Meaning |
|---|---|
| `id` | must lex as an identifier, so expressions can name it |
| `source` | `file`, `exec`, `http`, or `inline`. This alpha acquires `file` and `exec` |
| `ref` | a path for `file`, an executable path for `exec` |
| `max_age_seconds` | freshness bound, `acquired_at` against the snapshot's `frozen_at` |
| `required` | snapshot completeness only. Default `true`. It never decides settlement |

Each item ends up with a status: `ok`, `missing`, `stale`, or `error`. **Settlement is decided by
that status, never by `required`.**

## Rules

```yaml
rules:
  - id: tests-green-on-main
    when: 'identity.branch == "main" and fresh(tests) and evidence.tests == "passed"'
    outcome: ALLOW
    reason: Tests green on main within freshness bound.
    requires_evidence: [tests]      # optional
```

Rules are evaluated **in order**. The first rule that is `true` decides, and its `reason` becomes
the receipt's message verbatim. If a rule is `unsettled`, the walk **stops there** and the outcome
is HOLD — a later rule never speaks for evidence that could not be read. If every rule is `false`,
`default_outcome` applies.

`requires_evidence` lists ids that must be `ok` for the rule to be considered at all; if any is
not, the rule is unsettled and its `when` is never evaluated.

## The `when` language

Three-valued: **true**, **false**, **unsettled**. Unsettled is absorbing and there is no
short-circuit — `false and unsettled` is unsettled, not false. That is deliberate: a rule whose
inputs are unknown has an unknown answer, whatever the other operand says.

### Operands

| Form | Meaning |
|---|---|
| `candidate.action.argv[0]` | a path into the proposed action |
| `identity.branch` | a tracked identity field |
| `evidence.tests` | the observed value; **unsettled** unless the item's status is `ok` |
| `"literal"`, `42`, `true`, `false` | literals. No floating point anywhere |

A path that does not exist resolves to `absent` — settled knowledge that there is nothing there,
which is different from evidence that could not be read.

### Operators

- comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
- membership: `in`, with a list literal — `candidate.action.argv[0] in ["rm","mkfs","dd"]`
- boolean: `and`, `or`, `not`, and parentheses

Numbers compare exactly. Non-integer numbers are written as canonical decimal **strings**, never
floats, so no comparison ever depends on binary rounding.

### Functions

| Function | Returns |
|---|---|
| `present(id)` | whether the snapshot carries an `ok` item for `id`. **Total** — never unsettled |
| `fresh(id)` | whether that item is `ok` and within its `max_age_seconds`. **Total** |
| `matches(text, pattern)` | glob match, `*` only |

`present` and `fresh` are total by design: they are questions *about* the evidence, and a question
about missing evidence has a definite answer. A direct `evidence.<id>` reference is different — it
asks for the value, and there is no value to give.

```yaml
when: 'candidate.action.tool == "send_email" and not present(approvals)'
outcome: HOLD
reason: External email requires a recorded human approval.
```

## Worked example: the three outcomes

```yaml
rulebook_id: worked-example
version: 1.0.0
adopted_at: "2026-08-05T00:00:00Z"
track: [branch]
evidence:
  - {id: tests, source: exec, ref: "./ci/last-test-result.sh", max_age_seconds: 900}
rules:
  - id: tests-green-on-main
    when: 'identity.branch == "main" and fresh(tests) and evidence.tests == "passed"'
    outcome: ALLOW
    reason: Tests green on main.
  - id: tests-red
    when: 'fresh(tests) and evidence.tests == "failed"'
    outcome: BLOCK
    reason: Tests failed.
  - id: wrong-branch
    when: 'identity.branch != "main"'
    outcome: BLOCK
    reason: Deploys only from main.
default_outcome: HOLD
```

- tests pass, branch `main` → **ALLOW** on rule 1.
- tests fail, branch `main` → rule 1 false, rule 2 true → **BLOCK**.
- the tests command exits non-zero → rule 1 is unsettled (`evidence.tests` has no value) → the
  walk stops → **HOLD**, and `wrong-branch` is never reached even from a feature branch.

That last case is worth internalizing: unavailable evidence stops the walk. It does not fall
through to a later rule that happens to be decidable.

## Errors you will meet

| Code | Cause |
|---|---|
| `expression_parse_error` | the `when` text does not parse |
| `expression_type_error` | a mismatch provable from the text alone, including wrong arity |
| `undeclared_evidence_id` | an expression names an id the rulebook does not declare |
| `rulebook_semantic_invalid` | duplicate rule or evidence id, or an id that is not an identifier |
| `rulebook_not_adopted` | the snapshot was frozen before `adopted_at` |

Every example in this document parses under the real parser; a test asserts it.
