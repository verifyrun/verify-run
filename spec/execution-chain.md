# Execution chain — what happens, in order, and where each outcome may be produced
The order is fixed: candidate → rulebook pinned → evidence frozen → evaluation → authorization →
execution → acknowledgment → receipt → replay. Steps 1–3 are impure and are the only steps that
may produce ERROR. Step 4 is pure and produces ALLOW, BLOCK, or HOLD. No step may produce an
outcome earlier or later than shown here.

## 1. Candidate accepted
Validate against spec/candidate.schema.json → ERROR `candidate_schema_invalid`. Canonicalize;
`candidate_digest` is fixed from this point. A candidate carries no timestamp and never supplies
one.

## 2. Rulebook pinned
Load the YAML, validate → ERROR `rulebook_schema_invalid`. Parse every `when` → ERROR
`expression_parse_error`, `expression_type_error`, or `undeclared_evidence_id`. Canonicalize and
digest.

The pinned rulebook's full rule list governs the run. v1 has no candidate-sensitive rule
selection. If selection is ever added, it must be resolved and pinned here — before evidence is
frozen — and recorded in the receipt, so that replay selects the same rules from the same inputs.

`track` names the identity fields the receipt binds. A track field absent from the candidate's
`identity` is not an error: it resolves as `absent` (spec/rulebook-language.md), and the binding
records that it was absent.

## 3. Evidence frozen
Acquire, then freeze. Validate against spec/evidence.schema.json → ERROR
`snapshot_schema_invalid`, then:

- `frozen_at` is the instant of the freeze, and it is the run's start instant.
- every item's `acquired_at` must be at or before `frozen_at` → ERROR `evidence_order_invalid`.
  Nothing acquired after the freeze enters this decision.
- `order` must be exactly 0..n-1 across the items in array order → ERROR `evidence_order_invalid`.
- item ids must be unique across the snapshot → ERROR `snapshot_schema_invalid`.
- exactly one item for every declared id with `required: true` → ERROR `snapshot_item_missing`.
  A declaration with `required: false` may be omitted from the snapshot entirely.
- no item for an id the rulebook does not declare → ERROR `snapshot_item_undeclared`.
- `rulebook_digest` must equal the pinned rulebook's digest → ERROR `snapshot_rulebook_mismatch`.
- `frozen_at` must be at or after the rulebook's `adopted_at` → ERROR `rulebook_not_adopted`.
  This is the whole of adoption enforcement. It happens here, once, against a recorded value. The
  evaluator has no clock and never re-checks it, and replay re-checks it from the same recorded
  value and reaches the same answer.

`required` governs snapshot completeness only. Whether a rule can settle is decided by item
`status`, never by `required`.

A rule's optional `requires_evidence` lists ids that must be `ok` for that rule to be considered:
if any listed item is not `ok`, the rule is `unsettled` and its `when` is not evaluated. Every
listed id must be declared → ERROR `undeclared_evidence_id`.

## 4. Evaluation (pure)
Input: the canonical rulebook, the canonical candidate, and the frozen snapshot. Nothing else —
no clock, no network, no filesystem, no environment, no randomness, no locale, no process state.
Output: ALLOW, BLOCK, or HOLD with reasons, `matched_rule`, and `trace`, per
spec/rulebook-language.md and spec/reason-codes.md.

This step never produces ERROR. Every way of being invalid was caught in steps 1–3. A value that
meets an operator it cannot support is not invalidity — it is HOLD `operand_unsettled`
(spec/rulebook-language.md).

## 5–8. Authorization, execution, acknowledgment, receipt
ALLOW, BLOCK, and HOLD are decisions, and every decision emits a receipt. ERROR is not a decision
and emits none: a receipt requires a governing rulebook, a candidate digest, and an evidence
digest, and when evaluation never began at least one of those does not exist. ERROR is returned to
the caller as an outcome document and nothing is signed.

An ALLOW issues exactly one authorization: single-use, bound to `action_digest`,
`rulebook_digest`, and `evidence_digest`, with a nonce and an expiry derived from the rulebook's
`authorization.ttl_seconds`. BLOCK, HOLD, and ERROR issue none. Expiry and nonce reuse are checked
outside the evaluator, against recorded values. Execution acknowledgment is recorded in the
receipt.

## 9. Replay
Replay recomputes the decision from the recorded rulebook, candidate, and evidence snapshot. It
never re-acquires evidence and never re-executes the action.

A receipt records digests, not bodies — spec/receipt.schema.json is closed. The bodies live beside
it: a receipt written to `<path>.json` keeps its inputs in `<path>.inputs/` as `rulebook.json`,
`candidate.json`, and `snapshot.json`, each already in canonical form.

Replay is:
1. verify the receipt signature over the canonical receipt with `signature` omitted;
2. digest each body and compare against `rulebook.digest`, `candidate_digest`, `evidence_digest`;
3. recompute step 4;
4. compare outcome, reasons, `matched_rule`, and `trace` byte for byte.

A receipt presented without its inputs can complete step 1 only. That result is reported as
verified, not replayed. The two words are never merged.
