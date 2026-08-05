# Snapshot construction — declared acquisitions to a frozen snapshot
    snapshot_builder_version: 1

Takes a pinned rulebook, a recorded freeze instant, and a finite set of already-acquired evidence
results, and produces one immutable, schema-valid, content-addressed snapshot.

**Nothing is acquired here.** No file is read, no command runs, no endpoint is called, no sensor is
polled, nothing is retried, and no clock is consulted. The builder receives facts that adapters
already gathered and does exactly three things: it checks them against the rulebook's declared
boundary, it freezes them, and it hashes them.

## Inputs
    build_snapshot(rulebook, snapshot_id, frozen_at, acquisitions) -> FrozenSnapshot
    verify_snapshot_value(value, rulebook, registry) -> FrozenSnapshot

One acquisition is the smallest thing an adapter can report:

    {"id": "tests", "status": "ok", "acquired_at": "2026-08-05T00:00:00Z", "value": "passed"}

`id`, `status`, and `acquired_at` are required; `value` is present or absent per the rules below.
Nothing else is accepted — no order, no source, no error text, no adapter identity, no content
digest. `order` is assigned by the builder, and source configuration stays in the rulebook, bound
to this snapshot through `rulebook_digest` rather than copied into it.

## The declared boundary
The rulebook declares which evidence exists for a run. Only ids it declares may enter.

- An acquisition naming an undeclared id → ERROR `snapshot_item_undeclared`. Undeclared facts never
  enter silently; the rulebook is the boundary.
- Two acquisitions for one id → ERROR `snapshot_schema_invalid`. One declaration, one item.
- A declaration with `required: true` and no acquisition is **synthesized** as an item with status
  `missing` and `acquired_at` equal to `frozen_at`. `spec/execution-chain.md` requires one item per
  required declaration, and a caller that could not acquire something has still made an observation
  worth recording.
- A declaration with `required: false` and no acquisition is **omitted** entirely, which
  `spec/execution-chain.md` permits.

So a `required: false` id can be unavailable in two ways — absent from the snapshot, or present
with a non-`ok` status. Both are legal, they are not the same recording, and the evaluator already
treats them alike: `present()` is false and a value reference is unsettled either way. Fixtures
prove that equivalence rather than assuming it.

## Order
`order` records the acquisition sequence, and the sequence is the order the caller passes
acquisitions in. The builder assigns `order` from position: the first acquisition is `0`, the next
`1`, and so on, with synthesized `missing` items appended afterwards in declaration order.

`order` is therefore always exactly `0..n-1` and always equals array position, which is what
`spec/execution-chain.md` requires. A caller cannot supply `order`, so it cannot be duplicated,
non-contiguous, or disagree with array order.

Acquisition order is **content**. Two runs that acquired the same facts in a different sequence
produce different snapshots with different digests, and that is correct: they are different
recordings of how the run actually proceeded. Replay uses the recorded order and is unaffected.

## Freeze
`frozen_at` is supplied by the caller as a recorded instant and is the run's start instant. It is
never read from a clock, here or anywhere below.

- Every acquisition must satisfy `acquired_at <= frozen_at`, compared as exact offset-aware
  integer instants → else ERROR `evidence_order_invalid`. Evidence arriving after the freeze never
  enters this decision. Equality is permitted: acquiring exactly at the freeze is in time.
- `frozen_at` must be at or after the rulebook's `adopted_at` → else ERROR `rulebook_not_adopted`.
- Timestamps are stored as the caller wrote them. Two spellings with different offsets that denote
  the same instant compare equal for the freeze check and remain **distinct snapshot content** with
  distinct digests. Nothing is normalized in the hashed value.

Once built, a snapshot is immutable. Later evidence may justify another run; it can never alter
this one.

## Status
Exactly the four the schema declares: `ok`, `missing`, `stale`, `error`. No adapter-specific status
crosses this boundary, and none is collapsed into a boolean or dropped.

**The builder never computes `stale`.** Freshness is the evaluator's, derived from `acquired_at`,
`frozen_at`, and the declaration's `max_age_seconds`. `stale` as a status means something different
and independent: the adapter reports that what it observed is no longer valid, whatever its age.
Computing staleness in both layers would put one rule in two places, so it lives in one.

How an adapter decides that a 404 is `missing` rather than `error`, or that a timeout is `stale`, is
an adapter's business in a later closure. The builder validates and freezes what it is told.

## Values
- `ok` **requires** `value`. An `ok` item without one records nothing; the evaluator could not
  resolve it, and a rule referencing it would be unsettled while claiming to be settled → ERROR
  `snapshot_item_invalid`. The schema cannot express this, so construction enforces it.
- `missing` **forbids** `value`. Nothing was observed; that is what the status means → ERROR
  `snapshot_item_invalid`.
- `stale` and `error` **may** carry the observed value or omit it. Keeping it is often what makes a
  HOLD actionable.

An explicit JSON `null` is a value that is present. It is not the same as no `value` member, and
the two are never conflated: presence is tested by membership, never by truthiness.

A retained value on a `stale` or `error` item does **not** make it readable. Status controls
settlement, so a direct `evidence.<id>` reference is unsettled regardless of a retained value, and
fixtures prove it against the closed evaluator.

`value_digest` is not computed. No current contract requires it, the snapshot digest already covers
every value, and adding it later would change every snapshot digest — a `spec_version` decision, not
a quiet one.

## Digest
No self-reference, because the schema already says so: `snapshot_digest` is "Digest of this snapshot
with `snapshot_digest` omitted."

1. build the payload — every field except `snapshot_digest`;
2. canonicalize it;
3. SHA-256 those bytes;
4. add `snapshot_digest` as `sha256:` plus 64 lowercase hex;
5. schema-validate the completed object.

The completed snapshot's own canonical digest is a **different value** from `snapshot_digest`,
because the completed object contains the digest field and the payload does not. Only
`snapshot_digest` is ever called the snapshot digest; the other value is not used and is not
exposed.

Item order contributes. Source presentation does not, because the payload is a canonical value
before it is hashed. Absent optional fields differ from present ones, since they are different
documents.

## Verifying a snapshot the builder did not make
`verify_snapshot_value` accepts an externally supplied snapshot and never trusts its embedded
digest:

1. schema-validate it;
2. recompute the digest over the value minus `snapshot_digest` and compare → else ERROR
   `snapshot_digest_mismatch`;
3. check `rulebook_digest` against the pinned rulebook → else ERROR `snapshot_rulebook_mismatch`;
4. check the declared boundary, completeness, order, statuses, values, and freeze relationships,
   exactly as construction does;
5. preserve every original string.

No signature is verified here. That belongs to receipts.

## Validation order
Fixed, so a snapshot invalid several ways always reports the same first failure:

1. argument types — a programmer defect raises `TypeError`, not an outcome;
2. `frozen_at` well-formed;
3. rulebook adopted at `frozen_at`;
4. each acquisition's shape and canonical value model;
5. undeclared ids;
6. duplicate ids;
7. status and value combinations;
8. `acquired_at <= frozen_at`;
9. completeness, synthesizing required declarations;
10. payload construction and canonicalization;
11. digest;
12. schema validation of the completed object;
13. immutable return.

## Unavailable is not invalid
The distinction this unit exists to protect: **declared evidence that could not be obtained is a
valid snapshot**, not a construction failure. A required item recorded as `missing`, an adapter
reporting `error`, an observation marked `stale`, an optional declaration omitted — every one of
these builds successfully, reaches the evaluator, and may produce HOLD.

Construction fails only when the recording itself is incoherent: an undeclared id, a duplicate, an
`ok` with no value, evidence from after the freeze, a malformed instant, a digest that does not
match. Those are defects in the record. Unavailability is a fact about the world, and recording it
faithfully is the point.

## Immutability
The frozen snapshot is a record of strings only, with the canonical payload as authority and the
value reconstructed on request — the pattern Units 4, 5, and 6 established, and forced by the same
reason: the frozen value model admits only `dict` and `list`, so a recursively frozen structure
would be refused by canonicalization itself.
