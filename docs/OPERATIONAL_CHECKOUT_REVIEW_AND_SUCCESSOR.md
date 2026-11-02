# Independent operational checkout review

Disposition: CHANGES_REQUIRED. Inspected audit source SHA256
`e7833b805b79f6824c0cd933ac8832e77b8d71327d910a439fc7df9050b839e1` and the complete
`tests/product/test_operational_checkout_probe.py`. No Engineer edits or service actions.
The historical scope correction is sound: the revised p11 explicitly denies historical scan
revalidation, universal write protection and concurrency protection. The following defects remain.

## Blocking findings

1. **P1 — changed tracked bytes can be called a current clean match** (p11 Git status check).
   In a fresh fixture, commit source.txt, set `git update-index --assume-unchanged source.txt`
   or `--skip-worktree`, then change source.txt. Actual Git status with the candidate's exact
   flags returns empty. With a simulated EACCES root probe, p11 returns
   CHECKOUT_BOUND_ROOT_WRITE_REFUSED and says the current clean checkout matches the pinned
   commit despite changed tracked bytes. These are real Git fixtures; only the permission
   denial is mocked, as in the proposed tests. Existing changed-file coverage misses index flags.
   Reject unsupported index flags/sparse/submodule configurations or compare the actual selected
   filesystem payload, types, modes and inventory with the independently selected Git tree/manifest.
   Do not rely solely on status for content identity. Git must not honor untrusted fsmonitor/hooks,
   global/system config or replacement objects when establishing this claim; pin executable and
   isolate these inputs. Declare conversion/filter/submodule scope rather than silently equating
   Git status with byte identity. No concurrency guarantee follows from sequential checks.

2. **P2 — post-creation write failure is misclassified as creation refusal** (probe try block).
   The try covers open, write and close. A successful exclusive open followed by EACCES from
   write returns the accepted status, claims root creation was refused, and leaves its new file.
   Reproduced using a stream wrapper that actually creates the file then raises on write.
   Separate exclusive creation from later I/O: any successful create disproves creation refusal.
   Use an exclusive low-level open or narrowly scoped open attempt, then close/cleanup with explicit
   failure reporting. Permission errors after acquisition must never become accepted refusal.
   Preserve evidence of partial operations; do not unlink paths unless ownership is established.

3. **P2 — missing probe still contributes a caught plant** (main aggregation).
   p11(None) returns NOT_RUN, but `caught = status is not None` makes it caught, increments
   plants_run/caught and permits aggregate HOLDS. Also the P11 description remains a historical
   measurement-integrity plant, which the current root probe does not establish.
   Carry NOT_RUN/UNKNOWN separately; an unperformed required check cannot establish complete
   acceptance. Describe the revised check as a current bound root-create observation. Preserve
   historical verdicts as historical records rather than counting a different probe as their rerun.

Additional scope: recomputing selection_digest verifies internal consistency only. Independent
selection of the sealed predecessor digest is required for authenticity; an editable self-hashed
JSON file is not an authenticated trust anchor. The patch does not alone establish that anchor.

Reproduction: `scripts/review_operational_checkout_probe.py` extracts only p11 by AST, creates
fresh disposable Git fixtures and never imports/runs Engineer or scans the sealed subject. It
reproduces both index-flag bypasses, post-create denial and NOT_RUN aggregation. No full audit or
service was executed. Existing tests were inspected, not represented as independently rerun.

Root negative controls should cover both index flags, unsupported sparse/submodule states,
malformed frozen input, post-open and close-time errors, cleanup failure, NOT_RUN aggregate
accounting, and changed externally selected seal. Root owns the implementation and integration.

## Minimal authentic successor contract (proposal, not historical execution)

Use a NEW versioned record, e.g. `engineer.operational-checkout-observation/1`, at an exclusive
new output path. Keep old hostile_plants, closure and seal bytes immutable. Required fields:

- `predecessor`: exact independently selected historical seal/member hashes and original schema;
  explicit relation `historical_reference_only`, not inherited PASS or a historical rerun.
- `selection`: selected checkout canonical root, commit and exact tree/manifest identity,
  coverage/exclusions, selection artifact hash, examiner/gate/module and environment identities;
  independently chosen verification trust. Paths are declared current inputs, not rewritten old IDs.
- `operation`: new ID, selected current observation time, scope, bounded input/resource limits,
  accounting context/reservation or explicit uncharged coordinates; reserve before advertised paid
  reads. Separately authorize any create/delete probe; reading history must not hide a mutation.
- `observations`: raw bounded Git outputs/statuses and their digests, actual manifest comparison,
  flags/config checks, explicit probe stage (not attempted/open refused/created/I/O failure/cleanup),
  errno and remaining artifact identity. Distinguish observed facts from inferences.
- `result`: CURRENT_BOUND_ROOT_CREATE_REFUSED only for all identity checks and open-time eligible
  refusal; otherwise MISMATCH/UNKNOWN/NOT_RUN with reasons. Historical execution NOT_REVALIDATED,
  concurrent immutability UNKNOWN, portability UNRESOLVED, no authority or automatic retry.
- `retention`: member hashes and producer authentication against independently selected public
  trust; validation can be offline without spending keys. New signing grants no old provenance.

For a future actual remeasurement, create a separately approved fresh subject and invocation,
with new START/reservation and raw receipts. Bind migration to an explicit schema/cost/scope
mapping from old record to new record; validate the old seal and preserve unsupported old fields
as historical/UNKNOWN. Never fill absent historical inputs using a current run or label a newly
reconstructed checkout as the original execution. A read-only importer may authenticate and
expose old bytes but cannot supply missing original authority or claim portability closure.

## Separate Run follow-on

Public `vfy` selected-case checking remains the next Run obligation. Preserve existing checker
and adoption/module identities; add a command wrapper selecting bounded raw evidence, public
owner trust/context and exact checker identity, producing the existing scoped observation with
no keys/live pool reads/reserve/execute/replay. Ordinary Engineer must call this public command,
not import vfy or rely on the external sys.path script. No CLI implementation or acceptance is
claimed in this review-first return. Existing service evidence and exhausted pools are unchanged.
