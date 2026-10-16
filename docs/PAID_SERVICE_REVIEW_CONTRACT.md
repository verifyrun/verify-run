# Explicit paid retained service review / 1

Additive vfy.service_review; old service_adoption.py remains byte-exact at
0c98ad29c930d7a772ebe2203ab0c7a1c12f958ddaa4abb5f14e70d04826be66.
Old plans and uncharged historical reconcile remain valid and unchanged. Paid means
resource-accounted, not billing, spend authorization or monetary settlement.

## Exact consumer API

```python
from vfy.service_review import PaidReviewPool, paid_review, identity, ADOPTION_SHA256
pool = PaidReviewPool.attach(selected_predecessor,
    expected_snapshot_bytes=selected_head, policy_bytes=policy_raw)
ticket = pool.reserve(request_bytes=request_raw, recorded_at=now)
receipt = paid_review(pool, ticket, request_bytes=request_raw, recorded_at=now)
view = pool.verify_snapshot(pool.snapshot())
status = pool.inspect(ticket)
```

Reopen: `PaidReviewPool(selected_predecessor, expected_snapshot_bytes=selected_head,
policy_bytes=policy_raw)`. Reopening restores no live token and cannot repeat a
reservation. Supported exact predecessor types: common_capacity.CapacityOwner,
service_attempt.ServicePool, service_adoption.AdoptionPool. Attach is an explicit
monotone transition of that SAME root/state/lock, preserving its selected signed
head and all cumulative usage. Old handles cannot mutate the new profile. No create,
reset, grant, refund, or implicit transfer from the old operation's accounting.

A separately selected development accounting context may fund this NEW review;
this does not replenish or erase the old service/adoption pool. The accounting
root must be disjoint from the retained operation. Root's actual C7 pool remains
exhausted; producer tests only use new disposable synthetic accounting.

Policy exact fields:

```
schema: vfy.service-review-policy/1
pool_root: canonical selected accounting root
predecessor_sha256: SHA256 of exact selected signed head bytes
review_identity: identity()
adoption_sha256: ADOPTION_SHA256
resource_capacities: {read_bytes: N, read_calls: N, retained_bytes: N}
accounting_scope: EXPLICIT_DEVELOPMENT_REVIEW_ONLY
authority_granted: false
automatic_retry: false
```

Request exact fields:

```
schema: vfy.service-review-request/1
review_id: explicit unique new review identifier (max 256 characters)
pool_root: selected accounting root
policy_sha256: SHA256 of exact policy bytes
operation_root: canonical old retained operation root
plan_path: canonical selected old plan file
plan_sha256: SHA256 of selected raw old plan bytes
trust_path: canonical independently selected receipt trust file
trust_sha256: SHA256 of selected raw trust bytes
adoption_module_path: canonical installed vfy/service_adoption.py
adoption_sha256: ADOPTION_SHA256
expected_source_sha256: SHA256 of canonical selected source manifest
resources: {read_bytes: N, read_calls: N, retained_bytes: N}
authority_granted: false
automatic_retry: false
```

No request builder reads files implicitly. Selection acquisition is separate and
not claimed paid by this reservation. All numeric limits are nonnegative safe
integers; requested amounts are positive; retained_bytes is 65536..4194304 and
read_calls <=100000. Policy/request raw JSON <=65536 bytes each. Selected file
payload <=4MiB; canonical absolute paths <=4096 characters. No symlink, hardlink,
special-file payload access. Existing Run source traversal bounds still apply.

## Ordering and bounds

Reserve performs only input/accounting validation, not subject file reads. It
charges one inherited dispatch slot and retained_bytes inherited output capacity,
plus all three cumulative review coordinates. A distinct explicit review ID may
request another paid observation only if residual capacity remains. Same ID refuses.

paid_review consumes a live token and publishes consumption in the existing pool
BEFORE any selected payload read. Process loss, failed reads, mismatch, changed
inputs and budget exhaustion retain the full reservation forever; no automatic
retry. Incomplete consumption/publication fails closed. Constructor/reopen does not
restore capabilities. Forked/concurrent callers also meet the durable consumed entry.

The selected old module is hash-checked and loaded into private globals. A private
child_ledger facade meters its read_file calls; no global monkeypatch, sys.modules
replacement or old source edit. Module/plan/trust reads are included. Each payload
read reserves its logical size and a call before access, then checks size/mtime;
short/failed reads conservatively retain the charged request size. Read failures
caught by old reconcile cannot evade the outer failed-meter flag. Read trace
retention is bounded before access; final raw TRACE+RECEIPT lengths are checked.

The observed source identity is the canonical complete manifest produced by the
old reader's existing scan, while it holds the existing shared operation lock.
No extra source traversal is added. If no full scan completes, its identity is null.
Selected source mismatch cannot return OBSERVED_CANDIDATE. Observation describes
that locked scan, not continued freshness after the lock is released.

## Receipt and recovery

Signed receipt schema vfy.service-review-receipt/1 binds the exact request and
reservation ticket hashes, producer identity, observed source hash, source_relation
MATCH/MISMATCH/UNKNOWN, Run result, selected task/requirement/selection IDs, charged
read bytes/calls, all reserved coordinates and trace hash. State REVIEW_RECORDED
means a bounded review returned, NOT that Run accepted the copy. The run_result may
remain UNKNOWN. Interrupted/failed paid reads report UNKNOWN_HOLD_RETAINED when a
receipt can be retained; absent receipts stay UNKNOWN_HOLD_RETAINED via pool.inspect.

Files are exclusively created under `<pool>/reviews/<request_sha256>/TRACE.json`
and RECEIPT.json. No old operation writes. Pool settlement links the exact signed
receipt; all reserved resources remain charged even after completion. A missing
settlement is not repaired or retried automatically. Receipt trust is selected
independently through the preexisting owner's trust. `_fault(stage)` supports
fresh synthetic interruption checks: after_consume, after_read, before_receipt.

## Explicit exclusions and trust boundary

read_bytes/read_calls cover payloads crossing this operation's metered read boundary,
including selected inputs/module and old reconcile's read_file calls. Excluded:
selection/preparation, dependency imports, old module self-identity reads, metadata,
locks, accounting-store I/O, CPU/wall enforcement, physical I/O, filesystem allocation,
receipt checking and historical reading. retained_bytes covers TRACE+RECEIPT payload,
not accounting copies or disk overhead. Full cost/lifecycle accounting stays UNKNOWN.

Trusted local controller/Python/dependencies, selected owner/trust and cooperative
filesystem locks; no hostile-owner rollback, independent clock or organizational
permission claim. No execution/adoption/retry API, no original source writes, no
service launch. Existing historical UNKNOWN remains unchanged. Ordinary guided
selection, Platform consumption, full costs and full V1 remain OPEN.

## Reviewed paid-path refinements

The original reader uses os.walk without an error callback; it can omit an unreadable
subtree. This remains a limitation of the unchanged historical interface, not a
claim about prior readable subjects. The paid reader privately substitutes an
os.walk facade that raises on every enumeration error and marks the outer review
UNKNOWN_HOLD_RETAINED. No complete source identity is reported after that failure.
Both old module bytes and shared os.walk remain untouched.

Trace space is reserved using the canonical serialized entry's upper-bound size
(path with JSON escaping, maximum per-file byte count, fixed SHA256 and separator)
before reading payload, including control characters in paths. Synthetic root and
nested enumeration failures and expanded-path trace retention have focused controls.
