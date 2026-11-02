# Historical paid-review receipt verification / 1

Additive vfy.service_review_receipt. No changes to accepted service_review.py,
service_adoption.py, their identities, retained plans, pools or operations.

```python
from vfy.service_review_receipt import verify_receipt
result = verify_receipt(
    receipt_bytes=selected_receipt_raw, trace_bytes=selected_trace_raw,
    request_bytes=selected_request_raw, ticket_bytes=selected_ticket_raw,
    policy_bytes=selected_policy_raw, owner_trust=selected_public_owner_trust,
    expected_owner_issuer=selected_issuer,
    limits=dict(input_bytes=8*1024*1024, trace_entries=3000))
```

All inputs are bytes or caller-selected public trust/bounds. The function does no
filesystem access, reconciliation, pool reconstruction, nonce consumption, signing,
spending or automatic retry. Imports/input acquisition/this verification cost are
outside paid review accounting; no full-cost claim. No file convenience loader is
provided because it would hide input acquisition costs and selection.

Selected signed receipt/ticket bytes must be canonical and their signatures must
verify under the SAME explicitly selected owner issuer. Exact raw request and
policy hashes bind the receipt, last unconsumed ticket entry, producer and policy.
Only accepted paid producer identity 31bcb1ac6b700b0bc8674a5d95491711afbdd3ca6a222eea6e2dad47bd26683d
and adoption identity 0c98ad29c930d7a772ebe2203ab0c7a1c12f958ddaa4abb5f14e70d04826be66 are supported.
Selected owner trust includes the existing child_ledger envelope producer identity.
This is independent caller selection; trust is never learned from the receipt.

TRACE.json is REQUIRED, not optional. Its exact bytes must match the signed trace
hash. All events have bounded canonical absolute paths, safe byte counts and SHA256
hashes. REVIEW_RECORDED requires exact read-call count and sum of trace payload bytes;
first three events bind selected plan, trust and adoption module. Failed receipts
allow conservative charged totals >= recorded successful trace, within reservation.
TRACE+RECEIPT fit retained_bytes; request coordinates fit selected policy capacities.
Full reservation retention, exclusions, UNKNOWN rules and no-authority flags are
checked. Source relation must match selected expected/observed identity; mismatch
or failed review cannot promote the Run verdict to OBSERVED_CANDIDATE.

Result state VERIFIED_HISTORICAL_REVIEW_RECEIPT is only authenticated recorded
correspondence. recorded_review_state and run_result retain the original scoped
observation, including UNKNOWN. It does NOT read/reconstruct current source, prove
that recorded file hashes are current, independently rederive source-manifest identity
or semantic correctness, verify current keys/authority, establish latest pool head,
validate full predecessor accounting, or prove settlement publication. Source identity
and derived task/requirement IDs remain signed producer attestations bound to selected
inputs. It does not turn a historical OBSERVED_CANDIDATE into current acceptance.

Explicit output guards: current_source_checked=false, current_pool_checked=false,
settlement_verified=false, full_prefix_accounting_verified=false,
verification_cost_charged=false, full_cost=UNKNOWN, authority_granted=false,
automatic_retry=false. Invalid/missing/tampered inputs raise; callers must display
unavailable/UNKNOWN and must not retry the original paid review to repair them.
A process interrupted before receipt publication cannot supply a verified receipt;
keep its separate conservative signed accounting observation, not a fabricated one.

Bounds: every raw input <=4MiB, combined bytes <= selected input_bytes; request/policy
<=65536, receipt <=32768, trace entries <= selected trace_entries. No path resolution
or path following occurs. All file reads needed to supply these inputs are caller
work and must remain disclosed/accounted separately.
