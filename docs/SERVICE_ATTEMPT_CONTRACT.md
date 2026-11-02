# Service attempt accounting / 1

Private additive candidate, not a release or full service authority. Full V1
continues to require semantic acceptance, adoption, custody and continuation.
Existing common/managed modules and all old signatures remain byte-identical.

```python
from vfy.service_attempt import ServicePool
pool = ServicePool.attach(predecessor, predecessor_snapshot_bytes=head,
                          policy_bytes=policy)
# Reopen with the SAME independently selected predecessor, raw head and policy:
pool = ServicePool(predecessor, predecessor_snapshot_bytes=head, policy_bytes=policy)
ticket = pool.admit(request_bytes=request, preview_bytes=preview,
                    approval_bytes=approval, recorded_at=timestamp)
# Caller fsyncs its START first. It MUST NOT launch unless consume returns.
receipt = pool.consume(ticket, request_bytes=request, preview_bytes=preview,
                       start_bytes=start, recorded_at=timestamp)
# Only after consume returns: caller's separately approved bounded executor.
pool.settle(ticket, result_bytes=result, stdout_bytes=stdout,
            stderr_bytes=stderr, recorded_at=timestamp)
pool.mark_unknown(ticket, reason="interrupted", recorded_at=timestamp)
snapshot = pool.snapshot()
pool.verify_snapshot(snapshot)  # selected signed accounting; NOT freshness
```

No standalone store/create API. `predecessor` must be an exact built-in
`common_capacity.CapacityOwner` or `managed_capacity.ManagedCapacityOwner`.
The selected raw predecessor snapshot is validated with that owner's selected
trust/config/observer and preserved verbatim. Attach compares the actual head
under the SAME lock and atomically replaces the SAME state.json with a service
epoch. Old allocator handles then refuse writes. Legacy settlements are frozen:
finish them before selecting the transition head if further settlement is needed.
No dispatch slots/output budget are added, reset or refunded. Service's new
coordinates do not backfill unmeasured legacy resources or claim global capacity.

`policy_bytes` is strict canonical Run JSON with exactly:

* `schema`: `vfy.service-policy/1`; `pool_root`, `config_sha256`,
  `predecessor_sha256` (SHA256 of raw head), `service_identity` (`identity()`);
* `approval_trust`: independently selected issuer map in existing Run envelope
  format (`public_key_hex`, `producer_identity`). Keys must differ from pool
  owner AND child issuers. Never learn trust from the request/approval;
* `adapter_sha256`, `capture_sha256`: independently selected exact code hashes;
* `resource_capacities`: cumulative nonnegative safe integers with exact keys
  `wall_seconds`, `cpu_seconds`, `output_bytes`, `file_bytes`, `descriptors`;
* `authority_granted: false`, `automatic_retry: false`.

Selecting this policy explicitly authorizes only accounting profile extension
at that exact head. Owner signs the resulting state. It is NOT a grant of effect
authority. Missing shared capacity requires separately authorized existing-pool
capacity work; this API cannot provide it. No existing/exhausted pools are reset.

`request_bytes` has exactly `schema: vfy.service-attempt/1`, `attempt_id` (nonempty
string), `attempt_root` (absolute canonical directory), `pool_root`,
`policy_sha256`, `preview_sha256`, `resources`, and both false flags.
`resources` has the five keys above, positive safe integers, exactly matching
PREVIEW.limits. Admission charges one common dispatch slot, `output_bytes` common
retained-output bytes, and all five declared resource limits cumulatively. These
are charged bounds, NOT observed utilization: file bytes are the declared
per-file limit and descriptors the declared per-process limit, not total disk
or process-tree usage. CPU/wall enforcement scope belongs to the selected adapter.
No RAM, network, descendant-count, metadata-storage or discovery/checking cost
bound is established by this slice. Additional work must be explicitly budgeted.

Approval is an existing Run signed envelope, authenticated ONLY by selected
`approval_trust`, whose exact body is `schema: vfy.service-approval/1`,
`request_sha256`, `preview_sha256`, `policy_sha256`, `authority_granted: false`,
`automatic_retry: false`. This proves a selected issuer attested these bytes,
not that the issuer has broader action rights or a currently unrevoked capability.
The caller must separately validate current effect authorization and runtime
constraints. Approval binds every request resource and every raw PREVIEW field,
including source, examiner, environment, labels, policy and adapter/capture code.

PREVIEW must be `engineer.service-observation/1` with selected hashes/root/limits;
on-disk PREVIEW.json must match exact supplied bytes at admission and consume.
Admission refuses any existing START.json. START must be the existing Engineer
shape `{"preview": "<raw-preview-sha256>"}` at attempt_root/START.json, exact
raw bytes reread at consume. Run signs its raw SHA and exact request/PREVIEW/
approval binding. Run cannot prove who wrote/fsynced START; the trusted adapter
must enforce durable START, unchanged inputs/environment and immediate launch.
Neither byte correspondence nor a fixture establishes authentic runtime origin.

Ticket is the admission snapshot envelope; `consume` returns the signed consumed
snapshot. Both bind `body.entries[].request_sha256`, approval and PREVIEW hashes;
consumed entries include `start_sha256`. One live in-memory admission capability
is required in addition to durable state. A reconstructed object cannot consume,
even if admitted-but-not-consumed. Failed consume burns the live capability and
records UNKNOWN when storage permits. Any failure means NO LAUNCH/NO REPLAY.
Ambiguous publication leaves pending.json and blocks the shared pool. No retry
or refund recovery API exists. Keep caller lock through admission/START/consume/
launch/result; the pool lock is not an executor lock or hostile-owner defense.

Settlement rereads exact START, PREVIEW, RESULT.json, stdout.bin and stderr.bin.
RESULT.preview and stream SHA256s must match. Finite floating wall measurement
is accepted only in opaque RESULT bytes; signed coordinates remain integers.
Observed exit 0 => OBSERVED_EXIT_ZERO; positive => OBSERVED_EXIT_NONZERO;
negative => OBSERVED_SIGNAL; absent exit/launch failure/limit failure => UNKNOWN.
No stdout text grants success. All bounds remain fully charged for EVERY outcome.
Interruption/missing result uses mark_unknown; later evidence may be attached
once but an UNKNOWN attempt stays UNKNOWN, never reopens launch. This is evidence
linkage, not independent observation, semantic success, settlement/adoption rights,
hostile local-owner rollback defense, or full lifecycle affordability.

## Private installed artifact

The producer artifact directory is `/private/tmp/verify-run-service-artifacts-20261016`.
The private wheel retains base package version `0.1.0a7`; select the exact wheel
SHA256 in SOURCE_IDENTITY.json, never the version alone. It is NOT the public a7
artifact or a release. Install with `pip install --no-index --no-deps --target
NEW_INSTALLED_ROOT <exact wheel>` into an isolated dependency-equipped environment.
Run `python -I scripts/check_service_install.py NEW_INSTALLED_ROOT CHECK_ROOT`,
where CHECK_ROOT contains only the provided tests package. This asserts installed
module origin before running the focused controls. The fixture generator creates
only a fresh explicitly synthetic pool and ends UNKNOWN without launching; it
must never be used as a replacement for a selected common pool.

Engineer limits 60/40/1048576/67108864/128 (wall/CPU/output/file/descriptors)
require at least one remaining shared slot and 1048576 remaining output bytes.
An existing pool with total output capacity 786432 cannot admit that request even
when empty. Exact-limit controls demonstrate both that refusal and admission
against an explicitly sized fresh TEST pool. No implicit resource grant exists.
