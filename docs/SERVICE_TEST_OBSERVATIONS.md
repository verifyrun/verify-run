# Source-bound named test observations / 1

Private Run consumer contract. Adds read-only checking/evidence retention to
accepted service accounting without changing any allocator, signature, old pin,
accepted pool, or execution capability. Full V1 remains the connected target.

## Engineer wire contract (freeze before wiring)

PREVIEW retains `engineer.service-observation/1` and adds exactly these selected
bindings (existing service accounting accepts and binds extra PREVIEW fields):

* `test_selection_sha256`: SHA256 of raw examiner-selected selection bytes;
* `test_runner_sha256`: SHA256 of the exact pinned runner module bytes.

The selected adapter must enforce the pinned runner, prelaunch capture and caller
lock. Hash correspondence is not proof that a runner executed honestly. Runtime,
framework/native code and result integrity remain the selected adapter's trust
boundary; reports are untrusted process claims, including on a successful check.

Entire stdout must be the raw structured report, with no prefixes, suffix text,
second report or console parsing. Diagnostics go to stderr. Thus the existing
signed service result binds its bytes via stdout_sha256 and the report consumes
the existing shared stdout+stderr output reservation. No new report store bypasses
the shared allocator. PREVIEW must bind selection before approval/admission/START.

Report exact keys:

```json
{"schema":"engineer.service-tests/1","preview_sha256":"<raw PREVIEW hash>",
 "events":[{"id":"suite.Case.test_name","outcome":"success"}],
 "tests_run":1,"completed":true,"successful":true}
```

Each event has exactly `id`, `outcome`. Outcomes: `success`, `failure`, `error`,
`skip`, `expected_failure`, `unexpected_success`. Exactly one terminal event per
named TestCase. No duplicate IDs, even identical repeated successes. The selected
runner must aggregate subtest failures into the parent's terminal non-success;
it must not emit a second success for that parent. Fixture/setup/teardown errors,
load errors and incomplete runner completion must prevent success. They may yield
extra/unexpected IDs or completed=false, which this checker preserves as UNKNOWN.
No inference from Django console text or `successful` alone. `tests_run` must be
an exact nonnegative integer (not bool) equal to events length. `completed` and
`successful` must be exact booleans. Expected failures and skips never pass here.
Successful must match unittest-style summary: all outcomes in
success/skip/expected_failure; even consistent skipped/expected-failure reports
remain non-passing. Unknown fields/version/outcomes fail closed.

## Independently selected frozen inputs

`requirements_bytes` is strict Run JSON:
`{"schema":"vfy.service-requirements/1","requirements":{"REQ-ID":"frozen statement"}}`.
Nonempty requirements, IDs and statements. These bytes freeze scope/wording, not
the truth, completeness or adequacy of the requirements. Examiner chooses mapping.

`selection_bytes` exact keys:

* `schema`: `vfy.service-test-selection/1`;
* `requirements_sha256`: raw frozen requirements hash;
* `source_sha256`, `examiner_sha256`, `environment_sha256`: SHA256 of Run canonical
  JSON (`child_ledger.raw`) for the corresponding PREVIEW objects;
* `adapter_sha256`, `capture_sha256`, `runner_sha256`: selected raw code hashes;
* `labels`: exact ordered PREVIEW.labels, nonempty unique strings;
* `case_ids`: nonempty unique expected fully qualified test IDs (order immaterial);
* `requirement_cases`: exact frozen requirement ID keys, each mapping to a nonempty
  unique list of case IDs; union must equal case_ids; shared cases are permitted;
* `authority_granted: false`, `automatic_retry: false`.

Do not derive expected cases, mappings, trust or limits from the observed report.
Select these inputs before launch and bind them in approved PREVIEW. This checker
does not discover cases or infer which cases establish a requirement. Changed
source, examiner, environment, code, labels, requirements or mappings need a new
selection/PREVIEW, with new authorization/accounting as applicable, never history
rewrite or replay of an uncertain attempt.

## Run callable contract

Read-only reconstruction for an already completed attempt (no seed, no admission
capability, no pool state reads/writes, no root relocation, no re-execution):

```python
from vfy.service_tests import load_service_pool
pool = load_service_pool(
    snapshot_bytes=accounting_result,
    expected_snapshot_sha256=selected_accounting_sha256,
    expected_pool_root=original_pool_root,
    expected_config_bytes=selected_original_config,
    owner_trust=selected_owner_trust, child_trust=selected_child_trust,
    selected_observer=selected_original_observer,
    predecessor_snapshot_bytes=selected_original_head,
    policy_bytes=selected_original_service_policy,
    expected_child_trusts=selected_per_request_legacy_child_trusts,
    minimum_revision=selected_minimum_revision)
```

All selections come from the original owner/examiner context, not auto-trusted
report fields. For an empty common predecessor, expected_child_trusts is `{}`.
For a managed predecessor also pass `managed_legacy_snapshot_bytes`,
`selected_callback_identity`, `selected_managed_identity` exactly as originally
selected. This validates every signed prefix with existing unchanged validators.
Current installed module identity hashing still reads module source bytes. The
old directory need not exist for a common predecessor; its path stays exact.
Returned ReadOnlyServicePool.snapshot() returns only the selected archived bytes.
All mutation/attach/consume methods refuse. Use it with check/verify_retained below;
it cannot sign a NEW retain receipt (that requires the original live selected
ServicePool and its owner signer). A caller may save check's plain JSON result as
a derived observation, explicitly not an owner-signed receipt.

```python
from vfy.service_tests import TestObservationChecker
checker = TestObservationChecker(
    pool,  # independently selected existing vfy.service_attempt.ServicePool
    selection_bytes=selection, requirements_bytes=requirements,
    runner_bytes=runner,
    limits={"input_bytes": 16777216, "cases": 4096,
            "requirements": 1024, "retained_bytes": 33554432})
args = dict(preview_bytes=preview, start_bytes=start, result_bytes=result,
            stdout_bytes=stdout, stderr_bytes=stderr,
            accounting_snapshot_bytes=snapshot, request_sha256=request_sha)
record = checker.check(**args)
# Only if checker was constructed with the original signing ServicePool:
# receipt = checker.retain(NEW_EVIDENCE_DIRECTORY, recorded_at=timestamp, **args)
record = checker.verify_retained(NEW_EVIDENCE_DIRECTORY)  # no execution/pool writes
```

Constructor rejects malformed/unselected frozen inputs. `check` accepts only byte
inputs within independently selected limits; malformed raw evidence, mismatches,
untrusted accounting or uncertain reports return UNKNOWN, never success. Request
hash must identify exactly one entry in the authenticated selected pool snapshot.
Exact raw request, START, PREVIEW, result/stdout/stderr hashes must agree. The
selected snapshot is read-only evidence, not freshness. Known observed failures
remain non-passing. UNKNOWN accounting can never be promoted by a nice report.
Exit 0, no limit failure, exact unchanged post-execution source/examiner, completed
report and known exit-zero accounting are all needed for the scoped success state.

Output schema `vfy.service-test-observation/1`:
`state` is UNKNOWN, OBSERVED_SELECTED_CASES_NON_SUCCESS or
OBSERVED_SELECTED_CASES_SUCCESS. `all_selected_cases_reported_success` is true
only in the last state. Output retains reason codes, report events/summary when
well formed, requirement-to-case observations, exact raw input hashes, selected
checker identity and budgets/counts. It always says semantic_acceptance,
adoption and organizational_authority UNESTABLISHED, authority_granted=false,
automatic_retry=false. This is named process evidence, NOT a semantic verdict.

`retain` creates a new directory exclusively, writes raw bytes byte-for-byte plus
OBSERVATION.json, and writes a pool-owner-signed RECEIPT.json last. A failure may
leave partial evidence; never overwrite/retry that destination or treat a missing
receipt as retained closure. It neither changes the pool nor restores a capability.
Receipt has schema `vfy.service-test-evidence/1`, manifest, observation hash,
checker identity, timestamp, byte counts and the same authority/scope exclusions.
Copies remain evidence; their filesystem location conveys no action authority.
`verify_retained` authenticates the selected pool owner's signature, verifies every
raw member and byte count, and recomputes the observation against the independently
selected frozen inputs. It does not trust OBSERVATION.json merely because it exists.

Limits are explicit reader/retention bounds: total selected+supplied input bytes,
case/requirement counts, total emitted bytes including signature/manifest. They
are NOT resource grants or observed CPU/wall/RAM utilization. The record exposes
these costs and whether retention is charged to the service pool (false). Report
production/output is covered by the existing service reservation; additional
checking and duplicated evidence retention are separately bounded here and still
require allocation by the enclosing workflow for full lifecycle affordability.
No hidden discovery, environment access, re-execution, fallback parsing or grant.

## Installed distribution and retained-attempt entry point

Private wheel directory: `/private/tmp/verify-run-service-tests-artifacts-20261016`.
Installed target: `/private/tmp/verify-run-service-tests-installed-20261016`.
Select by exact wheel SHA256 in SOURCE_IDENTITY.json, not unchanged base package
version 0.1.0a7. Prior service allocator modules/signatures remain byte-identical.

`scripts/check_retained_service.py` provides a keyless CLI for the common empty
predecessor context export. Invoke with the selected dependency-equipped Python
and `-I`, supplying `--installed-root`, `--attempt-root`, `--context`,
`--context-sha256`, `--snapshot-sha256`, `--minimum-revision`, and a NEW `--output`.
It verifies the original context hash supplied by the caller; it does not establish
trust in a context just because the file is next to the report. Context exact keys:
pool_root, config_hex, owner_trust, child_trust, observer, head_hex, policy_hex.
It reads the retained `runner/verify_service_runner.py`; no adapter is imported,
process launched, source recaptured, key reconstructed or pool changed. The CLI
writes an exclusive derived observation JSON, not a new signed owner receipt.

The installed compatibility check used r15 `/private/tmp/verify-service-cfqcstv_`
with its owner-provided context and 13 exact assertion-case selections, including
`test_interruption.ScheduleInterruptionTest.test_schedule_failure_rolls_back_status_and_flip`.
It does not upgrade earlier print-only diagnostic evidence, establish rollback
outside that test scope, or prove in-process output cannot be forged. Preservation
of a named success claim is distinct from semantic truth or requirement sufficiency.
