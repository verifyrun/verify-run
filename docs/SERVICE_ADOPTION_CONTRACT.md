# Isolated service repair adoption / 1

New Run-owned `vfy.service-adoption/1`, not a relabelling of reminder repair or
managed-json-receipt/1. No service execution, original repository writes, production
promotion, semantic sufficiency, organizational authority or full V1 closure.

Reusable seams inspected: authorization.verify_authorization already recomputes
ALLOW and binds action/rulebook/evidence/runtime/current key status/expiry; LocalStore
consumes a nonce atomically. runner.execute_authorized_command only admits commands
and must NOT be used to execute adoption. Existing managed_capacity handles only a
fixed JSON callback. New adoption therefore uses a custom action and its own bounded
file replacement implementation, plus an explicit shared-pool successor profile.

## Exact API

```python
from vfy.service_adoption import (
    provision_managed_copy, prepare_adoption, action_for, AdoptionPool,
    adopt, reconcile, identity)
limits = dict(files=2000, source_bytes=16777216, read_bytes=67108864,
              write_bytes=1048576, file_mutations=10, journal_bytes=2097152)
root = provision_managed_copy(base_manifest_bytes=base_raw, base_files=base_bytes_by_path,
                             original_root=original_repository, limits=limits)
plan = prepare_adoption(root, candidate_manifest_bytes=candidate_raw,
                        candidate_files=candidate_bytes_by_path, task_id=task_id,
                        checker=selected_checker, check_inputs=retained_check_inputs,
                        limits=limits)
candidate = action_for(plan)  # exact custom action for existing Run authorization
pool = AdoptionPool.attach(selected_live_service_pool,
    expected_snapshot_bytes=selected_service_head, policy_bytes=policy_raw)
ticket = pool.reserve(plan, recorded_at=current_time)
# Issue an explicit CURRENT action authorization over candidate using existing
# Run rulebook/snapshot/gate/authorization APIs. Test evidence is not approval.
receipt = adopt(root, plan, pool=pool, ticket=ticket,
    pinned=selected_rulebook, snapshot=authorization_evidence, result=allow_result,
    authorization=authorization_value, runtime_id=selected_runtime,
    verification_time=current_time, authorization_keys=current_action_key_registry,
    registry=schema_registry, authorization_store=selected_existing_nonce_store)
status = reconcile(root, plan, owner_trust=selected_pool_owner_trust)
```

The exact constructor for reopening the accounting successor is
`AdoptionPool(selected_service_pool, expected_snapshot_bytes=old_head, policy_bytes=policy)`.
It does not restore live reservation tokens. Reopened reservations cannot adopt.
`pool.snapshot()` and `pool.verify_snapshot(raw)` inspect signed accounting.
`reconcile` is independent of live pool/key access and never writes or retries.

## Source and destination binding

Manifests are strict Run JSON objects `{relative/path: {sha256, bytes, executable}}`,
matching Engineer capture. The executable field is only the POSIX execute bits;
other permissions/empty directories/ownership are outside source identity. Each
file <=4 MiB; total files/bytes obey selected limits. No symlinks, hardlinks,
special files, `.git` components, traversal, absolute paths or directory/file
prefix conflicts. Source file population is frozen: this first profile supports
replacing regular files (including execute-mode changes), not adding/deleting or
renaming source paths. This supports the complete 1269-file service subject and
its views.py replacement without claiming a pristine upstream tree.

`base_files` and `candidate_files` are maps from every manifest path to bytes;
they must match the exact complete manifest. No original source path is opened
for writing. provision creates a NEW private `verify-service-adoption-*` directory
directly under canonical system temp, records its root/device/inode/uid plus the
copy directory's identity, and populates `copy/` with base bytes. It must be disjoint
from original_root. The provenance is a captured base, not an upstream-commit claim.

prepare checks the whole managed copy is BASE; recomputes the selected checker
result; requires OBSERVED_SELECTED_CASES_SUCCESS and exact candidate manifest ==
the tested PREVIEW.source. It stores the raw base/candidate manifests, selected
requirements/selection/runner and check input bytes, derived check record and
candidate replacement bytes. Plan binds their hashes, task_id, original root,
destination/fixture identity, complete manifests, changed paths, producer identity
and all limits. No interpretation of the frozen requirement statements is added.

Plan schema `vfy.service-adoption-plan/1`: fixture, original_root, destination,
task_id, base_manifest, candidate_manifest, changed_paths, evidence_sha256,
check_sha256, requirements_sha256, selection_sha256, producer_identity, limits,
accounting_pool_root, accounting_predecessor_sha256,
authority_granted=false, automatic_retry=false. `action_for(plan)` is exactly
`{candidate_id: sha256(canonical plan), kind: custom, action: {summary:
"Adopt approved service repair into isolated managed copy", tool:
"vfy.service-adoption/1", targets:[destination], params:{plan_sha256:<hex>}}}`.
Changing ANY bound input, destination or limit changes the action digest.

## Accounting and authority

Policy exact keys: schema=`vfy.service-adoption-policy/1`, pool_root,
predecessor_sha256 (raw selected service head), producer_identity=`identity()`,
resource_capacities={read_bytes,write_bytes,file_mutations,journal_bytes}, runtime_id,
authorization_store_root, action_key={key_id,key_version,public_key_hex}, and both
false flags. The action key must differ from the accounting owner key. The current
key registry must select that exact key as active; revoked/retired/expired/wrong
runtime/wrong action authorizations refuse. Caller supplies the current verification
instant under the trusted runtime clock; historical verification is never used.
The nonce store is the independently selected existing LocalStore at the exact
policy root, not a per-attempt replacement store. It is distinct from source/copy.

Attach advances the SAME pool state under its existing lock, validating and
preserving the original service snapshot verbatim. Old handles refuse mutations.
No grants, resets, refunds or inferred authority. Existing work/pools/history are
not migrated implicitly. Consumer selects/authorizes the exact transition head.
The plan binds the exact checked service pool root and raw accounting head. Reserve
refuses any different pool or predecessor; approval therefore binds this inherited
accounting identity too. Every reservation charges one shared dispatch slot, journal_bytes shared retained
output capacity, and the four declared adoption resource coordinates cumulatively.
All failure/interruption charges remain held. Original service resource totals
remain in the signed prefix. This is a new explicit accounting profile extension.

Resource units: read_bytes bounds selected PLAN/base/candidate manifest, retained
evidence, source-tree and candidate replacement verification payload reads during
one consumed attempt. It excludes fixture/lock metadata, authorization/nonce-store
and shared pool metadata, module identity reads, reservation admission, preparation
and read-only reconciliation. Total adoption I/O and lifecycle accounting are UNKNOWN;
write_bytes is staged replacement payload written; file_mutations counts replaced
source paths; journal_bytes bounds plan/evidence/intent/completion retained bytes.
Preparation/base-copy creation is separately structurally bounded and measured,
not silently counted as already-reserved adoption work. Full lifecycle preparation,
CPU/wall, disk allocation overhead and global retention accounting remain OPEN.
The adopted copy has no execution mechanism, network step or service launch.

## One intent, interruption, reconciliation

Before mutation: verify current exact authorization and selected store/key/runtime;
hold the provisioned fixture lock; consume the live resource reservation BEFORE
selected payload reads; compare saved plan/evidence and rescan full BASE; consume
the nonce and fsync consumption; write/fsync one
INTENT.json binding plan, authorization, reservation and full current source.
Then write candidate staging files and atomically replace selected paths, fsync
their directories, verify the whole CANDIDATE and write the signed COMPLETE record.
A failed source/evidence validation consumes the reservation even before INTENT.json
exists; its pool entry retains the planned intent hash. Wrong runtime/key/approval
refuses before selected payload reads and resource consumption. Any failure below
resource consumption retains UNKNOWN/no replay; partial staging or intent
is never cleaned up to make a retry possible. No automatic rollback or resume.
Concurrent calls share the fixture lock and same pool lock; at most one can consume.

`reconcile` reports content_state BASE/CANDIDATE/MIXED/UNKNOWN. MIXED means every
observed path matches either its base or candidate version but the complete tree
matches neither. Unexpected/missing/extra/aliased/unreadable content is UNKNOWN.
Content at CANDIDATE without a valid completion receipt is not known completion.
BASE with an intent is not permission to retry. Receipt verification requires
independently selected owner trust; absent/malformed/partial records remain UNKNOWN.
All reconciliation results set automatic_retry=false and no service_execution.
They preserve earlier uncertainty, never synthesize a completed original operation.

Trusted local single controller, Python/OS and cooperative locking remain bounds;
this is not hostile-owner storage/rollback resistance or live Platform authority.
Full V1 ordinary entry, Platform continuity, current authority and semantic/adoption
product acceptance remain distinct obligations even after local component tests.

## Fault controls and receipt states

The test-only `_fault(stage)` seam is called with `after_intent`, `after_replace`
(once per changed path), and `before_complete`. A process may be interrupted there;
no recovery executor exists. Signed completion is `OBSERVED_CANDIDATE`; reconciliation
returns this state only with selected owner trust and exact CANDIDATE content. Other
cases remain `UNKNOWN` with the separate content_state. Measured journal_bytes
includes a conservative 32768-byte final-record allowance, not exact disk usage.
