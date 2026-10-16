# Child-measured exact transport: partial delivery, hosted closure blocked

## Disposition

The original 1060 source members all match SOURCE_MANIFEST.json, totaling
10,039,865 bytes. Manifest SHA256:
`29a068926de05684569b57555996b6d963c4e1ad596741c8a933937192547926`.
No manifest, source, receipt, pin, original store or Engineer file was modified.
No dispatch, preparation, signing, recovery-store access or service execution ran.

**Do not install this packet as a claimed fix for all 52 setup errors.** It is
public retained receipt transport only. The requested exact source-plus-receipt
hosted closure cannot be delivered under the current exclusions and old runtime
contract. Compilation/test volume does not change that boundary.

## Concrete blockers

1. `measured_children.load_reviewed_source` hashes every member, not just imported
   Python modules. The frozen source includes 45 JSON fixtures with literal
   32-byte `private_key_hex` values (complete filename inventory in TRANSPORT.json).
   Examples are `fixtures/authorization/accept_minimum_valid.json` and
   `fixtures/execution/accept_exit_zero.json`. These are **test signing fixtures**,
   not evidence of live owner credentials. Nevertheless, this delivery follows
   the explicit exclusion of signing keys without assuming a fixture exception.
   Omitting/redacting them fails the existing loader; changing the manifest breaks
   its hard-coded SHA. Source bytes are therefore not in this archive. The exact
   old manifest is retained unchanged as an inventory, not as a satisfied load.
2. Even permitting those fixture bytes would not close hosted admission.
   `vfy/child_observer.py:79-83` binds the request to the exact runtime fixture,
   resolves the original executable, reads and hashes it, and checks original cwd.
   Runtime is `/Users/devinbostick/code/verify-engineer/.venv/bin/python`, resolving
   to `/opt/homebrew/Cellar/python@3.14/3.14.2/Frameworks/Python.framework/Versions/3.14/bin/python3.14`,
   SHA256 `0cd2a778ae7152ab55e55529186e2e1accc2bfd68c4c54e3a704df5191852d7f`.
   Linux Python is not that executable. Parent START and pinned payload source
   reads also use original absolute references. A relocated source selection
   does not rewrite these bindings. No replacement executable or path alias was made.
3. `test_measured_admission.py:14` and `test_common_allocation.py:13` call
   `mc.prepare`. Its lines152-154 require the separate original
   `/Users/devinbostick/code/verify/build/child-settlement-numeric-20261007/source`
   and exact selected pins. Preparation creates fresh START/key/store material;
   it is not read-only consumption of this measured demonstration. Tests also
   depend on V21/V24 embedded references outside this archive. These tests were
   inspected, not executed under the no-recreation/no-dispatch instruction.
4. Retained V22 recovery tests call `recover`, which reads `protected_store`,
   `state.json` and pending state selected by original intake. That is mutable
   custody, deliberately excluded. Public report snapshots cannot be relabelled
   as that live store. `common_allocation.load_common` selects another manifest
   through OWNER_SELECTION; a measured-source override alone is not its closure.

The six relevant consumer/test files were compared to `git show 7216311:<path>`
and were byte-identical at review time (current checkout HEAD6b1ad63). The measured
consumer SHA is `0be1cadd8c4dbc1fb9ef0ab4871c49147100000f99bc9d54225b0013e3f16476`.

## Delivered member contract

Private evidence branch directory: `recovery/child-measured-readonly-20261016/`.

Archive: `child-measured-public-receipts.zip`, 311,940 bytes, SHA256
`24451a7929d6143c11ef7322f72f7b80c0890a47c6f7f1699d3a895464fae30f`.

Exactly 44 regular read-only-mode archive members; no symlinks or executable bits:

- `audit/SOURCE_MANIFEST.json`, `audit/OBSERVER_SELECTION.json`.
- For each `first`, `follow-on`, `interrupted`, under `audit/demonstration/<case>/`:
  `trust.json`, `request.json`, `stdout.bin`, `stderr.bin`, `report.json`,
  `input.json`, `basis.json`, `START.json`, `budget.json`, `local-purpose.json`,
  `NOTICE.json`, plus the three original `ledger/reservation-<id>.binding.json`,
  `.acquisition.json`, `.observation.json` companions.

TRANSPORT.json enumerates every exact member, byte length and SHA256. No source
tree, signing key, state.json, lock, pending transaction, owner capability, pool,
pycache or distribution payload is included. Embedded paths remain unchanged.
Public trust bytes are retained historical selections, not new owner authority.

Select the archive by the digest above before inspecting/extracting it; reject
duplicate/unlisted/changed/nonregular/traversing entries against TRANSPORT.json.
Extract only into a fresh destination. Do not populate any protected store.
For a separately available and authorized exact old source, the existing consumer
location selection is:

```json
{"schema":"engineer.input-locations/1","paths":{"run_source":"/absolute/exact-existing-source","run_audit":"/absolute/fresh-extraction/audit"}}
```

`VERIFY_TEST_REVIEWED_INPUTS` selects that file in eu20 tests. This packet supplies
only `run_audit`; it does not supply a valid `run_source` on the hosted runner.
No blanket test-suite invocation is recommended from this packet.

## Validation and residual scope

`package_child_measured_public_receipts.py` verified every original manifest
member, then copied only the explicit public audit allowlist. A separate process
using `check_child_measured_public_transport.py` checked the archive inventory,
extracted it to a fresh directory and invoked the actual unchanged Engineer
loader/companion checker. It used the **original local** exact source, not a
transported source or an installed hosted pair. After extraction, a Python audit
hook rejected filesystem writes, launches and network operations. Output was
captured by the parent shell. All 44 extracted file bytes remained unchanged.

VALIDATION.json retains:

- Three `VERIFIED_SELECTED_SNAPSHOT_NOT_FRESHNESS` reports; interrupted unknown
  children and conservative exposure preserved.
- First completed child `VERIFIED_MEASURED_LOCAL_COMPANIONS`; both unreserved
  later children `UNKNOWN_INCOMPLETE`.
- Missing acquisition, altered signature/output/request, wrong runtime and wrong
  observer controls each `UNKNOWN_MEASUREMENT_CORRESPONDENCE`, retry false.

This independently checks byte transport and retained authentication, not issuer
authority, semantic adequacy, historical execution origin, current freshness,
hosted execution, full cost or CI closure. No test regenerated signed evidence.

Root's remaining integration boundary is to keep authentic historical receipt
checks distinct from tests requiring original runtime/custody. A portable fresh
synthetic admission would be a separately selected successor contract, not a
historical V22 acceptance or a rewrite of the old manifest. This task did not
create that successor. Private backup does not authorize public distribution.
