# Local custody handoff — development protocol 1

Private source successor `0.1.0a6+custody.dev1` (source only; no wheel built); no published contract, active installation or consumer adoption.
Trusted local controller protects worker installation, intent directory and source/control
selection. This is a cooperating-writer protocol, not isolation from hostile same-user code.

Opt-in CLI: `vfy --json --execution-report run --custody-handoff FILE -- <exact argv>`.
Existing calls are unchanged. Exactly one owned duplicate of a bound read-only regular-file
lease descriptor is inherited with close_fds=True. Only VFY_CUSTODY_HANDOFF is generated;
no ambient environment or descriptor set is forwarded. Explicit execution environment stays
unchanged, except collision with that reserved name refuses.

Envelope exact keys: binding, intent_path, intent_sha256, fd. Binding exact keys:
version=1, operation_id/source_id (64 lowercase hex), argv (exact command),
lease={device,inode}, worker_files={absolute real path:sha256}, worker_data (mapping),
coverage="guarded-intents-v1". All trusted worker/guard files needed by the owner boundary
must be listed; argv[0] must be listed. Run verifies bytes, not transitive Python imports.
Same file identity is not proof of same open-file description or lock acquisition: trusted
owner acquires the live lease. Descriptor number is transport, not operation identity.

Protected owner-precreated durable intent, canonical JSON exactly:
{schema:"vfy.custody-intent/1", binding_sha256:<canonical binding hash>, state:"PENDING"}.
The envelope binds its absolute path and SHA256. No `<intent_path>.terminal.json` may exist.
Run validates before acquisition and again after authorization verification, before consumption.
Command evidence providers refuse before acquisition; no provider transfer is implemented.
Candidate action.params.run_custody_sha256 commits canonical envelope excluding transport fd,
within the existing signed action digest. Changed operation/source/worker/intent/data or argv
refuses. No new permission, decision, nonce scope, receipt schema or replay meaning is added.

Worker receives {binding,intent_path,intent_sha256,handoff_sha256,fd:<owned duplicate>}
via VFY_CUSTODY_HANDOFF. Guarded startup validates before writes. Environment presence alone
is not authority. This generic protocol needs an examined Engineer bridge, not ambient
ENGINEER_SOURCE_LEASE forwarding. Current native92 GuardedPopen rejects Run and replaces
its own inherited envelopes; it must not silently adopt this contract.

Only after actual wait/poll observes direct-child exit, Run exclusively creates canonical
`<intent_path>.terminal.json`: schema=vfy.custody-terminal/1, handoff_sha256, returncode, pid (observed direct child),
scope=DIRECT_CHILD_ONLY. Known Popen start failure uses null returncode and NOT_STARTED.
No observed exit means no terminal. Write failure/partial terminal means UNKNOWN to owner.
Receipt construction still proceeds: lifecycle-record loss must not erase the action receipt.
BLOCK/HOLD/pre-consumption refusals leave unused intents for explicit owner reconciliation.
No return, timeout, receipt or terminal claims stopped-source status or permits retry.

Lifecycle owner (Engineer) must retain its original root writer intent until exact Run
terminal correlation, and recursively retain every permitted writer's intent and lease.
Only exact guarded worker entries or enforced no-fork helpers are permitted. Stop requires:
exclusive SAME fixed lease AND no pending/UNKNOWN root or descendant intents AND unchanged
source/control identities and stable source observation. A detached guarded grandchild has
its own intent. Parent death leaves UNKNOWN, even if child eventually exits. A leader's
terminal cannot clear grandchildren. Unsupported raw fork, shell, provider or unguarded
helper must refuse. This boundary is supplied by the examined lifecycle owner; the coverage
string is not sandbox enforcement and generic callers lacking it cannot use the profile.

Run remains local; no Engineer imports or ledger/journal mutation. Run terminal is a
separate direct-child observation. Engineer must explicitly integrate/read/authenticate it
and preserve original operation and allowance. This source successor alone does not remove
Engineer92's route refusal, establish genuine acceptance, or authorize pin migration.

One-use dispatch: after exact authorization verification/preflight and before consume,
Run exclusively creates `<intent_path>.claimed` with handoff digest and authorization ID.
It is never removed/reset, including failed consume or parent death. Concurrent/repeated
use refuses before consumption; partial claim is still claimed and UNKNOWN. The owner
cannot reuse an intent under fresh authority. This closes the duplicate-root dispatch race.
Descriptor duplication reserves a close-on-exec handle >=3, even with closed stdio.
