# Engineer f4799a2 re-review and fresh Run accounting preparation

Reviewed f4799a2ea196e3d7c1226f39f67658830cf1d957 source read-only. Root reports
40 source+40 installed controls and Engineer wheel
40d6fcbf5a156332ba51a533202634057f42839cf1657d3253a2b8450effa9a5.
No Engineer import/edit, service execution, admission or consumption performed here.

Previous cleanup/watchdog findings are addressed at their tested scope: caller lock
finally closes even if session close fails; original exception retains a cleanup
note; pipes close in finally on reap timeout; between-exchange timer kills Run;
ensure_live is called immediately before service Popen after retained consume ack.
Reader incomplete state/content UNKNOWN fix remains present.

One remaining P2 startup path: Session creates/starts the watchdog after Popen but
before entering its cleanup try. If Timer.start raises (for example thread creation
failure), __init__ exits without closing the spawned Run child; execute_accounted's
session variable is still None so outer cleanup cannot close it. Move Timer setup/
start inside protected initialization, make close tolerate absent/unstarted timer,
and test injected Timer.start failure closes/kills the spawned process. This is a
client-only correction; frozen service_observation bytes/PREVIEW need not change.
Execution review acceptance is held on this small correction. No Run wire change.

## Explicitly authorized independent preparation completed

PREVIEW /private/tmp/verify-service-71kbdb5s/PREVIEW.json
SHA256 6bcc0bc1234aba651966664e14d7ee09a8fd67802f3165b1bdbdc492961bb804
Adapter hash matches reviewed service_observation source:
1adb9a7b29368ef52f359599c92f8041c8ae4b7d545bd5c9976d64e609c36ad4.
Frozen test-selection digest preserved:
066a338a213b3507ff79cb2304ebb799dd94c512e555cc0274473b25655d362f.

New owner root /private/tmp/verify-run-service-71kbdb5s-accounting-20261016.
PREPARED.json records every exact public file/hash. Main selected inputs:
- PROFILE.json 2dd2cf8ad19ed41f0b4b9d384fd59d7944bd4384d5282f3ffac28f46ad8a529e
- REQUEST.json 33627fde4000ff37178e1ca554ee341a993ff62ec46a69bc448d9ea4040ceee7
- APPROVAL.json 2c72330ecd6902f06d5966bc85497304226723dcc447eb64474846bc75691221
- SELECTED_HEAD.json f52b761b16506b6a8aa74242177fadd932d334f709534444dd1cd3d2343765d0

This is a NEW explicitly disposable common pool transitioned to the service epoch,
not a reset/reattachment/grant on any old pool. Empty predecessor has no child dispatch
or measured-child acceptance claim. Its observer selection explicitly says
NO_CHILD_DISPATCH_SELECTED. Independent fresh development owner/approval/unused-child
public keys selected; no production or human/organizational rights inferred. Only
owner seed retained locally mode0600; no seeds included in backup. Approval attests
exact accounting request/PREVIEW/policy, not service effect authority.

Capacities: 1 shared slot, 1048576 retained output bytes; service resources exactly
wall_seconds60, cpu_seconds40, output_bytes1048576, file_bytes67108864,
descriptors128. Usage is zero. This context has no spare slot after the requested
single service attempt, and no automatic grant/refund. Session deadline300s.

Installed Run selected_pool loader validated profile, owner key/trust, predecessor,
head/policy, request, preview and signed approval. Snapshot and PREVIEW bytes were
unchanged afterward, no attempt START.json or ACCOUNTING.json exists. No admit,
consume or launch API was called; Root alone owns the later once-only service run.

Executable /private/tmp/verify-run-service-session-env-20261016/bin/vfy
Wheel SHA256 03731f3a4678339c758c6aeb37cdd35fe050aebf277d0f5dcb181dabca0e42a8
No runtime/wheel change. Do not run preparation again at this existing root. The
preparation script refuses existing destinations; prior pools/C7 remain untouched.
Full costs, installed actual-service acceptance, Platform/current authority and
full V1 remain OPEN. Public release held.
