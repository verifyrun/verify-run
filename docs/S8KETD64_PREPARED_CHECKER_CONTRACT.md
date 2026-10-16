# S8KETD64 disposable preparation and retained checker

Prepared only. Root owns one later actual service run and independent consumer acceptance.
No admission, consume, service execution, old pool reset, or old attempt replay occurred.

Accounting directory: `/private/tmp/verify-run-service-s8ketd64-accounting-20261016`.
The exact paths and hashes are in `PREPARED.json`; select them before opening the session.

| File | SHA256 |
|---|---|
| PROFILE.json | 65d3404911aac21e9bd7c5908e8c870ce52d7f1e2cff299b5af64a93c910dbe6 |
| REQUEST.json | e8e5d33c0b30209a051f2160c8e9aa109444e99404d940e64642f177e00487ad |
| APPROVAL.json | 506af56a6ee210c03835660911739c18768624962528c7c6ff3baa883cff8e8b |
| CONSUMER_CONTEXT.json | 3d4ad9057492867ca0643f15fad5d7c6874d884e309c055eb11ca6d6f9dbc49c |

Exact installed executable: `/private/tmp/verify-run-service-session-env-20261016/bin/vfy`.
Existing public session command: `vfy service-accounting-session --profile PATH --profile-sha256 HEX`.
Use the established Engineer one-use client and protected START/ack/launch ordering.
Session deadline 300 seconds; service limits remain wall 60 seconds, CPU 40 seconds,
128 descriptors, file_bytes 67108864, output_bytes 1048576. New common pool has one slot,
1048576 output bytes and zero usage. Fresh independent development owner/approval keys;
no human, production, provider, semantic or organizational authority. Owner seed and live
pool are intentionally excluded from private backup. Do not copy/reopen them as a reset.

PREVIEW SHA256: `05666f73a27785b53b106a19a3387e1fa00611c395b88b663da53cf612d93dcc`.
Selection SHA256: `b71df825b0cce7c99d437c1ed928983a5991e2b6adc638faf7052ad6436e20f6`.
Frozen requirements copied byte-exact from the prior C7 selection, SHA256
`1edbbb39a1f4fae30244f0c7a10acd786ccbd15640d9d098471dc04782db0879`.
Keyless preflight confirmed 15 exact case IDs, 15 requirements, mapping, runner,
source/examiner/environment identities, labels, adapter/capture and policy correspondence.
No completed observation is claimed.

## Retained checker command, only after Root's actual run

Select the SHA256 of the final retained ACCOUNTING_RESULT.json from the caller receipt
as SNAPSHOT_SHA256. This cannot be supplied before execution; never invent a snapshot.
This Run-owned script uses the unchanged installed checker. It is not a new `vfy`
subcommand or a completed ordinary Engineer UI integration. Engineer must not import vfy.

```sh
/private/tmp/verify-run-service-session-env-20261016/bin/python -I -B \
  /private/tmp/verify-run-service-s8ketd64-checker-20261016/check_retained_service.py \
  --installed-root /private/tmp/verify-run-service-session-env-20261016/lib/python3.14/site-packages \
  --checker-sha256 40b900a8a9d9d2d19a027542df2fa43ce9e6a6a099bca793d861af1c22204a83 \
  --attempt-root /private/tmp/verify-service-s8ketd64 \
  --context /private/tmp/verify-run-service-s8ketd64-accounting-20261016/CONSUMER_CONTEXT.json \
  --context-sha256 3d4ad9057492867ca0643f15fad5d7c6874d884e309c055eb11ca6d6f9dbc49c \
  --snapshot-sha256 "$SNAPSHOT_SHA256" --minimum-revision 4 \
  --requirements /private/tmp/verify-run-service-s8ketd64-accounting-20261016/FROZEN_REQUIREMENTS.json \
  --request /private/tmp/verify-run-service-s8ketd64-accounting-20261016/REQUEST.json \
  --output /private/tmp/verify-service-s8ketd64-selected-observation.json
```

Script SHA256: `976616f8c0d01ee333446dff00cf3ab187141a83c7f507e47883b2bcfcc39569`.
Wheel SHA256: `03731f3a4678339c758c6aeb37cdd35fe050aebf277d0f5dcb181dabca0e42a8`.
No module/old plan identity changed. This command reads no owner seed or live store,
imports no Engineer executor, and cannot acquire a live pool capability. It writes only
one exclusive NEW derived JSON observation; it does not sign a receipt or charge a pool.

Inputs are bounded by the existing 4 MiB/member limit and 16 MiB checker input budget,
4096 case events and 1024 requirements. Context authentication validates signed accounting,
selected owner trust/config/policy/predecessor/root and revision floor. Exact request,
START, PREVIEW, raw result/streams and frozen selection are bound by the checker.
Duplicate/missing/extra cases and incomplete or uncertain output cannot succeed;
skips/failures/errors do not yield selected-case success. The runner's in-process report
remains untrusted process evidence, not semantic truth.

Exit zero means a derived observation was written, NOT acceptance: inspect JSON state.
Only OBSERVED_SELECTED_CASES_SUCCESS establishes all selected cases reported success.
UNKNOWN and OBSERVED_SELECTED_CASES_NON_SUCCESS do not pass. Setup/input refusals exit
nonzero; no automatic retry. Output is historical, no freshness/authority inference.
Read/check CPU/wall and global retention are UNESTABLISHED; additional evidence is not
charged to this service pool. Full lifecycle accounting remains OPEN.

Installed validation: exact prelaunch bindings PASS; read-only consume refuses; wrong
checker pin refuses; incomplete attempt (absent final accounting) refuses without output.
Actual new service/checker acceptance remains pending Root's separately authorized run.
