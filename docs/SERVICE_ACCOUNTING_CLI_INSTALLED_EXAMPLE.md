# Installed development accounting CLI — exact one-use example

Producer implementation: f7db114e4f8acb59935ffa70859cf8a8bef08921.
Wheel (unchanged by this documentation/example follow-up):
/private/tmp/verify-run-service-session-artifacts-20261016/verify_run-0.1.0a7-py3-none-any.whl
SHA256 03731f3a4678339c758c6aeb37cdd35fe050aebf277d0f5dcb181dabca0e42a8.
Executable /private/tmp/verify-run-service-session-env-20261016/bin/vfy.
Exact protocol/profile is SERVICE_ACCOUNTING_CLI_CONTRACT.md.

## Already completed retained example — inspect, do not repeat

Actual public command launched by stdlib-only consumer (no vfy/Engineer imports):

```
/private/tmp/verify-run-service-session-env-20261016/bin/vfy service-accounting-session \
  --profile /private/var/folders/cf/v8sng4m17ygfnbt3k7ljpxfr0000gn/T/tmpkbz9_y2q/SESSION_PROFILE.json \
  --profile-sha256 8b9e0ddddf5d51a9ad59f48662cb3aeb9b7bc50752d3d23dccb07693d0a47297
```

Recorded exit0, OPEN -> ADMITTED -> CONSUMED -> SETTLED. The final signed entry is
UNKNOWN: synthetic LAUNCH_FAILED/no execution, deliberately not a fake process
success. Consumer holds ACCOUNTING.lock, fsyncs START before CONSUME and retains
consumption before creating the explicit synthetic no-execution result. Owner key
stays inside the Run process. No original C7 or used admission was involved.

Profile, request, approval and selection are under that same fresh root. Exact
request/reply bytes and SUMMARY.json are in its transcript/ directory. Selection
and root are now consumed; do not run the command again. The local fixture seed is
mode0600 and intentionally excluded from backup. It is a public deterministic
synthetic fixture key, not a production key or current organizational permission.

## Prepare another fresh synthetic setup for a new independent test

Run-owner fixture setup (never import this in Engineer):

```
/private/tmp/verify-run-service-session-env-20261016/bin/python -I -B \
  /private/tmp/verify-run-service-session-cli-20261016/scripts/prepare_service_accounting_cli_example.py \
  /private/tmp/verify-run-service-session-checks-20261016 \
  /private/tmp/verify-run-service-session-env-20261016/lib/python3.14/site-packages \
  /private/tmp/verify-run-service-session-cli-20261016/scripts/service_accounting_cli_example_client.py \
  /private/tmp/verify-run-service-session-env-20261016/bin/vfy
```

This prints a NEW selection path/hash and exact stdlib-consumer command. Execute
that emitted command once only. It provisions a fresh test fixture explicitly;
the public session CLI has no provision/attach/reset/grant entry. For real consumer
wiring the Run owner supplies an independently selected existing service epoch,
not this fixture factory or a replacement budget. Profile inputs embed exact
snapshot/config/predecessor/policy and managed legacy bytes with SHA256; selection
supplies independent public trust/observer/callback identities and minimum revision.
The key_file is Run-owner-selected development key custody, not an Engineer seed.

## Actual installed controls and reproduction

/private/tmp/run-service-session-installed-pass.log records 122 installed checks;
the first 18 use the public console subprocess. Installed module origin is printed.
Exact reproduction harness (creates NEW disposable cases, never used tickets):

```
/private/tmp/verify-run-service-session-env-20261016/bin/python -I -B \
  /private/tmp/verify-run-service-session-cli-20261016/scripts/check_service_accounting_cli_install.py \
  /private/tmp/verify-run-service-session-checks-20261016 \
  /private/tmp/verify-run-service-session-env-20261016/lib/python3.14/site-packages \
  /private/tmp/verify-run-service-session-env-20261016/bin/vfy
```

Controls: successful signed zero-exit synthetic evidence/reopen refusal; bad key
permissions/runtime identity; changed head; changed PREVIEW; concurrent session;
duplicate consume; EOF; SIGKILL after admission and after consumption; lost consume
ack; managed predecessor usage preservation; oversized frame; shared exhaustion;
tampered result; timeout; wrong approval; wrong session/sequence/version; wrong
START. Failed/interrupted reservations remain held, no new pools or grants are
created by the CLI, reopened capabilities cannot launch. The full suite also checks
historical readers, unchanged allocator behavior and existing CLI architecture.

pip check passed after normal --no-index installation in a copied isolated development
environment; no --no-deps install and no source-path injection into actual public
console/stdlib consumer. Build used --no-deps only to build the Run wheel, with local
setuptools. No package-release or broad Engineer compatibility claim. Root must
independently accept its shared lock/START/ack/runtime/approval integration before
ungating execute_accounted; full cost and Platform/current production authority OPEN.
