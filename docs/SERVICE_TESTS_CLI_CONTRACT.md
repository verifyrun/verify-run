# Public retained selected-case CLI /1

Command: `vfy check-service-tests --request-sha256 HEX`.
One exact UTF-8 JSON document on stdin, EOF, one JSON response plus newline on stdout.
No action flags, paths to read, live store access, keys, reserve/consume/settle/retain,
service execution, source recapture or retry. Recorded paths identify evidence only.

## Request: vfy.check-service-tests-request/1

Exact outer fields:
- `schema`: `vfy.check-service-tests-request/1`
- `module_sha256`: `40b900a8a9d9d2d19a027542df2fa43ce9e6a6a099bca793d861af1c22204a83`
- `minimum_revision`: selected positive integer, normally 4 for the completed attempt
- `limits`: exact positive integer fields `input_bytes`, `output_bytes`, `cases`, `requirements`
- `inputs`: exact fields `context`, `snapshot`, `selection`, `requirements`, `runner`,
  `preview`, `start`, `result`, `stdout`, `stderr`, `request`

Each input is exactly `{ "base64": "canonical RFC4648 encoding", "sha256": "lowercase hex" }`.
The command-line digest binds the entire exact stdin, not a reserialization. Caller selects
trust and hashes independently before invocation. Do not derive trusted expectations from
untrusted response fields. No private keys may be included.

Context is the existing common-predecessor export with exact fields `pool_root`, `config_hex`,
`owner_trust`, `child_trust`, `observer`, `head_hex`, `policy_hex`. Hex strings are canonical
lowercase. Only an empty signed vfy.common-capacity-state/1 predecessor is supported; other
predecessors refuse, not silently converted. This limitation matches the selected S8KETD64
context. Public trust/config/policy/root/predecessor and the selected final snapshot authenticate
through the unchanged keyless load_service_pool. `snapshot` is final ACCOUNTING_RESULT bytes;
`request` is the original accounting request, not this CLI envelope. Requirements, selection,
runner and raw PREVIEW/START/RESULT/streams feed the unchanged TestObservationChecker.

## Bounds and status

Maximum wire stdin 25165824 bytes (24 MiB); member 4194304 bytes (4 MiB); total decoded
input bytes <= selected input_bytes <= 16777216 (16 MiB). Context's three hex payloads are
additionally decoded with individual 4 MiB caps and already bounded by the context member.
Maximum cases 4096 and requirements 1024. Selected stdout bound 1024..1048576 bytes.
Checker retained_bytes remains 33554432 for identity/contract compatibility; this command
retains/signs nothing. Strict JSON loader rejects duplicate keys and unsupported values.
The caller must enforce a process deadline and close stdin; this command does not promise
an internal wall/CPU deadline or total-memory bound. These are byte/count limits, not paid
lifecycle accounting. Interpreter/import/self-code reads and parsing costs are uncharged;
full_cost UNKNOWN. No live accounting reservation is implied by reading a paid attempt.

Exact response fields:
`schema`, `command`, `request_sha256`, `state`, `mode`, `result`, `error`,
`current_source_checked`, `read_cost_charged`, `full_cost`, `authority_granted`, `automatic_retry`.

- schema: `vfy.service-tests-cli-response/1`; command: `check-service-tests`
- mode: `HISTORICAL_SELECTED_CASES`; current_source_checked/read_cost_charged false
- full_cost: `UNKNOWN`; authority_granted/automatic_retry false
- state READ_COMPLETED: result is the unchanged vfy.service-test-observation/1; error null
- state REFUSED: result null; error is a short exception class, never raw evidence
- request_sha256 matches selected request; malformed excessively long digest may be null
  in bounded refusal only, never a usable completed response

Exit 0 = completed reading, NOT passing observation. Inner UNKNOWN/non-success remains
nonpassing. Only inner OBSERVED_SELECTED_CASES_SUCCESS means all exact selected cases
reported success. No semantic sufficiency, adoption, source freshness or authority inference.
Exit 12 = refusal; 1 = output I/O failure; 2 = CLI usage. On valid selected requests refusal
fits 1024 bytes. Caller verifies exact outer fields/types/command/hash/flags and inner shape,
preserves UNKNOWN and does not infer acceptance from exit0. No automatic action retry.

## Installed candidate and exact retained example

Executable: `/private/tmp/verify-run-service-tests-cli-env-20261016/bin/vfy`.
Wheel: `/private/tmp/verify-run-service-tests-cli-artifacts-20261016/verify_run-0.1.0a7-py3-none-any.whl`
SHA256: `2f11458f05ef91795baa78b9bff47f4be798c3193ddd04139a42e42c3e882ff6`.
New service_tests_cli.py SHA256:
`42b1ea65561bb17f3794a321f6e9c20496a470262ea6a0ce4cf6c260baf11e50`.
This candidate is private; same a7 version label alone does not select it. Installed into a
new copy of the existing dependency-equipped development environment using --no-deps;
pip check passes. This is not a new normal-dependency Engineer-pair acceptance.

```sh
/private/tmp/verify-run-service-tests-cli-env-20261016/bin/vfy check-service-tests \
  --request-sha256 59d8c906d7a5e8c2bfb55285573d6fe56431b77f9fb8f0310f1db8554c677569 \
  < /private/tmp/verify-run-service-tests-cli-artifacts-20261016/S8KETD64_REQUEST.json
```

Already tested against retained bytes, no service execution needed. Response artifact:
`/private/tmp/verify-run-service-tests-cli-artifacts-20261016/S8KETD64_RESPONSE.json`, SHA256
`ed701af5b59000b472567ee8f4c17b10c370a5a90c95de44f40691fea881136a`.
Its inner object equals the exact previously accepted selected observation: all 15 cases,
no reasons, semantic UNESTABLISHED. Every input digest tamper refused; rebound malformed
stdout produced inner UNKNOWN. Protected retained evidence/pool bytes unchanged.

Source and installed synthetic checker/protocol suites: 40 checks each, including existing
case-outcome controls and eight new protocol test methods. Installed stdlib-only consumer
uses only public CLI, with no vfy import or sys.path change. Dependency, service_tests,
service_attempt, service_adoption, service_review, receipt/read/accounting CLI module bytes
compared unchanged to previous installed modules (see INSTALLED_VALIDATION.json for list).
Only new wrapper plus CLI dispatch added. Old wheel/environment and historical plans preserved.

Root owns ordinary Engineer subprocess wiring and separate consumer acceptance. Verify this
exact wheel and wrapper selection before integration. No public release/Platform/full-V1
closure is implied. Independent integration review remains needed after consumer wiring.
