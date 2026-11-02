# Public execution report 1

`vfy --json --execution-report run -- <command>` adds `execution_report` to the existing JSON
response. Without the option, the historical field set and signed receipt format are unchanged.
The option requires `--json` and `run`. This is operational reporting, not a new acceptance profile.

The report has exact fields:

| field | values / meaning |
|---|---|
| `version` | `1` |
| `launcher_execution` | `started`, `not_started`, `unknown`; the directly authorized process, not a nested checker |
| `checker_execution` | `not_observed`; Run does not authenticate nested checker observations |
| `context_refusal` | `not_observed`; no exit code, including 65, proves context refusal |
| `nonce_consumption` | `consumed`, `not_consumed`, `unknown`; the attempt's consumption status |
| `receipt_availability` | `committed`, `preserved_uncommitted`, `inline_uncommitted`, `unavailable`, `unknown` |
| `completion` | `exited`, `timed_out`, `signalled`, `not_started`, `unknown` |
| `trust_policy` | `supplied_snapshot`; not immediate on-disk revocation ordering |
| `automatic_retry_permitted` | `false` |
| `recovery` | `new_request_only`, `inspect_recorded_attempt`, `reconcile_before_new_request` |

A normal decision that did not execute consumes nothing. A completed ALLOW attempt reports actual
launch and completion plus consumption and committed receipt. An executable that cannot start can
still consume authority and produce a receipt; `not_started` is not `not_consumed`.
Recording failures report the known consumed attempt, actual observed completion where available,
and whether a signed receipt was preserved, returned inline or never produced. Other typed or
unexpected failures conservatively report unknown state unless the runtime has those observations.
A killed runtime, missing/truncated response, or lost transport has no reliable report: the consumer
MUST synthesize unknown state, not false booleans or successful completion.

An issued authorization, ALLOW result, consumption record, exit status, receipt and application effect
are different facts. A receipt from a refused launcher does not establish that a checker started.
Engineer owns an independently authenticated observation format for checker entry, context refusal,
semantic evidence and application acknowledgment. Generic Run cannot infer these from stdout or an
exit value: checker code itself can exit 65. If the selected task requires such distinctions as
acceptance evidence and no supported observation adapter exists, that task must be refused.

## Recovery and ownership

Run never automatically retries an action. Consumption is single-use within its declared local
store scope; a new `vfy run` creates new authority and can repeat effects. A returned completion or
receipt does not make repetition safe. `new_request_only` means a caller can evaluate a distinct
request under fresh authority; it is not advice to retry the previous effect. `inspect_recorded_attempt`
means use the existing receipt and application acknowledgment. `reconcile_before_new_request`
requires resolving uncertain effects/consumption with the authority and application owners first.

After interruption: retain the invocation identity and available receipt/consumption records;
inspect existing records via the public receipt commands; authenticate any uncommitted receipt
before trusting it; reconcile actual destination/effects through the Engineer adapter. No receipt
alone is evidence of no effects. If existing APIs cannot identify an interrupted attempt, report
that recovery gap and keep automatic retry disabled. There is no public external-token spending,
request-id lookup or cross-store exactly-once API in this version.

Trust is loaded as a snapshot for the attempt. Changes after preparation do not cancel that
snapshot. Immediate update/launch ordering requires an authority-owner service or admission lock
covering both operations, outside this local CLI's present guarantee. The signing-key preflight
checks that each seed matches its active trusted identity before consumption or launch.
