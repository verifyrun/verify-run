# Independent Run review of Engineer af81fef

Read-only source review of af81fef2f628783e7feaa2413b45cc160e48e39c in
/private/tmp/verify-engineer-continuation-20261013. No Engineer edits, tests,
retained reconciliation, receipt verification or service actions executed by this
review. Reported installed acceptance belongs to Root, not an independently rerun
acceptance here.

P2: reject internally contradictory or incomplete successful read replies.
service_read_cli.py:84-94 accepts a reply without validating error,
read_incomplete, read_usage or the command-specific result shape. In particular,
an exit0 reply with matching schema/command/request hash/mode, all outer false
flags and full_cost UNKNOWN, plus read_incomplete=true and
result={state:OBSERVED_CANDIDATE,content_state:CANDIDATE} passes transport validation.
service_repair_view.py:60 then renders "The saved repair matches this managed copy."
The producer contract requires an incomplete read to result in UNKNOWN. Current
Run does not emit this contradictory reply, but the consumer's declared hostile
reply validation does not enforce that boundary. An error!=null is also accepted.

Smallest correction owned by Root: validate exact response fields/types and error
null for READ_COMPLETED; require incomplete reconciliation to retain UNKNOWN;
validate read usage against selected limits and command-specific result schema/
flags before rendering success. Do not reject legitimate completed UNKNOWN as a
transport failure or add a replay path. Add hostile contradiction/missing-field
controls; the current test fixture itself omits these response fields.

No additional source-isolation, secret-transfer or operation-replay finding in the
three reviewed files. They invoke the public executable and preserve outer no-
authority/no-retry, historical scope, uncharged-read limitation and display exit2.
Executable selection still relies on existing VFY/environment installation trust;
a matching request echo is not independent authentication of a malicious executable.
No broad architecture/CI, execution/accounting or full-chain acceptance inferred.

Accounting continuation: new Run-owned candidate documented in
SERVICE_ACCOUNTING_CLI_CONTRACT.md. Producer synthetic and installed checks are
separate from Root's independent consumer/ordering acceptance. No new independent
external review of that implementation has been claimed in this turn.
