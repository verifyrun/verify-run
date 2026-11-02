# Corrected Engineer selected-case consumer re-examination

Disposition: ORIGINAL_REPRODUCTIONS_CLOSED; RESIDUAL_CHANGES_REQUIRED.
No Engineer edits, service replay, Run invocation or pool changes. AST-extracted validation
and rendering were exercised on copies of the retained request/response; cleanup used fakes.

Exact source SHA256:
- service_test_view.py: de8e5e3560888885cb49048276a0a1ec930aee3ba19ef1ce62c8020e6003adc0
- service_read_cli.py: 752e792c2dcc7dbdcbfd082aaa2d1b082176e7c4ae78182f70547ed0ccc85682
- cli.py: 5951a49e7d80d2f48afbaed7ca0579b3bf7cae53cce147071dbff841bbc78caf

All eight original mutations now refuse: foreign refs, incomplete report, failed/missing/
duplicate cases, empty requirements, empty limits and invalid numeric costs. The real retained
positive response still validates. A partial/null UNKNOWN remains UNKNOWN and renders no
success. The original simulated final-wait error now receives timeout=1 and closes pipes and
selector. These corrections are accepted, not reopened.

## Remaining P1: report still not bound to selected raw stdout

The prior review explicitly required binding report to selected raw stdout. The implementation
compares claimed report to selected IDs/mapping, but not to the selected stdout document.
Reproduction: copy the valid request, change raw stdout's first case to failure, update its
input hash, corresponding result refs and exact outer wire digest; keep response report as
all-success. validate_response accepts and render reports success. No selected service bytes
were changed: this is an in-memory hostile reply/packet consistency test.

Also reproduced: report.schema changed to foreign.report/99 still accepted; input_bytes=0
accepted despite nonempty selected checker inputs. Thus exact report shape and exact input
count are not yet verified. Existing positive test success_pair uses stdout bytes b'stdout'
(not the reported JSON), so it currently encodes this missing binding.

Smallest completion: strict-decode the selected stdout member, authenticate its digest, and
require the returned report to match that exact parsed document for successful observations;
require exact engineer.service-tests/1 fields and exact event shapes, while retaining the
already implemented success consistency checks. Calculate checker input_bytes from the nine
selected checker input byte members (selection, requirements, runner, preview, start, result,
stdout, stderr, snapshot), excluding context and request, following the published producer
coordinate. Preserve partial UNKNOWN records; never convert an UNKNOWN to success. This is
reply consistency checking, not reimplementing signature/accounting evaluation in Engineer.
Add controls for jointly rebound stdout+refs+outer digest with contradictory claimed report,
wrong schema/extra event fields, and zero/incorrect otherwise-in-range byte count.

## Remaining P2: selector construction bypasses cleanup

DefaultSelector() is still executed after Popen but before try/finally. Simulated selector
construction OSError leaves both pipes open, with no wait or kill attempted. This exact setup
case was requested in the prior review. Initialize selector=None and enter protected lifecycle
immediately after successful Popen; construct/register inside it. Ensure each close is attempted
independently if another close fails, and retain original failure plus cleanup diagnostics.
The new nested finally correctly covers a reap error, but selector.close or first stream.close
can still skip remaining close calls. Add setup-failure and close-failure controls as well as the
now-passing reap failure. Never reconnect/resend.

## Registry disposition

HOLD service_read_cli.py SHA752e792c... for the complete bounded-reader claim. Its fixed public
read-only command architecture is admissible; no provider/authority/action route was introduced,
but the unresolved lifecycle case blocks exact-source approval requested here.
The previously scoped dispatcher-only approval for cli.py SHA5951a49e... remains valid because
its bytes are unchanged. This is not consumer-correctness or installed-pair approval.
Root owns fixes and the new normal-install pair acceptance; preserve existing evidence.

Reproduction: scripts/review_corrected_selected_case_consumer.py; original findings and outputs
remain intact. Candidate test source was inspected; no claim of rerunning its whole suite.
