# Independent public selected-case consumer review

Disposition: CHANGES_REQUIRED; no Engineer edits, Run/service calls, pool changes or evidence
rewrites. Inspected complete new view, transport, tests/eu20/test_service_test_view.py,
and CLI diff from accepted 21aeaeb. Reproductions use AST-extracted validation/render code
with copies of the retained accepted public request/response, plus simulated transport cleanup.

Exact sources:
- engineer/experience/service_test_view.py:
  2aa1a297d8c065bb120162f7e0a6092f86b6aa6e3689977f9a056c250ab59d2a
- engineer/experience/service_read_cli.py:
  4d3656a488167d00f5e2222b348711bef05695d324bda02fc7b6c9ad22cb4603
- engineer/cli.py:
  5951a49e7d80d2f48afbaed7ca0579b3bf7cae53cce147071dbff841bbc78caf

## P1: contradictory/unbound inner report can display success

validate_response checks outer protocol, selected checker hash, original request hash,
scope flags and success boolean/reasons. It does not validate refs, report, selected_limits,
requirement contents/mapping or numeric costs. Starting with the real valid S8KETD64
response, EACH independent mutation below passes validate_response and renders
“The saved selected tests reported success.”:

- refs replaced with a foreign stdout digest;
- report.completed=false;
- one report case changed to failure;
- a case removed, or a duplicate added;
- requirements replaced with an empty dictionary;
- selected_limits replaced with an empty dictionary;
- cost input_bytes=-1 and case_events=true.

These are protocol-boundary contradictions, not claims that the pinned Run producer emits
such replies. The existing tests mutate only one of state/boolean/reasons, so they miss an
internally consistent success header carrying contradictory evidence details.

Fix consumer consistency validation without becoming a second Run verifier: validate expected
refs against all selected packet member hashes, exact selected_limits, exact result/cost/report
shapes and primitive types; success must have the selected unique complete case set, all success
outcomes, consistent counts/summary/PREVIEW hash, and exact requirement IDs/mapped case lists
with successful states. Bind report to the selected raw stdout document. Refuse contradictory
replies; preserve legitimate UNKNOWN's partial/null report, refs and counts as allowed by Run's
schema rather than forcing success-shaped details. Run remains owner of signature/accounting
and observation evaluation. Add hostile controls that keep state, success boolean and reasons
mutually consistent while changing each of these inner fields.

## P2: cleanup can overrun deadline and leak resources

read() finally calls proc.wait() with no timeout, even after kill. The advertised 30-second
exchange deadline is not a complete lifecycle bound. If that wait or kill raises, selector.close
and both pipe closes are skipped. A simulated second wait failure reproduced open stdout,
stderr and selector; the second wait received timeout=None. Selector construction also occurs
outside protected cleanup after Popen and should be covered by the same cleanup discipline.

Use bounded reap with a declared cleanup allowance, close streams/selector in nested finally,
and preserve the original refusal with cleanup diagnostics. Do not reconnect or resend.
Tests should cover a child closing pipes but failing to reap, kill/reap errors, selector setup
failure, and unconditional descriptor closure. No real hung process was created in this review.
This defect pre-exists the new command but is material to approving the newly selected reader
source as a bounded transport.

## What is correct and what remains scoped

Packet bytes are capped at 24 MiB and bound to the caller-selected digest before transport.
Transport serializes strict finite JSON and binds Run's response to the SHA of the actual
canonicalized wire request. Original packet SHA and wire SHA are different roles; reserialization
is not an unbound reply. Duplicate JSON object fields are refused. Output and stderr are each
bounded by selected 1024..1048576 bytes for this command (combined at most twice that limit).
Only three fixed public read commands are admitted. UNKNOWN uses non-success wording;
authority/retry/current checks remain false; CLI returns incomplete exit2 on completed historical
reading. No new direct vfy import, provider path, service execution, or spending key is introduced.
Input acquisition limits are byte caps, not an independent filesystem read deadline. Selected
Run executable remains a trusted external selection; a request hash alone is not executable
authentication. Root owns exact installed normal-dependency profile acceptance.

## Exact-source subprocess registry disposition

APPROVED_SCOPED_DISPATCHER_ONLY for engineer/cli.py SHA256
5951a49e7d80d2f48afbaed7ca0579b3bf7cae53cce147071dbff841bbc78caf.
The only changes from reviewed CLI are explicit review-service-tests parser/dispatch, exception
handling and historical exit2. Its existing subprocess import is still SubprocessError handling;
this branch invokes no subprocess directly. No broad path/import waiver or consumer-correctness
acceptance follows. Future source bytes require renewed review.

HOLD the new service_read_cli.py exact registry identity pending P2 and consumer-boundary fixes.
Its architectural purpose is admissible fixed public read transport, but the complete bounded
transport claim is not justified at these bytes. Root should update after correction and review,
not weaken the audit. No registry entries were edited by Run.

Reproduction: scripts/review_engineer_selected_case_consumer.py. It does not import Engineer
or execute Run. Static test review is not an independent rerun of the candidate pytest suite.
Actual reported source-console success is retained as scoped positive evidence and does not
close these adversarial gaps. Ordinary installed consumer acceptance remains pending.
