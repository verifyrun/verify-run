# Latest consumer re-review and reader registry disposition

Sources independently re-read and exercised:
- service_test_view.py c5859a61fa9aee65e4b76e12612a081c4fb95b4d7469bf2df85890acd509583d
- service_read_cli.py 7dc5fc406af9ffb42c4aa7ed011319d7bfaaa32cd5a5e0ec81fcc8181b8039ca
- cli.py 5951a49e7d80d2f48afbaed7ca0579b3bf7cae53cce147071dbff841bbc78caf

All eight original mutations refuse; actual prior positive object validates; partial UNKNOWN
remains UNKNOWN. Contradictory report versus selected raw stdout now refuses. Selector creation
failure now enters cleanup, performs bounded wait and closes both pipes. Reap failure still
uses timeout=1 and closes selector/pipes. Source inspection confirms nested finally also attempts
both pipe closures if selector or first pipe close fails. No service or Run invocation occurred.

APPROVED_SCOPED_PUBLIC_READ_TRANSPORT for service_read_cli.py exact SHA
7dc5fc406af9ffb42c4aa7ed011319d7bfaaa32cd5a5e0ec81fcc8181b8039ca.
This approves fixed three-command read-only subprocess transport with selected byte bounds,
30-second exchange deadline and one-second cleanup reap allowance, no reconnect/resend or
service/action authority. It does not assert an OS-wide hard process lifetime guarantee,
complete accounting, consumer semantic correctness or normal-install pair acceptance.
The CLI dispatcher-only approval at SHA5951a49e... remains valid. No broad waiver or Engineer
registry edit was made. Any new source bytes require fresh selection/review.

Residual consumer validation details (already specified in prior review) remain:

1. The success report is compared with selected stdout, but neither report schema nor exact
   report/event fields are checked. Reproduction changes report.schema to foreign.report/99,
   embeds the same changed document in the selected stdout, updates its selected digest and
   refs, and binds the outer response to the newly serialized request digest. It still passes
   as success. Require exact engineer.service-tests/1 schema and fields; exact event id/outcome
   fields, alongside existing complete/count/unique-case/outcome/mapping checks. Do not merely
   check equality of two malformed documents. Add the coherently rebound invalid-schema control.
2. costs.input_bytes=0 passes for the nonempty real packet. Bound checking is not count checking.
   Validate the exact sum of the nine checker input members (selection, requirements, runner,
   preview, start, result, stdout, stderr, snapshot), excluding context and request, where the
   producer supplies a measured integer. Preserve legitimate UNKNOWN null counts. This does
   not establish full lifecycle costs, which remain UNKNOWN.

Thus transport registry approval is no longer held, but complete hostile-response acceptance
remains CHANGES_REQUIRED for the view. These do not negate the genuine 15-case retained result.
Root owns the corrected normal-install edition and independent consumer acceptance; the earlier
installed pair is superseded, not promoted to current acceptance.

Reproduction: scripts/review_latest_selected_case_consumer.py (AST extraction; no Engineer import,
no service execution). Results retained separately from earlier source revisions.

Coordination note: Root updated source while the preceding recheck artifact was being generated.
The earlier script stopped when the new report-equality check correctly refused its previously
accepted mutation; its redirected JSON file is empty, not a passing run. Earlier prose refers
to the explicitly recorded earlier hashes and the successful tool result at those hashes. This
latest JSON is the completed reproduction for the newer hashes above; do not treat the empty
intermediate artifact as evidence of acceptance or silently rewrite it.
