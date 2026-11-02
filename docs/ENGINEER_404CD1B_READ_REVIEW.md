# Independent Run re-review of Engineer 404cd1b

Read-only inspection of 404cd1b916b6d29ca3a651a46a8981928eca9c0d, no Engineer
edits, tests, C7 reads or operation replay. Root reports 27 source/installed
controls and wheel e0f89a7bfd2e73ad747c4302135849cc88ca251a096d6bf572857b338747b93e;
these were not independently executed here.

Original P2 observed-candidate counterexample is fixed: exact outer fields,
error=null, boolean read_incomplete, bounded non-boolean integer usage, result
flags and OBSERVED_CANDIDATE consistency are now checked. Legitimate UNKNOWN
remains available. Source-isolation and no-authority/no-retry boundaries preserved.

Residual P2: incomplete read can still assert content matches.
service_read_cli.validate_response requires only result.state==UNKNOWN when
read_incomplete=true. _repair_result accepts content_state=CANDIDATE in that
state. service_repair_view.render then takes its second branch and says
"The copy matches the repair, but completion is not verified."
Counterexample: take the valid incomplete UNKNOWN fixture, set
result.content_state='CANDIDATE', leave result.state='UNKNOWN' and all false flags.
The new validator accepts it and the renderer claims a copy match. The actual
Run adapter forces both state and content_state to UNKNOWN whenever reading is
incomplete. Require both UNKNOWN for incomplete replies, or suppress any content-
match wording on incomplete reads. Existing legitimate complete-read UNKNOWN /
CANDIDATE (unsigned completion) must remain separately representable.

Disposition: original counterexample closed; do not accept the complete hostile-
response/rendering correction until this residual branch is covered. No further
substantive boundary finding identified in this focused re-review. This is source
inspection, not a current runtime truth or broader CI/full-chain acceptance.
