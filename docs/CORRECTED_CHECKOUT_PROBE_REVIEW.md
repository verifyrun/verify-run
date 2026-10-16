# Corrected checkout probe independent review

Disposition: ACCEPTED_CURRENT_GIT_REPORTED_ROOT_CREATE_OBSERVATION_ONLY.
Reviewed audit_real_operational.py SHA256
`020b59d0fbff3eb49280a72c054e1b6b25b8eed73604929667ad57562c884312`.
Read the revised tests; independently exercised extracted p11 and actual aggregate AST
expressions using new disposable Git fixtures. No historical checkout probe, service
execution, Engineer edit, sealed evidence rewrite or pool change.

The previous three false-acceptance paths are closed at this source identity:

- Actual assume-unchanged and skip-worktree flags with changed tracked bytes are refused
  by ls-files -v before the root-create probe.
- Only os.open's eligible permission errors establish root creation refusal. Successful
  creation is refused and cleaned. A simulated close-after-success permission error
  propagates after cleanup; it cannot be promoted to denied creation.
- NOT_RUN is not caught; incomplete aggregate returns exit 2 rather than success.

The source explicitly limits the claim to Git-reported clean, not actual byte equality.
Status has core.fsmonitor=false. Existing refusal of changes/extra/ignored files, root
and selected HEAD binding, selection consistency digest, exclusive/no-follow root creation,
and no historical/concurrency revalidation remain appropriate to this limited observation.

Remaining scope and reporting:

1. A self-digest is internal consistency, not independent provenance. Root must select and
   retain the exact old seal/selection digest externally; do not let the candidate inherit
   authenticity merely by recomputing a changed selection's digest.
2. This trusts the locally selected Git executable/configuration and filesystem behavior.
   Git is still found through PATH and config is not comprehensively isolated. Status clean
   does not attest all bytes/modes, filter conversions, submodule contents or loaded code.
   No hostile Git/config execution safety or bounded-output/full-cost claim is established.
3. Root creation refusal is current, for this process/identity/location only. No universal
   immutability, concurrent snapshot, filesystem-recursive write denial or historical
   execution inference. Root-path ancestor races and cleanup races are outside this scope.
   Close/unlink failures raise; they are not durable successful observations.
4. Residual reporting issue: main still describes P11 as the tree under measurement modified
   by measuring it; NOT_RUN is listed as ESCAPED and included in plants_run=len(rows). Exit 2
   prevents false success, but a missing observation is not an executed hostile plant or an
   observed escaped attack. Distinguish attempted/performed/not_run and rename current P11
   in any successor record/report. Do not rewrite the historical record to fix this wording.
5. The prior detached-clone result predates these final corrections and is not acceptance of
   this exact source. Root's pending authorized observation can establish a new current
   result at this hash, with fresh output and original seal preserved. Portability remains
   UNRESOLVED and no historical rerun is fabricated.

No remaining blocker to that narrowly labelled current p11 observation was found. This is
not acceptance of the broader historical regeneration/portability/full audit claim. Preserve
separate UNKNOWN/NOT_RUN in a successor and use the previously proposed predecessor-bound
new-record contract. Public vfy selected-case CLI remains a separate Run implementation
obligation; this review does not claim it was delivered.

Reproduction: scripts/review_corrected_checkout_probe.py; retained JSON in private evidence
recovery/corrected-checkout-review. Checks operate solely on disposable fixtures and AST
extracted code; the full operational audit and proposed pytest suite were not rerun.
