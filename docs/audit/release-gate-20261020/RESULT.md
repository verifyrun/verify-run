# W01 private Run release gate correction

Base: 4f9361a, unchanged Run runtime. Scope: release scanner and artifact identity,
not full release readiness. Engineer retains independent W01 ownership.

Reproduced35 vocabulary findings:33 uses of an existing signed lifecycle status
field across two modules/two tests, plus2 ordinary prose matches. Exact path and
whole-source SHA256 now permit only the reviewed protocol token. Changed source,
relocated file, unrelated prohibited tokens and later same-line matches still fail.
No module/path exclusion, scanner truncation or retained payload rename was added.
The two prose corrections are new documentation revisions; base/history preserved.
Engineer owner independently inspected the diff and found no broad exemption.

The ordinary build also reproduced a collision with the sealed reference wheel
filename. Distinct private wheel build tag1gate20261020 fixes the collision while
preserving runtime version and frozen conformance record. Package metadata remains
a7: consumers must select the exact wheel digest, not infer compatibility from the
version alone. This is no public release, installed-runtime switch or new historical
conformance result. Initial conflicting build retained outside the checkout at
/private/tmp/verify-run-release-evidence-20261020/initial-build/ for diagnosis.

Source and separately unpacked sdist:47 checks each,46 passed and1 historical-wheel
absence skip. Package content tests executed, not skipped. Normal dependency install,
pip check, public command help and malformed-request refusal passed outside checkout.
All41 source-backed runtime Python members match base, wheel and installed bytes.
No service, adoption, pool or original operation was rerun. Current source references
and sealed producer identities remain unchanged. Linux hosted acceptance not run.

Artifact hashes and per-module correspondence: VALIDATION.json.
Private deliverables: recovery/release-gate-20261020/.

Separate consumer connection: adoption/1 binds task_id plus source, candidate,
requirements, selection and checked evidence into plan; signed completion binds
plan digest, intent, candidate and destination. It does not establish organization
or workspace authority. Existing declared task succession binds task bytes/revision/
predecessor under host-selected checkers. Engineer confirmed Platform owns current
server-selected task/basis plus organization/workspace association; no Run schema
change is needed now. Do not infer tenant authority from a task string.

Remaining: Engineer current W01 gates, actual hosted pair acceptance, Platform
association and full joined launch gates. No completion percentage or FEH inferred.
