# Independent disposition: once-only public-session service accounting

ACCEPTED_SCOPED_RETAINED_SERVICE_ACCOUNTING for 71kbdb5s. Source review of Engineer
21aeaeb2ee5c1c50e00bdb120dc1f11a73049f00 closes watchdog-start cleanup finding:
Timer construction/start is inside protected try, close tolerates absent watchdog,
original failure preserved and pipe/caller-lock finalization retained. Startup
failure control inspected; Root's13source+13installed tests were not rerun here.
No further substantive finding within this reviewed startup boundary.

Selected retained bytes independently authenticated using installed Run read-only
load_service_pool, independent owner trust/config/policy from prepared profile:
- Profile2dd2cf8ad19ed41f0b4b9d384fd59d7944bd4384d5282f3ffac28f46ad8a529e;
  preview6bcc0bc1234aba651966664e14d7ee09a8fd67802f3165b1bdbdc492961bb804.
- Signed revision chain1->2->3->4 with exact previous hashes, one entry only;
  ADMITTED -> CONSUMED -> OBSERVED_EXIT_ZERO. No extra entry/refund/reset.
- Raw request/approval/PREVIEW/START/result/stdout/stderr and initial ACCOUNTING
  profile/request bindings match. Final retained ACCOUNTING_RESULT equals current
  selected new pool state bytes. This equality is a selected local observation,
  not hostile rollback resistance or future freshness.
- Shared capacity fully charged1/1 slots,1048576/1048576 retained-output reservation.
  All declared service reservations retained: wall60s,cpu40s,output1048576bytes,
  file67108864bytes,descriptors128. These are declared bounded coordinates, not
  measured full lifecycle utilization. Actual retained stdout+stderr14581bytes;
  smaller captured output does not refund the declared reservation.
- Retained RESULT says PROCESS_OBSERVED,exit0,startup_observedtrue,
  inputs_unchangedtrue,limit_failurenull. These are signed-linked process observations,
  not independent present-source remeasurement or loaded-code provenance proof.
- Stdout parses as engineer.service-tests/1; exact selected15 unique case IDs,
  all success,completed/successfultrue,tests_run15 and matching PREVIEW digest.
- Root packet matching records equal originals and SHA256SUMS verify. Reviewed
  retained files, public setup files, selected pool state and packet were hashed
  before/after and byte-unchanged. No seed read, no live pool capability/session,
  admit/consume/settle/action/replay/reset or Engineer import/edit invoked.

## Scope distinction that must remain explicit

Frozen TEST_SELECTION.json retains prior adapter digest
77d840a68a4a24412a03a1936c3f72ccf44e6fbd9560b59d92a35c6dc5a7117d;
current PREVIEW selects
1adb9a7b29368ef52f359599c92f8041c8ae4b7d545bd5c9976d64e609c36ad4.
Other inspected selection identities (source/examiner/environment/capture/runner)
match PREVIEW. Thus exact15 retained case outcomes can be reported as untrusted
process evidence, but full source-bound TestObservationChecker acceptance for this
selection is NOT established. Do not rewrite selection/PREVIEW or replay the used
attempt to repair this retrospectively. This does not invalidate scoped accounting.
No semantic sufficiency, requirement adequacy or adoption acceptance follows.

Review is uncharged read-only inspection; fullcostUNKNOWN. Root explicitly records
Engineer installed with --no-deps in a development pair. Normal dependency install,
source-isolation/hostedCI, Platform/ordinary agent route, current production/human
rights and fullV1 remain OPEN. Public release held. Prior exhausted C7 pools were
not accessed or modified. Used71kbdb5s pool is now exhausted and nonrepeatable.

Exact final accounting rawSHA256:
b6e86101470ce4a641177b1e2a4ef86a6ebb16c853958f3e4da14f80af53105e.
Independent check script: scripts/review_retained_service_71kbdb5s.py (read-only).
Full result/hash record retained in private evidence branch. No runtime/wheel change.
