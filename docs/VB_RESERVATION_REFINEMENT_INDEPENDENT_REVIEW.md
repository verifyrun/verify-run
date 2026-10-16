# Independent VB allocation / reservation / keyed settlement review

Selected Papers private commit: d7046e2bad1bd15f14f7a13aabc140a5771f073c.
Reviewed the three requested research folders and their six Lean sources, including predecessor
comparison/recovery/lifecycle definitions. All selected SHA256SUMS members verified; corresponding
sources in /private/tmp/verify-vb-fork-credit-20261016 match exactly. Build logs inspected, not
independently recompiled. The supplied folders do not themselves include transitive LCSGRed
sources/toolchain closure; this is not an independent reproducible-build attestation.

Disposition: CONDITIONAL_MATHEMATICAL_INGREDIENTS_SUPPORTED_BY_SOURCE_REVIEW.
No theorem-statement/proof mismatch found in the three extensions. Runtime refinement and full
cost are NOT ESTABLISHED. This examination does not substitute for pending Claude review, grant
novelty/publication acceptance, or close a paper/program target. No service/pool operations,
Engineer edits, sealed research changes or unchanged selected-test consumer re-review occurred.

## 1. What the proofs establish

ForkCredit.charges_le_caps uses the sequential resume bound with old=0 for each separately
allocated branch. allocated_fork_budget then adds the common old expenditure and supplied
coordination term once. The result is a bound on sums of abstract charges, not parallel execution
or a measured global resource. The converse universal_cap_condition is correctly restricted to
ALL equal-length componentwise expenditures up to the caps: choosing actual=allowed proves
necessity. It is not a necessity theorem for a particular selector, attainable expenditures,
or an optimal allocator. The 10/10 cloned example charging 6+6 and 6/4 partition control are
correct discriminating cases. Shared worlds/outcomes/menu preparation remains supplied input.

ReservationRefinement.reserve_conserves and settle_conserves are correct Nat balance equations
conditional on successful transitions. settle requires actual<=cap and separately available
settlement overhead; it does not finance that overhead out of an as-yet-unverified refund.
interrupted=id retains the full pending reservation. actual_budget requires the explicit
pendingActual<=pending premise; conservation alone does not supply it. selector_actual_bound
connects ONE selector charge to ONE cap bounded by aggregate pending, not every concurrent
pending computation. The aggregate_replay_gap is correctly framed: the numeric two-step trace
could describe two real completions or replay one completion; the state has no ID to distinguish
them. It is an indistinguishability gap, not an exploit of a specified authenticated runtime.

KeyedSettlement.no_repeat and no_reissue correctly reject the completed ID in the immediate
successor. completed_persists preserves a tombstone through other successful complete steps.
completion_conserves transfers the predecessor total equality. These are sequential function
properties for the supplied state, not claims of non-copyable or durably current state. Reusing
the old input state accepts completion again; issuing against two copies of an initial free=10
state admits cap6 on each. These are exactly the rollback/fork premises the results acknowledge.
Reported propext/Quot.sound are standard logical assumptions, not supplied durability axioms;
absence of sorryAx does not turn the parameterized accounting model into a measured implementation.

## 2. Strongest remaining mathematical/refinement obligations

A. Define a finitely represented reachable-state invariant, not arbitrary State values:
   pending = sum of caps of all pending IDs; completed IDs are disjoint and retained; free,
   pending and cumulative spent have one authenticated budget origin. Current State accepts
   e.g. ledger=(spent0,pending6,free0) with two entries each pending6. Every balance theorem can
   still be true, while assigning 6 units of work to each violates pendingActual<=pending.
   Such a state need not be reachable from a valid issue history; proving that is the missing
   invariant, not a refutation of the present lemmas. Specify initial validity and preservation
   through issue, complete, interruption/refusal and migration; lift tombstone persistence to
   the complete reachable operation language (currently only successful complete is proved).

B. Define the runtime simulation relation and cost domination on traces, including crashes and
   all unsuccessful prefixes. Theorems currently admit overhead=0, abstract total functions,
   unbounded Nat arithmetic and function-valued ID maps. Finite machine integer overflow limits,
   finite storage, lookups, ledger validation, duplicate detection and tombstone retention must
   refine those abstractions or cause explicit bounded refusal. No GC/rekey/reset may silently
   resurrect IDs. General trace refinement is the next useful theorem, not more scalar identities.

C. Price EVERY advertised access: construction of menu/worlds/model, tariff evaluation itself,
   computing bound/full before admission, repeated baseline/candidate out evaluations, recovery
   checks, authentication, validation, failed/refused attempts, joining, journal publication,
   recovery, migration and checker revision. scan's charged 1+eval does not itself prove an
   upper bound on those computations; supplied out may be expensive, and Lean totality is not
   a runtime bound. Physical realization of any charge as actual cost remains a premise.

   Concrete obstruction to a full-cost reading: repeat a request whose cap exceeds free. reserve
   returns none each time with no ledger change. If each real refusal costs epsilon>0, n refusals
   cost n*epsilon while the model records zero. The same issue applies to resume's no-fit path.
   Paid checking must be reserved before it, or explicitly funded by a bounded enclosing session.
   A finite prepaid admission envelope solves the regression only within its declared bootstrap
   boundary; it does not create an uncharged initial parser/authenticator/oracle.

D. Preserve the epistemic premises. lifecycle_answer still needs actual-world support membership
   and observation fidelity. VBLifecycle gives explicit same-evidence obstructions when these
   fail. Ledger authenticity is not world coverage, semantic sufficiency or organizational action
   authority. Full 138530-unit/all-paper construction, discovery, revision and coverage stay OPEN.

## 3. Exact existing Run seams and their limits

Run source selected at c08026b9c275c131354c66f87e44ce822eb7de02 (runtime hashes retained in JSON).
Source inspection only; existing test source reviewed but tests/operations were not rerun.

| Existing seam | Useful guarantee under trusted local custody | Missing implication |
|---|---|---|
| common_capacity.CapacityOwner.locked/_change | Same root/lock inode, exclusive flock, signed state validation; exclusive pending.json, fsync/rename publication; pending marker blocks further dispatch | Cooperative local serialization, not hostile rollback/fork prevention or a global cap across create() roots |
| common reserve/bind_dispatch/settle | Bound reservation and logical child IDs, duplicate refusal, single settlement; slot permanently consumed; known retained-output byte amount may release unused hold; unknown keeps full hold | Captured payload correspondence only; not arbitrary physical work or paid settlement/refusal overhead |
| service_accounting_cli.selected_pool | Existing owner lock held nonblocking for entire live session; exact selected snapshot must equal current store; public trust/config/root selected before capability use | Detects changed current head relative to that selection; no external monotone witness if both profile and store are rolled back |
| service_attempt.ServicePool.admit/consume/settle | Same allocator predecessor and additive resource caps; attempt/root/PREVIEW uniqueness; in-memory capability consumed before exact durable caller START acknowledgement; duplicate result settlement refuses | Whole service cap stays charged on success/failure/interruption; not unused-cap refund or measured total actual resource cost |
| service_review.PaidReviewPool.reserve/_consume/_finish | Same selected shared allocator, retained review_id, one-use live capability before payload reads, receipt linkage, no fresh capability on reopen | All caps retained; selected logical read bytes/calls and trace retention only; full lifecycle exclusions explicit |
| service_adoption.AdoptionPool plus adopt/_locked | Existing common/service predecessor, consumed reservation before validation reads, current development authorization/nonce, durable INTENT before copy mutation, nonblocking per-copy lock, exclusive intent prevents retry, read-only reconcile | No multi-file atomic commit, crash can leave mixed/UNKNOWN; no global rollback resistance, semantic authority or full-I/O accounting |

Publication details: child_ledger.fresh writes O_EXCL/O_NOFOLLOW, fsyncs file and directory.
The pool writes pending.json then replaces state.json and syncs its directory. A leftover
pending file conservatively blocks work; it is not a distributed durable transaction proof.
state.json is replaceable; previous/revision fields and signatures do not make an append-only
anti-rollback journal. Archived valid prefixes remain authentic historical records. No operation
was performed to restore one; this conclusion follows from the validation/freshness contracts.

Service/paid-review reservation holds are stronger than refunding for the selected coordinates,
but differ from the model's spent=actual interpretation. A conservative abstraction can map
terminal charge to cap and uncertain work to pending cap, leaving free unchanged on terminal
service completion. It still needs actual_work<=cap for any advertised physical coordinate.
Common retained-output settlement is the narrower existing refund seam; do not generalize it
into service-cost refund or relabel managed_repair/managed-json-receipt profiles.

Locks require trusted control of the root, lock inode and writer/key custody. A privileged
writer can replace lock/state or clone keys; independent create() calls can each mint a cap.
Signatures authenticate issuer statements, not unique current issuance. Development profiles
have no production/Human/Platform authority. Reopened handles losing _live prevents re-launch,
but does not establish globally nonrollbackable credit authority.

## 4. Smallest proposed contract (not implemented or authorized deployment)

Propose `vfy.keyed-reservation-refinement/1` as an additive, explicitly selected contract over
ONE existing allocator, not a fresh budget store. Initially select the conservative no-refund
service/review profile; a refunding profile is a distinct future contract requiring measured
and authenticated actual-cost bounds. Existing schemas/modules/history remain exact.

Selection contains authority domain and budget origin, root/config/policy/runtime identities,
independent public trust/key version, authenticated epoch and head digest/revision, vector
coordinates/units/limits, finite ID/storage limits, operation scope and explicit cost exclusions.
A source/plan/evidence digest binds the task, not a grant of action authority.

Proposed callable semantics (names are proposals, not existing APIs):

- reserve_branch(selection, expected_head, reservation_id, request_digest, cap_vector,
  prepaid_check_envelope): atomically compare authoritative current head, reject every used ID,
  deduct from the SAME parent allocator, durably retain the keyed pending entry before any
  cap-covered work. Admission/failed validation costs consume the enclosing prepaid envelope.
- consume_once(reservation_id, expected_head, durable_start_digest): burn live capability and
  durably record exact invocation binding before acknowledgement. Lost acknowledgement, crash,
  or missing evidence means retained hold/UNKNOWN, never reissue/retry.
- record_completion(reservation_id, expected_head, result_digest, bounded_cost_evidence): only
  the exact pending consumed ID can transition once; bind its full signed trace/coordinates,
  retained completion marker and resulting head. No-refund mode charges the full cap. Optional
  later refund mode requires actual<=cap and separately prepaid settlement cost. Read-only
  reconciliation cannot spend or manufacture a replacement live capability.

The load-bearing authority contract is compare-and-advance(domain,epoch,expected_head,next_head),
with an independently authenticated monotone witness OUTSIDE any state rollback domain being
claimed against. Local trusted nonrollbackable custody can be a stated premise for a local
refinement; existing flock/selected-head checks realize serialization within that premise only.
A signature or second file in the same restorable directory is not that witness. Across roots,
each delegated cap must trace to one debit from the selected parent; independently minted pools
cannot be assumed jointly funded. If witness state is unavailable/inconsistent, hold UNKNOWN
and issue no new credit. Define journal/witness crash order and recovery without automatic retry.
No new external authority service, production key or deployment is authorized by this proposal.

Each receipt binds domain/epoch/reservation ID/request/parent debit/prior+next head, resource
caps and coordinate definitions, START/result hashes, cost evidence/scope, marker retention and
UNKNOWN status. Historical verification accepts authenticity only, never current spendability.
Select head freshness independently; do not learn trust or minimum epoch from the receipt.
Reserve finite marker/journal/verification bytes and stop on exhaustion. Any migration must bind
old seal/head and explicit current authority, preserve consumed IDs and holds, pay migration
costs, and retain old bytes; no silent new genesis or inferred reset.

## 5. Discriminating next evidence and full-target disposition

On a NEW disposable context only, require concurrent same-head reservations (at most one cap
advance), duplicate ID/reissue, crash before/after debit/intent/ack/completion, lost ack, old
signed-head rollback, cloned-root/key presentation, witness unavailability, failed validation
charges and finite tombstone/journal exhaustion. Some are known existing local controls; hostile
rollback/global-fork controls require the authority premise/component above and must not be
reported as passed by the current runtime. Link runtime traces to the reachable-state invariant
and each cost coordinate, rather than inferring refinement from test count or Lean compilation.

Target impact: recovery/continuation + resource composition -> conditional branch cap and keyed
reservation models -> missing authenticated current-state/cost simulation -> PROGRAM FULL TARGET
OPEN. Preserve these valid scoped results; do not replace the unchanged full objective with a
finite ledger result, software test success or compilation. Claude review remains independently
pending. Prior accepted selected-tests pair is unchanged and was not re-reviewed.
