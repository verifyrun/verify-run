# Engineering checks profile and integration handoff

Status: **draft contract, not an implemented or supported runtime profile**.
Proposed identity: `engineering-checks-v1`, version `1.0.0-draft.1`.
Base transport: verify-run receipt spec 1 and decision-replay-v1 1.0.0.
No existing vfy command advertises this profile. No conformance claim follows from this document.

The September 18 full handoff and Engineer commission 137 were subsequently located and read.
The handoff's product is repository + task → useful checked improvement → authorized exact
application, with bounded internal construction also required. This check-only profile is an
intermediate milestone, **not sufficient for that product**. The smallest full consumer profile
is drafted below; neither profile is supported by current Run dispatch. The user should see one
simple operation and precise limits, not this internal contract or research terminology.

Observed consumer baseline: Engineer main `aab7bff0187537f793b8fd4243ca4c886cdd17ac`,
`engineer/compile/harness.py:execute_witness` materializes a compiled rulebook and declared
file evidence, invokes installed `vfy --json run`, then `vfy replay`. It records runtime output;
replay flags are read from CLI text. Its default disposable workspace does not retain replay
bodies; retained review flows must choose persistent workspaces. Engineer's `CLOSED_FLOOR.json`
and `PLATFORM_CONTRACT.md` pin public CLI use of `verify-run==0.1.0a3`, not internal imports.
Commission 137's worktree is `a914868b166fdf781b028d174582cec2e7b4569b`; its newer declaration
certificate is a separate source capability, not a released replacement for that floor.
Platform `3ca5f7355b29a09fda21066beac58bd87535f403` also pins a3 and marks its optional Engineer
0.4.0rc2 integration PREPARED. These local Run edits carry no consumer migration approval.

## Four operations, four claims

| Operation | What acceptance establishes | What it does not establish |
|---|---|---|
| Signature verification | Protected bytes verify under an independently selected key and current trust policy | Truth, legitimate organizational authority, policy adequacy, correct decision, effects |
| Decision replay | Exact retained inputs reproduce the complete recorded gate result and trace under fixed semantics | Reacquisition, rerunning tests, evidence truth, improvement, permission to act now |
| Evidence checking | The profile validator checked subject/requirement/checker/context bindings, required coverage, authenticated runner observations and declared checker-specific evidence rules | Arbitrary correctness beyond those requirements; logs or a signed pass boolean are not a proof |
| Controlled re-execution | A new authorized checker run observed a new result on the identified input under enforced context and limits | Reproduction of the external world, guaranteed identical nondeterministic results, replay of old authority |

Reports must contain separate states for signature, replay, evidence checking and execution,
including `not_checked`, `unsupported`, and `refused` where appropriate. Never derive one state
from another. An exported receipt's historical ALLOW is not a new execution permit. An evidence
checker may validate a machine-checkable certificate if its domain defines one; ordinary tests
are reported as observations by a trusted execution adapter, not upgraded into such certificates.

## Required manifest and enforcement ownership

All referenced bodies are retained in a portable bundle, content-addressed by SHA-256 with a
declared byte/canonical-JSON domain. A digest without its body is incomplete. Duplicate names,
ambiguous encodings, floats, unknown required fields and unsupported versions are refused.
The profile's own manifest is canonical JSON; raw files are hashed as raw bytes.

| Binding | Minimum content | Who must check and enforce it |
|---|---|---|
| Profile | Exact id, version and locally approved contract digest | Engineer dispatch table selects a preinstalled trusted validator; never load executable verifier code from the bundle |
| Subject | Repository identity, baseline tree digest, proposed tree digest, change digest; canonical tree manifest of relative paths, regular-file contents and executable modes | Engineer independently materializes and hashes all included bytes; adapter runs only that immutable tree. Git commit alone is insufficient for dirty/untracked work |
| Requirements | Ordered, unique requirement ids with complete requirement bodies/digests and explicit scope | Engineer binds the user-approved requirement set; validator rejects missing, substituted or uncovered requirements |
| Checkers | Checker id/version, executable/package or image digest, invocation, toolchain identity; requirement-to-checker mapping | Adapter resolves the pinned checker/toolchain; validator checks every required mapping and actual execution identity |
| Context | Immutable execution image/toolchain, argv, relative cwd, exact nonsecret environment, input tree, no-network setting, no mutable host mounts, stdin policy | Platform provides a context it can actually enforce; adapter verifies its identity before starting. A mutable path and a pre-launch hash alone are insufficient |
| Evidence | Unique check id, subject/requirements/checker/context digests, authenticated adapter identity, start/end observations, result class, complete bounded output or explicit truncation, evidence artifact digests | Profile validator recomputes bindings, authenticates observations with externally supplied adapter trust, applies checker-specific evidence rules; candidate author cannot substitute a pass boolean |
| Authorization | Candidate includes exact profile and manifest digest; rulebook and evidence digests, runtime, nonce, TTL | Run verifies the transport; Engineer refuses unapproved policy digests; execution adapter checks manifest against retained immutable subject/context and enforces Run live verification plus atomic consumption |
| Limits | Declared wall time, output, memory/process/CPU limits where required; total run budget, pre-effect capacity reservation and actual usage with units | Platform/adapter enforce supported limits; Engineer accounts for all attempts and aggregates usage. Unsupported required limit refuses, never silently becomes advisory |
| Trust/adoption | Caller-approved policy digest and allowed adapter/checker/signing identities and scopes | Engineer/Platform own adoption and trust distribution. `adopted_at` alone proves neither approval nor policy supersession |

Initial tree scope: regular files and executable mode only; reject symlinks, submodules, devices,
case-colliding paths, traversal, and missing content until explicitly specified. Include all bytes
the checker can read from the subject, including relevant untracked/generated inputs. Exclusions
must be explicit and the isolation boundary must prevent reading excluded mutable source.
First profile uses no secrets in the signed environment. Secret-bearing execution needs a
separate supported reference/attestation contract; do not expose secrets or pretend a redacted
value identifies the environment. Dependency caches must be immutable and digest-bound.

## Dispatch and boundaries that make hashes meaningful

Checker permission and engineering acceptance are separate decisions. The first authorizes a
bounded check using preflight evidence (approved manifest, adapter and limits), not a claimed
test result. After that run, a second diagnostic decision evaluates its retained observations
against requirements. Only the second may be presented as engineering acceptance. It authorizes
no apply/deploy operation. This avoids requiring the future result as evidence for launching the
checker itself. Controlled re-execution repeats the permission step with fresh authority.

1. Engineer receives the expected profile from the caller's operation, independently of the
   artifact. Missing profile, unknown version, wrong contract digest, or an unavailable enforcing
   adapter returns `unsupported_profile`; it never falls back to generic v1 acceptance.
2. The profile validator checks the complete manifest and retained bodies, then resolves the
   approved rulebook and trust policy. A generic vfy ALLOW is necessary transport evidence only;
   it is never sufficient for `engineering-checks-v1` acceptance.
3. Engineer obtains an immutable subject and the adapter's enforceable context handle. It checks
   their digests, checks evidence provenance/coverage and binds the validated manifest into the
   candidate. Existing `action.params` and structured evidence can carry this; Run does not
   interpret arbitrary params, so their presence alone confers no profile guarantee.
4. Immediately before spending, the adapter verifies that the SAME immutable handle and context
   are used, recomputes candidate bindings and uses the supported live authorization/consumption boundary.
   A hash-then-open sequence on a mutable file cannot implement this step. If the selected
   platform cannot enforce it, this profile is unsupported there.
5. The checker executes inside that boundary. After completion the adapter signs an observation
   bound to the subject/context/checker/requirements and usage. The validator checks it before
   reporting engineering acceptance. Timeout, truncation where evidence requires full output,
   missing observations, and incomplete requirement coverage cannot produce acceptance.
6. Export includes the receipt, all input bodies, manifest, evidence, checker contracts and trust
   references. Verifier trust roots remain independently supplied. Offline decision replay is
   permitted without executing checkers. Controlled re-execution is an explicit NEW run with
   fresh authority, consumption record, budget and evidence; it never spends an old receipt.

The actual consumer must apply a patch. It needs the separately versioned operation below,
which validates the destination baseline and provides a transactional apply boundary. A comparison
followed by an unrelated write is insufficient. This is not added to the small generic evaluator.

The existing public CLI generates and spends its own authorization within `run`; it does not
accept an externally issued token or expose the internal Python consumption API as a supported
Engineer interface. An implementation must demonstrate a CLI-launched enforcing adapter with
immutable handles and an approved manifest, or propose a versioned public interface with concrete
missing requirements. Do not bypass the consumer floor by importing Run internals. Selection and
migration are bounded I4 work in the estimate, not a claim that a new core API is already needed.

## Smallest useful-improvement profile (consumer draft)

Proposed id `engineering-improvement-v1`, version `1.0.0-draft.1`; unknown id/version/contract or
operation refuses before checking, issuing authority, or writing. It composes the bindings and
check protocol above and adds mandatory operations `compare` and `apply`. It must never silently
downgrade to `engineering-checks-v1`. Its narrow initial scope is one explicit task, one repository,
a supplied patch over regular files, named testable obligations and one declared supported language
family. Unsupported syntax, source binding or task predicate yields an honest limitation, not
useful improvement. This milestone does not discharge the full handoff's language or internal
construction obligations.

| Additional obligation | Enforcer and acceptance |
|---|---|
| Task/source correspondence | Engineer retains task text and independently reviewed requirement-to-source bindings, with explicit unresolved entries. A name match is not sufficient. Mandatory unresolved bindings refuse useful-improvement acceptance. |
| Independent improvement criterion | Engineer pins a caller-approved comparison contract before checking. Baseline and proposal use equivalent checker access, context and budgets; a known failing task assertion must pass, required preserved properties must remain satisfied, and no mandatory check may be omitted. Limitation-only output is not useful delivery. Report observed scope, not general program correctness. |
| Construction and cost | Supplied-candidate mode names its external proposer; later bounded internal-construction mode records model/tool identities, every attempt, failed checks and accumulated actual usage. A schema version is not a model identity. Unsupported accounting prevents claims depending on full-run cost. |
| Adoption/authority | Platform or explicit local caller approves exact profile, comparison, policy, destination and patch identities. Approval to check is distinct from approval to apply. Require fresh apply authorization and current trust, not a replayed historical ALLOW. Free local operation requires no Platform account. |
| Exact application | Adapter binds source baseline plus destination and performs transactional compare-and-apply under an enforceable concurrency boundary; any destination mutation refuses without partial write. Retain the installed tree identity and acknowledgment. |
| Interruption and recovery | Adapter/Platform journal intent, consumption, effects and acknowledgment. If effects might have occurred without a receipt, report unknown and reconcile; never automatically retry the action. Run's local consumption and signed result do not promise cross-store exactly-once effects. |
| Portable result | Export all input/evidence/comparison/application bodies. Report signature, decision replay, semantic evidence checks, observed improvement, adoption and effect acknowledgment separately. Offline verification grants no present permission and does not repeat the action. |

Smallest full acceptance: an independent task assertion fails on baseline and passes on the patch;
the identical retained check context covers all required assertions on both trees; the caller
approves that exact patch; fresh authorization permits transactional application to the unchanged
baseline; an independently trusted offline reader verifies the complete bundle. Inject mutations
between each boundary, concurrent destination writes, and a crash after effects but before receipt.
Every substitution refuses or is prevented; the crash reports unknown without automatic retry.
This is a proposed composed test, **not passed by the Run-only suite**.

Full target backlog owned by Engineer remains bounded internal candidate construction, TS/TSX and
other declared language coverage, independently labelled held-out real-repository trials, a cold
external-agent trial and a complete resource account. Platform owns organizational authority,
retention and hosted operations. Neither a small first profile nor a research hold removes them.

## Smallest integration acceptance and mutation matrix

Start with a repository containing one failing test for one explicit requirement and a proposed
patch that passes it. A normal user invokes one Engineer operation without writing YAML. Record
the exact trees, requirement and checker; capture an authenticated observation from the enforced
context; validate and export. An independent offline verifier must identify which checks passed,
recompute the gate result, and avoid launching anything. An explicitly requested controlled run
uses fresh authority and may produce a different observation without falsifying the old receipt.

| Mutation point | Mutation | Required observation |
|---|---|---|
| Before checking | Replace requirement, checker, dependency or source body while retaining its digest | Binding refusal, no checker launched |
| During checking | Modify the user's mutable worktree | Immutable checked subject remains unchanged; report never claims the new worktree was checked |
| After checking, before authorization | Substitute proposed tree or requirement set, inject constant `passed`, omit a required check | Evidence/profile refusal, no authority issued |
| After authorization, before execution | Change candidate params, argv, runtime or snapshot | Run binding refusal before consumption/launch |
| After authorization, before execution | Change program bytes, cwd, environment, image, mount or limit behind an unchanged manifest | Enforcing adapter refuses, or immutable context prevents substitution; generic Run alone is insufficient |
| Spending | Retire/revoke key, expire token, or repeat nonce in same consumption scope | Refusal before launch; retired/expired historical records remain replayable under historical policy; revoked trust is separately refused |
| After execution | Change output, usage or acknowledgment | Signature/binding refusal; no replacement of observation with a claimed result |
| Offline import | Remove body, change profile version, supply untrusted signing/adapter key | Explicit incomplete/unsupported/untrusted refusal; no generic fallback |

Run's local repair tests cover TTL/trust/lifecycle and transport mutation boundaries. They do
not claim the absent Engineer/Platform adapter passes the immutable-context rows. Integration
readiness stays blocked on those rows, even if the generic conformance profile passes 30/30.

## Core versus domain packs

Reusable core: canonical bytes and digests, deterministic declared-policy evaluation, typed
outcomes, action-bound authorization, explicit trust modes, scoped atomic consumption, signed
records and offline decision recomputation. Reuse depends on its stated input/trust/store/OS
assumptions, not a claim that one policy fits all applications.

Engineering pack: repository/tree interpretation, requirement coverage, test and analysis
semantics, checker-specific evidence validation, user explanations and any baseline comparison.
Other application domains need their own evidence meaning, temporal assumptions, failure costs,
authority scopes and checkers. Improvement needs a defined baseline and metric with evidence;
neither ALLOW nor passing tests implies improvement.

Platform/adapter: immutable execution context, process and resource isolation, aggregate accounting,
remote evidence acquisition, organizational trust distribution, durable retention and any
cross-machine consumption guarantee. None belongs inside the pure gate merely because it is
needed around it. A candidate requiring unsupported guarantees is refused by its profile entry
point; it does not force the existing v1 evaluator to reinterpret historical records.

## Contract handoff and release holds

Engineer owns P2 and the actual user workflow. Platform owns P3. Run owns R1–R4, this draft P1
and its A1 participation only. Reconcile estimates by these ids, not by adding three copies of
shared integration work. Ratify the exact consumer migration and remaining adapter interfaces before finalizing P1.
P2/P3 remain owned and estimated in their respective repositories. Papers are required only for claims explicitly depending on their statements.

Compatibility: no new signed receipt fields, no canonicalization changes, no rewriting historical
artifacts, no changing generic v1 acceptance into engineering acceptance. A profile-specific
dispatcher and enforceable adapter are required additions outside the generic core. The existing
decision-replay-v1 kit remains frozen. New profile fixtures require their own versioned manifest.
No release, push, publication or deployment is authorized by this handoff.
