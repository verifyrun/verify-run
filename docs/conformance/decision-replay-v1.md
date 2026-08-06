# Decision Replay Conformance Profile v1

    profile_id       decision-replay-v1
    profile_version  1.0.0
    status           draft
    fixtures         conformance/decision-replay-v1/fixtures/manifest.json
    machine profile  conformance/decision-replay-v1/profile.json

## 1. Status

This is a draft public profile. It is vendor-neutral. `verify-run` is its first reference
implementation and is not its definition: an implementation conforms by satisfying the requirements
below and the fixtures that witness them, in any language, on any platform.

Passing the fixtures is a **self-reported test result** against a named profile version and a named
fixture-manifest digest. It is not certification, accreditation, endorsement, or approval by any
third party. No body accredits this profile, and this document creates none.

## 2. Scope

The profile covers one question:

> Does this implementation settle declared inputs to one of four non-collapsible terminal classes,
> create exact action-bound authority on ALLOW, and emit an artifact that lets someone else verify
> and fully recompute **the recorded decision** without trusting the producer's database?

The phrase **the recorded decision** is load-bearing and is used throughout. Recomputing a recorded
decision is not re-executing an action, and this profile never conflates them.

Out of scope, permanently for v1: how a rulebook is authored, how evidence is obtained, what a
decision ought to be, and what happened in the world.

## 3. Terminology

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as in RFC 2119.

**Declared inputs** — the rulebook, the candidate action, the frozen evidence snapshot, and, where
the terminal is ALLOW, the authorization. **Terminal** — one of ALLOW, BLOCK, HOLD, ERROR.
**Artifact** — the signed, portable record of a decision. **Protected fields** — every artifact
member covered by the signature. **Recomputation** — deriving the recorded terminal again from the
recorded inputs alone. **Trust anchor** — a public verification key an auditor supplies
independently of the artifact.

## 4. Conformance target

The target is an implementation that produces and consumes decision artifacts. An implementation
declares which operations it exposes through an adapter (§14). A conforming implementation MUST
expose verification and historical recomputation. It MAY expose evaluation and live spending; where
it does, the relevant requirements apply.

## 5. Declared inputs

- **DR-1.1** An artifact MUST identify or contain the exact declared inputs needed to recompute the
  recorded decision.
- **DR-1.2** Recomputation MUST NOT require reacquiring evidence from a live source.
- **DR-1.3** Recomputation MUST NOT require a mutable database row, an unrecorded model response,
  a live API, hidden configuration, an undocumented default, or an implementation-local cache.

A trust anchor is not one of these. Verification keys MAY, and normally SHOULD, be supplied
independently of the artifact; the profile requires that no *secret* or *mutable* state be needed to
recompute a decision, not that the artifact carry its own key.

## 6. Terminal settlement

- **DR-2.1** For declared inputs and a stated profile, settlement MUST produce exactly one terminal
  from {ALLOW, BLOCK, HOLD, ERROR}.
- **DR-2.2** The same declared inputs MUST produce the same terminal on repetition.
- **DR-2.3** HOLD MUST NOT be reported as BLOCK or as ALLOW. HOLD means the rulebook could not
  settle the question; it is not a negative decision and it is not a failure.
- **DR-2.4** ERROR MUST NOT be reported as a decision terminal. ERROR is a preparation or validity
  failure: evaluation never validly began.
- **DR-2.5** An implementation MUST NOT default to ALLOW when settlement cannot be completed.

The four classes are non-collapsible. An implementation that maps any one onto another does not
conform, however convenient the mapping is for its user interface.

## 7. ALLOW authority

- **DR-3.1** Where the terminal is ALLOW and an authorization exists, the artifact MUST name it, and
  the authorization MUST bind the exact candidate, rulebook, and evidence snapshot by digest.
- **DR-3.2** An authorization MUST declare a validity interval whose end is after its start.
- **DR-3.3** BLOCK, HOLD, and ERROR MUST NOT carry an authorization or an execution record.
- **DR-3.4** An authorization MUST carry a single-use identifier, unique within the implementation's
  declared store scope.
- **DR-3.5** An implementation that exposes spending of a supplied authorization MUST verify the
  bindings and MUST refuse outside the validity interval.

**Declared scope, stated plainly.** DR-3.4 is scoped to the store the implementation declares.
This profile does **not** require globally unique single use across copied stores or across
machines, and an implementation MUST NOT claim it on the strength of this profile. v1 carries no
fixture for DR-3.5, because the reference implementation does not expose an externally supplied
authorization for spending; an implementation that does exposes it through the adapter's
`live_spend` capability.

## 8. Artifact requirements

- **DR-4.1** The artifact MUST be canonical under its declared canonicalization profile.
- **DR-4.2** The artifact MUST bind the recorded inputs by digest.
- **DR-4.3** The artifact MUST bind the terminal result.
- **DR-4.4** The artifact MUST be signed under a declared algorithm and key identity.
- **DR-4.5** Altering any protected field MUST cause verification to fail.
- **DR-4.6** Verification MUST require only the artifact and an independently supplied public trust
  anchor. It MUST NOT require the producer's database, network, or private key material.

Four things are distinct and are kept distinct: the artifact is **portable**; the trust anchor must
be **available**; the private key must remain **secret**; and verification must be **independent of
the producer's database**. An implementation may satisfy three and fail the fourth.

## 9. Verification

- **DR-5.1** A verifier MUST refuse an artifact whose signing key identity is unknown to the
  supplied trust anchor.
- **DR-5.2** A verifier MUST refuse an artifact bearing a cryptographically valid signature from a
  key the trust anchor does not hold. A valid signature is not a trusted signature.
- **DR-5.3** A verifier MUST refuse a missing, malformed, or copied signature.
- **DR-5.4** A verifier MUST refuse an unsupported replay mode.
- **DR-5.5** A verifier MUST refuse an unknown protected field where the profile forbids one.

A verifier MAY be the same software that produced the artifact. Conformance MUST NOT require that,
and an implementation MUST NOT present "our verifier agrees with our producer" as independent
verification.

## 10. Historical recomputation

This is the centre of the profile.

- **DR-6.1** A replayer MUST recompute the recorded terminal from the recorded inputs.
- **DR-6.2** A replayer MUST verify the recorded bindings.
- **DR-6.3** A replayer MUST NOT reacquire evidence.
- **DR-6.4** A replayer MUST NOT execute the action.
- **DR-6.5** A replayer MUST NOT require the recorded authorization to be presently spendable.
- **DR-6.6** Recomputation MUST continue to succeed after the recorded authorization's validity
  interval has elapsed.
- **DR-6.7** A replayer MUST refuse a missing or substituted recorded input.
- **DR-6.8** Retired signing keys SHOULD continue to verify artifacts they already signed.

DR-6.5 and DR-6.6 exist because the distinction is easy to get wrong and expensive when it is. A
validity interval bounds when an authorization may be **spent**. Replay spends nothing. Asking
whether a recorded authorization is still spendable makes every historical ALLOW record expire out
of the guarantee — precisely the records of actions that happened. What a replayer MUST check is
that the authorization was well-formed and bound to these inputs; what it MUST NOT check is the
present clock. DR-6.8 is a SHOULD because an implementation may have a defensible revocation model;
it is not a MUST because retirement that repudiated history would make replay fail exactly when it
matters most.

## 11. Execution acknowledgment

- **DR-7.1** Where an artifact carries an execution acknowledgment, it MUST be inside the protected
  fields.
- **DR-7.2** Altering the acknowledgment MUST cause verification to fail.
- **DR-7.3** An artifact without an acknowledgment MUST NOT be presented as evidence that the action
  ran.

An acknowledgment means the runtime reported that it attempted or completed the action. It is not
proof that the world changed. An implementation MUST NOT describe it as such.

## 12. Failure behaviour

- **DR-8.1** An implementation MUST refuse, or return ERROR, for malformed declared inputs, invalid
  canonical form, invalid signatures, unknown or untrusted keys, altered bindings, unsupported
  replay modes, and malformed validity intervals.
- **DR-8.2** An implementation MUST NOT normalize a protected artifact into acceptance. Repairing,
  defaulting, or re-serializing protected bytes before verification does not conform.

Refusals are categorized, not spelled: an implementation reports its own reason codes and maps them
onto the profile's neutral categories through its adapter. The profile constrains which category a
refusal may carry; it does not dictate the order in which an implementation checks, because a
verifier that notices a malformed artifact before it checks the signature is not less correct.

## 13. Historical compatibility

- **DR-9.1** An implementation MUST declare which profile versions it accepts, which artifact
  versions it verifies, whether historical replay is supported, whether migration rewrites protected
  bytes, and whether retired keys still verify history.

For the reference implementation, artifacts written by `verify-run 0.1.0a1` verify and replay
unchanged under `0.1.0a2`, including after their authorization's interval elapsed, with no migration
and no rewriting of protected bytes. That is a fact about one implementation's history. It is
recorded here as an example of what DR-9.1 asks for, and it is **not** normative for anyone else.

### Requirements without a fixture

Two requirements are stated without a fixture in v1, and neither is smuggled past the reader:

- **DR-3.5** — no fixture. The reference implementation exposes no way to present an externally
  supplied authorization for spending, so v1 has nothing to exercise. An implementation that does
  expose it declares `live_spend` through its adapter, and a later profile version may add the
  fixture.
- **DR-9.1** — no fixture in the bundle sense. It is witnessed by the adapter's `capabilities`
  answer, which every conformance result records verbatim, so the declaration is published with the
  result rather than tested against a bundle.

## 14. Result reporting

A conformance run reports against `conformance/decision-replay-v1/result.schema.json`. Overall
status is PASS, FAIL, or INCOMPLETE. Any required fixture failing makes the run FAIL. Any required
fixture skipped, or any fixture-manifest problem, makes it INCOMPLETE. A result is meaningful only
together with its profile version, fixture-manifest digest, runner version, and implementation
version; a result quoted without them says nothing.

## 15. Security considerations

Verification establishes that an artifact is authentic, unaltered, and that its recorded decision
follows from its recorded inputs. It establishes nothing about the world.

An implementation that satisfies this profile can still be operated badly: the rulebook may be
wrong, the evidence may be false, the declared authority may be illegitimate, and the key may be
held by the wrong person. The profile deliberately does not reach any of that. It makes the record
checkable by someone who does not trust the producer, which is a smaller claim than it is often
mistaken for, and is the only one the artifacts support.

## 16. Explicit nonclaims

This profile does not establish any of the following, and an implementation MUST NOT cite it as
evidence of any of them:

- truth of the declared evidence in the external world;
- quality, wisdom, or fitness of the rulebook;
- legitimacy of the declared authority;
- sandboxing or confinement of the authorized action;
- attestation of the executed program's bytes;
- exactly-once external side effects;
- uniqueness of a single-use identifier beyond the declared store scope;
- correctness of any model that produced the evidence;
- proof that the action's external effects occurred;
- regulatory, legal, or contractual compliance;
- absence of compromise outside the declared boundary.

## 17. Reference fixtures

`conformance/decision-replay-v1/fixtures/` holds 30 bundles: 6 positive and 24 negative. Each bundle
is a finished set of artifacts — canonical JSON bodies, a signed receipt, and a trust anchor holding
public keys only — so an implementation in any language can consume it without a YAML parser or a
Python package. Every bundle records the golden vector in this repository it was derived from and
that vector's digest, and the runner re-checks both.

No fixture permits evidence acquisition or action execution, and none needs to be forbidden: a
bundle contains no evidence source and no executable, so a replay that succeeds has demonstrably
done neither. The ALLOW bundles carry authorizations whose validity intervals elapsed in 2026, so
DR-6.6 is witnessed by every positive ALLOW fixture rather than by a test that waits.

## 18. Versioning and change control

Profile versions are semantic and independent of any implementation's package version.

- **PATCH** — editorial or tooling correction that changes no requirement and no fixture.
- **MINOR** — an additive optional capability or fixture that leaves the meaning of a previous PASS
  intact.
- **MAJOR** — any changed MUST or MUST NOT, any changed required fixture, any changed terminal
  meaning, any changed artifact requirement, or any change to what PASS means.

A recorded result applies only to its exact profile version, fixture-manifest digest, runner
version, and implementation version. Changing the fixture manifest invalidates prior results by
construction, because the digest is part of the claim.
