# Receipt and replay — recording a decision, and recomputing it later
    receipt_version: 1

A receipt is a signed record of one decision. Replay recomputes that decision from the recorded
inputs and compares. They are different operations making different claims, and this file exists
mostly to keep them apart.

Nothing here executes an action, acquires evidence, reads a clock, opens a file, or touches a
network.

## What a receipt claims, and what it does not
A receipt says: *this rulebook, this candidate, and this evidence snapshot produced this result,
and here is a signature over that record.*

It does **not** say the action succeeded, that the world changed, or that anything was permitted.
Permission is the authorization's claim; a receipt referencing one records that it existed. **A
receipt never authorizes retroactively.** A signed record of an executed action whose
authorization was invalid is a signed record of an unauthorized action, and verification says so.

## Position in the chain
    pinning → freeze → evaluation → authorization → execution → acknowledgment → **receipt** → verification → replay

Issuing a receipt changes nothing before it.

## Which decisions get a receipt
`spec/execution-chain.md` already settled it: ALLOW, BLOCK, and HOLD are decisions and each emits
one. **ERROR emits none** — a receipt requires a governing rulebook, a candidate digest, and an
evidence digest, and when evaluation never validly began at least one does not exist. The outcome
schema admits ERROR because outcomes are reported in other places; the chain forbids recording one
as a decision receipt, and that is the rule here.

By terminal class:

| Outcome | `authorization_id` | `execution` |
|---|---|---|
| ALLOW | present when an authorization was issued | present when the runtime reported back |
| BLOCK, HOLD | **absent** — no authorization exists to name | **absent** — nothing was authorized to execute |
| ERROR | no receipt at all | — |

A BLOCK or HOLD receipt carrying an authorization reference or an execution record is refused.
Negative decisions carry no action authority and must not look as though they might.

## Fields
`spec/receipt.schema.json` requires `receipt_id`, `spec_version` (`const "1"`), `created_at`,
`rulebook` (`rulebook_id`, `version`, `digest`), `candidate_digest`, `evidence_digest`, `result`,
`replay`, and `signature`. `authorization_id` and `execution` are optional. `additionalProperties`
is `false`.

**There is no `runtime_id` on a receipt**, and none may be added. Runtime identity is bound one
step away: the receipt names an `authorization_id`, and the authorization carries `runtime_id`
inside its own signed bytes.

**There is no receipt digest field**, and none is invented. A receipt's identity is its canonical
bytes together with its signature.

The `result` is the **complete** evaluation outcome — outcome, reasons, `matched_rule`, and
`trace` — embedded by reference to the outcome schema, not a digest of one. So comparison during
replay is a comparison of whole canonical values, never of the terminal word alone.

## Execution acknowledgment
`execution` carries `acknowledged`, `acknowledged_at`, `exit_status`, and `note`. All are
optional within it, and the caller supplies the whole object.

It means exactly: **the runtime reports that it attempted or completed the authorized action.** It
is not proof that the external world changed. `exit_status` is what a process returned;
`acknowledged` is what a runtime asserts. Neither is evidence, and a receipt does not upgrade them
into any.

The acknowledgment carries no action digest of its own — the schema has none. It is bound by being
inside a receipt that already names the exact `candidate_digest`, and by the receipt signature
covering both. There is no separate acknowledgment signature.

## Binding
Every digest a receipt carries is recomputed at verification, never read and trusted:

- `rulebook.digest` against the supplied pinned rulebook, and `rulebook_id` and `version` with it;
- `candidate_digest` against the supplied candidate;
- `evidence_digest` against the supplied snapshot;
- `result` against a recomputed evaluation;
- `authorization_id` against the supplied authorization, whose `action_digest`,
  `rulebook_digest`, and `evidence_digest` must equal the receipt's three — so a mismatched
  authorization is caught by content and not merely by name.

### Replay does not ask whether the authorization is still spendable
    receipt_version: 1 — clarified in 0.1.0a2; no artifact and no signed byte changed.

An authorization's validity interval bounds when it may be **consumed**. Replay consumes nothing.
So replay checks the interval for internal consistency — issued at or after the freeze, expiring
after it was issued — and does **not** compare it against the present clock.

The alternative was measured, not imagined: checking `now` against `expires_at` during replay made
every ALLOW receipt stop replaying `ttl_seconds` after it was written, which for the shipped
templates is two to ten minutes. BLOCK and HOLD receipts were unaffected because they reference no
authorization, so precisely the records of actions that *happened* were the ones that expired out
of the guarantee.

This is the same failure the section below refuses for retired keys, arriving by a different road,
and it is refused here for the same reason: `CLAUDE.md`'s definition of done says "`vfy replay` on
**any emitted receipt** verifies byte-identical", and a receipt that verified yesterday must verify
today. Every other authorization check is unchanged — signature, key identity and status, the three
digest bindings, the runtime binding, and the recomputed ALLOW.

A caller that genuinely wants "was this authorization valid at instant X" may still supply X.
Nothing that spends an authorization may use the historical form; `runner.execute_authorized_command`
always supplies the instant it is verifying for.

A signature proves who produced the bytes. It proves nothing about whether those bytes describe
the objects in front of you, and **a signed mismatch is still invalid**.

## Signature
Ed25519 over the canonical bytes of the receipt **with its own `signature` omitted**, value base64
with padding — the same domain `spec/canonicalization.md` fixes for every signed artifact.

1. build the receipt without `signature`;
2. canonicalize;
3. sign those exact UTF-8 bytes;
4. add the signature block;
5. schema-validate the completed receipt.

Non-circular. Ed25519 is deterministic, so the same payload and key always produce the same bytes.

The receipt-signing key may differ from the authorization-signing key, and the two registries are
separate arguments. Nothing requires them to be the same key, and a system that rotates one need
not rotate the other.

## Key retirement differs from Unit 8, deliberately
For **authorizations**, `spec/authorization.md` refuses a retired key entirely: an authorization
lives seconds, and a retired key must authorize nothing.

For **receipts**, a retired key **still verifies receipts it already signed**. It may not sign new
ones. The reason is in the schema's own title — "signed; **offline-replayable**" — and in
`CLAUDE.md`'s definition of done: "`vfy replay` on **any emitted receipt** verifies
byte-identical." If retiring a key made its historical receipts unverifiable, replay would fail
exactly when it matters most, and both statements would become false.

So retirement means *stop signing with it*, not *repudiate what it signed*. This asymmetry is
deliberate and is the one place this unit does not reuse Unit 8's rule. A key that must repudiate
its history is a revoked key, which is a different concept this version does not have.

## Verification is not replay
Two operations, two claims, and conflating them is the failure this section exists to prevent.

**`verify_receipt`** takes a receipt and a key registry. It checks schema, replay mode, key
identity and status, signature encoding, and the signature itself. It reports that the record is
authentic and unaltered.

It says **nothing** about whether the decision was correct, because it never saw the rulebook, the
candidate, or the snapshot. A digest-only receipt is not independently replayable by itself, and
this function does not pretend otherwise: its report carries `replayed = False`.

**`replay_receipt`** additionally takes the exact bodies. It verifies the receipt, pins the
supplied rulebook and compares digests, validates the candidate and compares, verifies the
snapshot and compares, **recomputes the evaluation**, and compares the complete recorded result
against the recomputation.

Replay does not rerun a model, reacquire evidence, re-execute the action, contact the original
system, or establish that anything happened in the world. `replay.mode` is `recompute-decision`
and that constant is the whole promise.

Missing bodies are their own typed state — `replay_body_missing` — not a false verdict in either
direction.

## Verification order
`verify_receipt`: argument types → schema → replay mode → key lookup and status → signature
encoding → signature → outcome eligibility → the authorization and execution presence rules for
the terminal class.

`replay_receipt`: receipt verification → rulebook pinning and digest → candidate validation and
digest → snapshot verification and digest → evaluation → complete result comparison →
authorization cross-binding when supplied → acknowledgment presence → report.

## Reports
Both return immutable records with explicit fields, not a single boolean, because callers need to
tell repair paths apart. A `ReceiptVerification` reports the receipt id, key identity, outcome,
replay mode, `signature_valid`, and `replayed = False`. A `ReplayVerification` adds
`bodies_matched`, `result_recomputed`, `result_matched`, `authorization_verified`, and the
recomputed canonical result.

## Trust anchor
Keys come from a caller-supplied registry, always. A receipt carries `key_id` and `key_version`
but no key material, so an artifact can never certify itself. A perfectly formed receipt signed by
a key nobody trusts is refused with `signing_key_unknown`, which is the entire point.

## Immutability
`FrozenReceipt` and both reports follow the established pattern: canonical text as authority,
defensive reconstruction, no retained mutable inputs, no input mutation.
