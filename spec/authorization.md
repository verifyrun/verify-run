# Authorization — binding one permitted action
    authorization_version: 1

An authorization is permission for **one exact action, under one exact rulebook, on one exact
frozen snapshot, in one runtime, for a bounded interval, once**. It is not a token that says a
decision happened; it is a cryptographic binding that a specific action was permitted under
specific recorded conditions.

Nothing here executes, acknowledges, stores, or receipts anything. No clock is read, no randomness
is drawn, no file is opened, and no network is touched.

## Position in the chain
    rulebook pinned → snapshot frozen → evaluation → **authorization** → execution → acknowledgment → receipt

Issuance happens after a completed evaluation and never changes it.

## Eligibility
`spec/authorization.schema.json` states it in its own title: "Single-use action authorization
(**only issued on ALLOW**)."

BLOCK, HOLD, and ERROR receive no authorization. There is no signed negative authorization,
because authorization means action authority and a negative result confers none. Recording that a
negative decision happened is the receipt's job, and keeping the two separate is what stops
"authorized" from quietly coming to mean "evaluated."

## What is bound
The schema requires exactly these bindings, and no others may be added — `additionalProperties`
is `false`:

| Field | Domain |
|---|---|
| `action_digest` | the validated canonical **candidate** document. `spec/canonicalization.md` fixes it: "Digest of the exact canonical candidate. A different command is a different digest." |
| `rulebook_digest` | the pinned rulebook's digest |
| `evidence_digest` | the governing snapshot's `snapshot_digest` |
| `runtime_id` | the declared runtime |
| `issued_at`, `expires_at` | the validity interval |
| `nonce` | the single-use token |
| `authorization_id` | this authorization's own name |

**There is no result field, and none may be added.** The evaluation result is bound
**transitively**: evaluation is a pure function of the pinned rulebook, the candidate, and the
frozen snapshot, and all three are bound by digest. Given those three, the result is not a matter
of trust — it is recomputable. So verification recomputes it rather than reading a recorded claim,
and requires both that it matches the result the caller supplied and that its outcome is ALLOW.

There is one `action_digest` and no separate `candidate_digest` here. The receipt carries
`candidate_digest`; `spec/canonicalization.md` declares them the same value under two names, one
per artifact. Nothing in this unit computes two digests for one thing.

## No self-certification
A signature proves who produced the bytes. It proves nothing about whether those bytes describe
the objects a caller is holding.

Verification therefore **independently recomputes every binding** from the supplied rulebook,
candidate, snapshot, and result, and compares. A perfectly valid signature over an authorization
whose `rulebook_digest` names a different rulebook is refused. Signature validity and binding
correctness are separate questions and both must pass.

## Signature domain
`spec/canonicalization.md` already fixes it: Ed25519 over the canonical bytes of the artifact
**with its own `signature` member omitted**, and `signature.value` is base64 with padding
(RFC 4648 §4).

1. build the authorization without `signature`;
2. canonicalize it;
3. sign those exact UTF-8 bytes;
4. add the signature block;
5. schema-validate the completed authorization.

Non-circular by construction. Ed25519 is deterministic (RFC 8032), so signing draws no randomness
and the same payload and key always produce the same signature — which is what makes signing
vectors freezable at all.

`alg`, `key_id`, and `key_version` live inside `signature` and are therefore **outside** the signed
bytes. That is the declared domain and it is safe here: `alg` is `const "ed25519"`, so there is no
algorithm to confuse; and substituting a different `key_id` makes verification look up a different
key, under which the signature does not verify. An attacker who could re-sign under another
registered key would not need to substitute metadata.

That argument has a premise, and since 0.1.0a2 the premise is enforced rather than assumed: **one
public key carries one identity.** `build_key_registry` refuses the same public key under two
`(key_id, key_version)` pairs with `signing_key_invalid`. Registered twice, the substitution above
would look up the *same* key and the relabelled artifact would verify under an identity that never
signed it — and because status is held per identity while signing authority is held by the key, a
retired identity could be escaped by relabelling to an active one. Distinct keys under distinct
identities, and one key under several versions, are unaffected.

## Time
Every instant is supplied by the caller and compared as exact integer nanoseconds. No clock.

- `issued_at` must be at or after the snapshot's `frozen_at`. Authorization follows the freeze in
  the chain, so an authorization issued before the evidence it rests on is incoherent.
- `expires_at` is `issued_at` plus the rulebook's `authorization.ttl_seconds`, or **300** when the
  declaration omits it — the schema's declared default, applied here by the consumer exactly as
  `spec/rulebook-loading.md` says defaults are applied.
- `expires_at` must be strictly after `issued_at`.
- **Expiry is exclusive**: an authorization is valid while `verification_time < expires_at`. At
  `expires_at` it has expired — that is what an expiry instant means, and it is the shorter of the
  two readings. No source settles it, so the narrower one is chosen and pinned here.
- Verification before `issued_at` is refused.
- Offset spellings denoting one instant compare equal, and every timestamp is stored exactly as
  written. Nothing is normalized in the signed bytes.

## Nonce
The caller supplies it. This boundary draws no randomness — `CLAUDE.md` forbids it in the trusted
core — so a nonce is an input, never a product. The schema requires at least 16 characters. A
deterministic nonce is therefore legal and is what makes the fixtures reproducible.

## Single use, honestly
Four separate things, and conflating them is how one-time use silently fails:

1. the rulebook **declares** `single_use`, which its schema pins to `const true`, so every
   authorization under this spec version is single-use and a reusable one is not expressible;
2. **verification** checks structure, bindings, signature, and time — all pure;
3. **checking consumption** requires state;
4. **recording consumption atomically** requires durable state, and belongs to the local store.

`verify_authorization` accepts an optional consumed-nonce view. Given one, a nonce already
consumed is refused. **Given none, verification makes no single-use claim at all** — it returns a
structurally and cryptographically valid authorization and says nothing about whether it has
already been spent. A stateless function cannot enforce one-time use, and this one does not
pretend to.

Verification never mutates the view. Consumption is a separate operation the caller performs
against its own store, and durable atomicity is a later closure's obligation.

## Keys
A verification key is identified by the pair `(key_id, key_version)`, both of which the signature
block carries, and holds a 32-byte Ed25519 public key and a status.

- an unknown pair → ERROR `signing_key_unknown`;
- a retired pair → ERROR `signing_key_retired`;
- key material that is not a 32-byte Ed25519 key → ERROR `signing_key_invalid`.

Unknown and retired stay distinct because `fixtures/tamper/ATTACK_CLASSES.md` lists them as
separate classes with separate repairs.

**Retired means retired for authorization verification**, not merely for new issuance: a retired
key authorizes nothing. Authorizations live for seconds, so nothing durable is lost. Whether a
retired key should still verify a *historical receipt* is a different question with a different
answer, and it belongs to the receipt closure — recorded here, not decided here.

The registry is a small immutable in-memory mapping the caller assembles. Nothing is fetched.

## Verification order
Fixed, so an authorization wrong in several ways always reports the same first failure:

1. argument types — a programmer defect raises `TypeError`, not an outcome;
2. authorization schema;
3. key lookup by `(key_id, key_version)`, then key status, then key material;
4. signature encoding;
5. signature over the canonical payload;
6. rulebook binding;
7. action binding;
8. snapshot binding;
9. result binding, by recomputing the evaluation;
10. outcome eligibility;
11. runtime binding;
12. `issued_at` against the snapshot freeze, and `expires_at` after `issued_at`;
13. verification time within the interval;
14. nonce consumption, if a view was supplied.

## Immutability
The frozen authorization is a record of strings with the canonical complete authorization as
authority and the value reconstructed on request — the pattern Units 4 through 7 established, and
forced by the same reason: the frozen value model admits only `dict` and `list`.
