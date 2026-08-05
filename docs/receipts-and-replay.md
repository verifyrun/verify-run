# Receipts and replay

A receipt is a signed record of one decision. Replay recomputes that decision from the recorded
inputs and compares. They are different operations making different claims, and this document
exists mostly to keep them apart.

## What a receipt contains

```json
{
  "receipt_id": "r-b4b83611eecc18cf00ca07a0",
  "spec_version": "1",
  "created_at": "2026-08-05T18:04:14Z",
  "rulebook": {"rulebook_id": "pipeline-gate", "version": "1.0.0", "digest": "sha256:eb85..."},
  "candidate_digest": "sha256:b549...",
  "evidence_digest": "sha256:9f2d...",
  "result": {"outcome": "ALLOW", "matched_rule": "...", "reasons": [...], "trace": [...]},
  "authorization_id": "a-...",
  "execution": {"acknowledged": true, "acknowledged_at": "...", "exit_status": 0},
  "replay": {"mode": "recompute-decision"},
  "signature": {"alg": "ed25519", "key_id": "receipt-key", "key_version": 1, "value": "..."}
}
```

It carries **digests, not bodies**. The bodies live beside it, in `<receipt_id>.inputs/`:
`rulebook.json`, `candidate.json`, `snapshot.json`, and `authorization.json` for ALLOW records.

`result` is the complete outcome — outcome, reasons, matched rule, and the rule-by-rule trace —
so replay compares whole canonical values, never just the terminal word.

There is no `runtime_id` on a receipt, and none may be added: runtime identity is bound one step
away, inside the authorization's own signed bytes.

## By outcome

| Outcome | `authorization_id` | `execution` |
|---|---|---|
| ALLOW | present | present |
| BLOCK, HOLD | **absent** — nothing was authorized | **absent** — nothing ran |
| ERROR | **no receipt at all** |

ERROR emits nothing because a receipt needs a governing rulebook, a candidate digest, and an
evidence digest, and when evaluation never validly began at least one does not exist.

A BLOCK or HOLD receipt carrying an authorization reference is refused. Negative decisions carry
no action authority and must not look as though they might.

## What signature verification proves

That these bytes were produced by the holder of a key you trust, and have not been altered since.

It proves **nothing** about whether those bytes describe the objects in front of you. So every
digest is recomputed at verification rather than read and believed — a perfectly valid signature
over a receipt naming a different rulebook is refused. A signed mismatch is still invalid.

## Verification is not replay

**`vfy replay`** does both, and reports them separately.

- **Verification** checks the schema, the replay mode, the key's identity and status, and the
  signature. It says the record is authentic and unaltered. On its own it reports
  `replayed = false`, because it never saw the rulebook, the candidate, or the snapshot.
- **Replay** additionally takes the exact bodies, compares each against the digest the receipt
  records, **recomputes the evaluation**, and compares the complete recorded result against the
  recomputation.

A receipt presented without its bodies can complete verification only. That is reported as
verified and not replayed — a distinct state, not a failure in either direction.

## What replay does not do

It does not re-run the command, re-acquire evidence, contact the original system, rerun a model,
or establish that anything happened in the world. `replay.mode` is the constant
`recompute-decision`, and that constant is the whole promise.

**A receipt never authorizes retroactively.** A signed record of an executed action whose
authorization was invalid is a signed record of an *unauthorized* action, and verification says so.

## Execution acknowledgment

`execution` means exactly: the runtime reports that it attempted or completed the authorized
action.

| What happened | `acknowledged` | `exit_status` | `note` |
|---|---|---|---|
| started, exited | `true` | the exit code | — |
| exceeded the timeout | `true` | omitted | `timed out` |
| killed by a signal | `true` | omitted | `terminated by signal` |
| could not be started | `false` | omitted | `could not start` |

`exit_status` means the process exited with this code and nothing else. POSIX reports signal death
as a negative return code, and recording `-9` would merge "exited with status 9" with "killed by
signal 9"; both omit it and the note says which happened.

Stdout and stderr are **not** in the acknowledgment, not signed, and not stored. Command output is
exactly where credentials tend to appear, and a signed artifact is the last place they belong.

A launch failure still emits a receipt: the authorization was already spent, and a spent authority
with no record of what became of it is the hole this system exists to close.

**An acknowledgment is not proof the world changed.** A process exiting zero proves a process
exited zero.

## Local storage

```
.vfy/
  receipts/<receipt_id>.json          the receipt, exactly as signed
  receipts/<receipt_id>.inputs/       the bodies replay needs
  consumed/<sha256-of-nonce>.json     spent authorizations
  index.json                          derived, subordinate, rebuildable
```

Every file holds exactly the canonical bytes of its artifact — no pretty-printing, no trailing
newline. The rulebook body is stored as canonical JSON rather than the original YAML; canonical
JSON is valid input to the strict loader, so replay reproduces the identical pinned digest from it.

**The store is not a trust anchor.** A file being local proves nothing: every load re-verifies
signatures and re-runs replay against key registries you supply, exactly as if the bytes had
arrived from a stranger.

Committed receipt records are authoritative. `index.json` is a cache: it may be deleted at any
time, it is rebuilt by scanning the records, and a listing reconciles against them — so a stale
index never hides a committed receipt and an index entry naming no record is never believed.

## Key retirement

For **authorizations**, a retired key authorizes nothing at all. An authorization lives seconds;
nothing durable is lost.

For **receipts**, a retired key **still verifies receipts it already signed** — it simply may not
sign new ones. Otherwise replay would fail exactly when it matters most, and "any emitted receipt
replays" would become false. Retirement means *stop signing with it*, not *repudiate what it
signed*. A key that must repudiate its history is a revoked key, which this version does not have.

## Writing the same id twice

Identical bytes are idempotent and succeed. Any differing byte is refused as a conflict. There is
no overwrite operation, and one receipt id can never come to mean two contents.
