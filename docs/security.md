# Security model and trust boundaries

What this software guarantees, and — at least as important — what it does not. Everything below is
what the implementation actually does, with the gaps named rather than smoothed over.

## Trust anchors

Keys come from a registry **you** assemble, always. Artifacts carry a `key_id` and `key_version`
but never key material, so an artifact can never certify itself. A perfectly formed receipt signed
by a key nobody trusts is refused.

`key_id`, `key_version`, and `alg` sit outside the signed bytes, which is safe because `alg` is a
constant and a substituted `key_id` selects a key the signature does not verify under. That holds
only while one public key carries one identity, so the registry now refuses the same public key
under two identities — otherwise a relabelled artifact would verify under an identity that never
signed it, and per-identity retirement could be escaped by relabelling.

`vfy init` generates two distinct Ed25519 keypairs — one for authorizations, one for receipts —
writes the private seeds mode `0600`, and records the public halves in `.vfy/keys/trust.json`. The
two registries stay separate: a system that rotates one need not rotate the other.

No private byte is ever printed by any command, under any flag. No key is ever read from an
environment variable. If a key file's mode grants group or other access, `vfy run` warns.

There is no key-rotation command in this alpha.

## Authorization

Issued **only on ALLOW**. There is no signed negative authorization, because authorization means
action authority and a negative result confers none.

It binds the exact candidate digest, rulebook digest, evidence-snapshot digest, runtime id, a
validity interval, and a single-use nonce. Verification recomputes every binding from the objects
in hand and **recomputes the evaluation**, requiring it to match the supplied result and to be
ALLOW. A signature alone establishes nothing about what the bytes describe.

Expiry is exclusive: valid while `now < expires_at`, and it bounds when an authorization may be
**consumed**. `vfy run` reads the clock at the spend rather than carrying the issue instant
forward, so the interval bounds this CLI's own runs as well as an authorization presented later.
The window between issue and spend is normally microseconds, so a sane `ttl_seconds` never fires
— but it is a live check, not a decorative field, and a rulebook that sets a one-second interval
gets one. **Replay does not consult it at all** — replay spends nothing, and a receipt that
verified yesterday must verify today. Everything else about a recorded authorization is still
re-checked on replay: signature, key identity and status, all three digest bindings, the runtime
binding, and the recomputed ALLOW.

## Single use, and the gap it cannot close

The nonce is consumed by exclusive creation — atomic on a local filesystem — **before the process
is created**. Checking then launching would leave a window where two callers both pass; consuming
then launching leaves none.

Stated plainly, because a guarantee that is false only during an outage is worse than none:

> Atomic consumption before execution prevents a second local caller from receiving the same
> execution right. **It does not make an external action exactly-once.**

- Crash after consumption, before launch → the authority is spent and nothing ran. Irreversible,
  and the safe direction.
- Crash after launch, before the receipt is stored → the world may have changed with no stored
  record of it.

There is no automatic retry anywhere. A consumed authorization stays consumed. Moving consumption
after execution would make retries convenient and permit duplicate action, so it is not done.

## Command execution

- The authorized argv, verbatim. Nothing is split, joined, quoted, globbed, or expanded.
- **No shell, ever.** An argument containing `;`, `$(...)`, `*`, or spaces is one literal argument.
- The working directory is explicit.
- The environment is **empty** unless your configuration names entries. The parent environment is
  never inherited.
- Standard input is closed.
- Output is captured to declared bounds and returned to you — never signed, stored, or logged.
- A timeout ends the child's whole process group.

**This is not a sandbox.** The command runs with your privileges and can do anything you can. What
is bounded is the *interface*: no shell, no inherited environment, an explicit directory, bounded
output, a timeout, and a process group that can be ended. Nothing here confines what the command
itself does.

A descendant that puts itself in a new session escapes the timeout's group kill. On a platform
without process groups the timeout ends only the direct child. Full process-tree termination is
not claimed.

`argv[0]` must name a path. A bare name would be resolved along the interpreter's compiled-in
default path, and one recorded digest would mean different programs on different machines. The CLI
resolves bare names along a configured search path — never `PATH` — **before** the candidate is
digested, so the receipt records the program that ran.

## Evidence acquisition

Two sources: a local file, and a local command's stdout. Both are bounded and read once; the bytes
read are the observation, with no claim that the source was unchanged before or after.

Paths resolve under an explicit caller-supplied root. Absolute refs are refused, escape is
prevented by resolution rather than string matching, and symlinks are refused at every component.
At the final component the open itself refuses to follow a symlink and refuses to block on a named
pipe, so the check-then-read window cannot be used to substitute one. **Parent directories are not
covered by that atomic step**, and an `exec` ref has only the pre-launch check, because launching
a process follows symlinks by definition.

**No HTTP.** A rulebook may declare it; nothing is acquired, no socket is opened, and nothing is
fabricated. The item is recorded as missing and the rulebook holds.

**`vfy check` acquires evidence too.** A preview runs steps 1 to 4 of the chain, and acquisition is
step 3, so an `exec` declaration means a local child process under `check` exactly as under `run`.
What `check` never starts is the candidate's own action. Read a rulebook's `evidence` block before
running `check` against it, on the same footing as `run`.

## The determinism boundary

Evaluation is a pure function of the pinned rulebook, the candidate, and the frozen snapshot. It
reads no clock, no randomness, no environment, no filesystem, no network, no locale, and no
timezone. Integers and canonical decimal strings only — never floating point — so no comparison
depends on binary rounding.

Its *cost* is bounded too, which matters because a rulebook's patterns are written by you while the
values they run against are composed by whoever proposes the candidate: expression nesting is
capped at a declared 64 across every recursive path, and `matches` runs in time bounded by the
product of the pattern and value lengths rather than exponentially in the number of `*` segments.

Time, key generation, and nonces live at the command-line edge and enter the trusted layers only
as recorded values. The full suite passes under hostile hash seeds, locales, timezones, and
UTF-8 modes.

## Storage

The store is **not** a trust anchor. Every load re-verifies signatures and re-runs replay against
your key registries.

- Committed receipt records are authoritative; the index is a rebuildable cache that can never
  make a committed record look absent or make a missing one look present.
- Symlinks are refused throughout the trusted layout, checked so a link is seen rather than
  followed. Filenames derive only from a restricted grammar and from SHA-256 hex, so traversal
  cannot appear in a derived name.
- Nothing is deleted recursively, and no path outside your root is touched. Abandoned staging is
  **reported, never silently removed** — it may be the only evidence of an interrupted or hostile
  write.

### Durability, precisely

- **Process-crash atomicity** — provided. A crash leaves either no committed record or a complete
  one.
- **Rename atomicity** — provided on POSIX and NTFS for same-directory renames.
- **Full power-loss durability** — **not claimed.** Directories are not fsynced, so a power cut may
  lose a rename the operating system reported as complete.

## Concurrency

Declared class: **multiple processes and threads on one machine sharing one root on a local
filesystem.** Proven at that scope: exactly one launch per authorization, and concurrent commits
of different records that do not interfere.

Explicitly out of scope: NFS and other network filesystems where exclusive creation and rename
atomicity are weaker, and coordination across machines.

## Platform

Developed and fully tested on CPython 3.14, macOS on arm64, APFS. CI covers Python 3.11–3.13 on
Linux. Windows is not tested; the process-group and file-mode behavior above is POSIX-specific.
Cross-platform support is not claimed.

## Three bindings this deliberately does not add

Each of these was proposed during the 0.1.x hardening review, evaluated individually, and left
out. They are recorded here rather than closed quietly, because "we did not think of it" and "we
decided against it, and here is the reasoning" are different states and a reader deserves to know
which one applies.

### The executable's bytes are not bound to the authorization

An authorization binds the candidate, and the candidate names `argv[0]` as a **path**. It does not
bind the digest of the file at that path, so a file replaced between the freeze and the launch is
launched. The conformance profile states this as a nonclaim in exactly those terms: *attestation
of the executed program's bytes*.

It stays a nonclaim because the binding could not be honestly kept. Hashing the file and then
launching it leaves the same window one step later — the file can change between the read and the
`exec` — and closing it needs a held descriptor executed directly (`fexecve`), which CPython does
not expose portably. A recorded digest would therefore assert something stronger than what was
enforced, in a signed artifact, which is the one failure mode this product exists to avoid.

What *is* available, today, with nothing added: **the program's digest is evidence, and evidence
is what a rulebook gates on.** An `exec` declaration whose script prints the digest as JSON makes
the bytes a recorded fact that the evaluator reads, the snapshot freezes, the receipt binds, and
replay recomputes:

```yaml
evidence:
  - {id: program, source: exec, ref: "./ci/program-digest.sh", max_age_seconds: 60}
rules:
  - id: unknown-program
    when: 'evidence.program != "<the digest this rulebook is about>"'
    outcome: BLOCK
    reason: The program at that path is not the one this rulebook names.
```

That is strictly more honest than a built-in binding: the digest is dated, frozen, signed, and
replayable like every other observation, and its `max_age_seconds` states how stale the reading
may be. It still does not close the window between the reading and the launch, and nothing in this
product claims to.

### `track` has no executable force

`track` declares the identity fields a rulebook is written about. It is schema-validated and then
never consulted — not to require a field, not to reject an undeclared one. A mistyped
`--identity brnach=main` therefore reaches HOLD rather than a refusal, because the rule that needs
`identity.branch` cannot settle without it.

Requiring declared fields, or rejecting undeclared ones, would be a new rule about which
candidates are **admissible at all** — a different kind of statement from anything the rulebook
language currently makes, and one that changes what a valid run is. `spec/execution-chain.md`
already says that belongs to a version that states it deliberately, and this is not that version.
HOLD on a typo is the safe direction: nothing is authorized, and the receipt records exactly why.

### The store has no identity of its own

`.vfy/store.json` records a format version and nothing else. A store is not bound to a workspace,
a runtime id, or a key. Two stores therefore each enforce single use **within themselves**, which
the profile states as a nonclaim: *uniqueness of a single-use identifier beyond the declared store
scope*.

Binding an identity into the store would mean a store format change, a migration for every store
written by 0.1.0a1 and 0.1.0a2, and coupling the store to configuration it is deliberately kept
away from — for a guarantee that is already unreachable through this CLI's surface, since `vfy run`
generates its own nonce per run and accepts no externally supplied authorization. The store is
explicitly not a trust anchor: every load re-verifies signatures and re-runs replay against
caller-supplied keys, so a file being local proves nothing either way.

If a hosted plane ever hands out authorizations for a runtime to spend later, this is the first
thing that has to change, and it changes there — with a stated scope for uniqueness — rather than
being bolted onto a local cache now.

## What is not claimed

- Not independently formally verified, and not independently audited.
- Does not prove the external world changed.
- Does not provide exactly-once external execution.
- Does not sandbox or confine the commands it gates.
- Does not defend against an attacker who can already write to your workspace, replace your key
  files, or run as you.
- No cross-language conformance has been demonstrated; this is the Python reference implementation.

## Reporting a problem

Open an issue describing the behavior and the smallest reproduction. For anything you believe is
exploitable, please report privately to the maintainer before disclosing publicly.

## Build and release dependencies

Stated rather than hardened, because a claim this repository cannot keep is worse than an honest
boundary.

Continuous integration uses `actions/checkout@v4` and `actions/setup-python@v5`, and builds with
`pip` and `build` at whatever version the runner resolves. Those are **mutable references**: a tag
can be moved, and an unpinned build tool resolves to whatever is current. This project relies on
ordinary GitHub Marketplace and PyPI trust for them and does not claim immutable action identity.

What that does and does not mean:

- A compromised action or build tool could affect **what CI reports** and **what a release
  artifact contains**. That is a real exposure and pinning by commit digest would reduce it.
- It does not affect what a *recipient* can check. Every published artifact's identity is its
  SHA-256; the conformance result is bound to that digest by
  [`conformance/reference-result.json`](../conformance/reference-result.json); and a receipt
  verifies and replays offline against key registries the reader supplies. None of those depend on
  trusting the machine that built the artifact.

Pinning by commit digest is a maintenance policy decision — it makes every action upgrade a manual
step — and this alpha has not taken it. The exposure is written down here instead of being papered
over with partial pins that would imply a guarantee the rest of the pipeline does not make.
