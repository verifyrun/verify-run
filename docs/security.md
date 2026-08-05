# Security model and trust boundaries

What this software guarantees, and — at least as important — what it does not. Everything below is
what the implementation actually does, with the gaps named rather than smoothed over.

## Trust anchors

Keys come from a registry **you** assemble, always. Artifacts carry a `key_id` and `key_version`
but never key material, so an artifact can never certify itself. A perfectly formed receipt signed
by a key nobody trusts is refused.

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

Expiry is exclusive: valid while `now < expires_at`.

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

## The determinism boundary

Evaluation is a pure function of the pinned rulebook, the candidate, and the frozen snapshot. It
reads no clock, no randomness, no environment, no filesystem, no network, no locale, and no
timezone. Integers and canonical decimal strings only — never floating point — so no comparison
depends on binary rounding.

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
