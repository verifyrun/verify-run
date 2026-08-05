# Evidence adapters — turning local observation into a declared acquisition
    adapter_version: 1

An adapter makes **one bounded local observation** and reports it as one acquisition result. That
is the whole job.

It does not build a snapshot, evaluate a rule, choose an outcome, authorize an action, issue a
receipt, persist anything, or reinterpret a status afterwards. It reads no clock, draws no
randomness, opens no socket, inspects no environment variable, and infers no home directory.

Adapters are the first components that are *intentionally effectful*, and their effect is bounded
to exactly one of: reading one local file, or running one local child process.

## Sources in v1
Two: `file` and `exec`. They are what the current templates need locally.

**`http` is declared by `claims-gate` and is not implemented.** `coverage` is an `http`
declaration, and without an adapter for it `build_snapshot` synthesizes that item as `missing` —
which is legal and honest. The consequence is precise and worth stating: `claims-gate` can reach
neither ALLOW nor its `coverage-denies` BLOCK from local evidence alone. `fresh(coverage)` is
false and `evidence.coverage` is unsettled, so the rulebook holds. That is the correct behavior for
evidence nobody has acquired, not a defect.

`inline` is declared by the schema and used by no template; it is not implemented either.

## What an adapter returns
Exactly the shape `build_snapshot` already accepts, and nothing more:

    {"id": ..., "status": ..., "acquired_at": ..., "value": ...}

No `order` — the snapshot builder assigns it. No source field, no diagnostic prose, no error text,
no stderr. **Nothing an adapter learns about a failure enters the signed snapshot.** A failed
observation is recorded as a status, and the reason it failed is a matter for a log, not for the
cryptographic record.

`acquired_at` is **supplied by the caller**. An adapter never constructs a timestamp — not from a
clock, not from file metadata, not from when a process finished. The caller records when the
observation was taken and owns that claim.

## What an adapter never decides
Freshness is the evaluator's, computed from `acquired_at`, `frozen_at`, and `max_age_seconds`.
An adapter never compares ages and never marks something `stale`.

**No v1 adapter originates `stale`.** Neither a file read nor a command run has a local condition
meaning "observed, but no longer valid" independent of age. The status exists for sources that do —
a sensor reporting its own reading as expired, say — and fabricating one here to exercise the
enum would be inventing a fact.

An adapter never returns ALLOW, BLOCK, HOLD, or ERROR. A command that exits non-zero produces
evidence with status `error`; whether that becomes a BLOCK, a HOLD, or nothing at all is the
rulebook's business, and the separation is the point.

## Two levels of failure
Kept apart, because they have different repairs:

1. **A typed adapter error** — the call itself is malformed or unsafe, and no trustworthy
   observation is possible. A missing `ref`, a path escaping the root, a symlink, a non-regular
   file, an invalid timeout. Nothing is returned.
2. **An acquisition result with a non-`ok` status** — the observation ran and the answer is that
   the evidence is not available. An absent file, unparseable content, a failing command. This is
   a successful adapter call reporting bad news, and it flows into the snapshot as evidence.

Confusing the two would either hide configuration faults as evidence gaps, or turn ordinary
unavailability into a crash.

## The root
Every path resolves under an **explicit caller-supplied root**. The adapter never consults the
process working directory, because the same declaration must not observe different files depending
on where a program happened to be started.

Template refs are relative — `.vfy/approvals.json`, `./claim/authority.json`,
`./ci/last-test-result.sh` — and resolve under that root. An absolute `ref` is refused: it would
by definition escape.

Escape is prevented by resolution, not by string inspection. The candidate path is fully resolved
and must remain inside the resolved root, so `../` sequences, doubled separators, and any other
spelling that lands outside are all refused the same way — and a spelling that lands back inside,
such as `a/../b`, is not refused at all.

**A root that is not an existing directory is a typed adapter error**, not a run of `missing`
results. One mistyped root would otherwise turn every declaration in a rulebook into an evidence
gap, which reads as "nobody has gathered this yet" when the truth is "nobody looked in the right
place". A root that is itself a symlink is refused for the same reason a component symlink is.

## File observation
1. validate the declaration — `source` must be `file`, `ref` must be present;
2. resolve under the root, refusing escape;
3. refuse a symlink anywhere on the way, and refuse anything that is not a regular file;
4. open once and read at most the byte limit plus one, so oversize is detected rather than
   truncated silently;
5. strict-load the bytes as JSON through the closed loader;
6. canonicalize;
7. return `ok` with the value.

An absent file returns **`missing`**. Unreadable or unparseable content returns **`error`**.
A traversal, a symlink, a directory, or a device returns a **typed adapter error** — evidence
declared at a path occupied by a directory is a configuration fault, not an observation.

**The bytes read through one descriptor are the observation.** The file may change a microsecond
later; the snapshot freezes what was read, not the file. No claim is made that the file was
unchanged before, during, or after, and no second read is taken to compare.

### What the symlink check does and does not close
Checking a path and then opening it are two operations, and something can change between them.
Stated exactly, so the guarantee is not larger than the code:

- **The final component is safe.** The open refuses to follow a symlink and refuses to block on a
  named pipe in the same operation that opens the file, and the opened descriptor is confirmed to
  be a regular file before a byte is read. A symlink substituted into that window fails the read;
  it is never followed.
- **The parent directories are not.** A component higher up the path can still be replaced between
  resolution and open. Closing that would need the whole walk done through directory descriptors,
  which is worth doing when an adapter reads a path another user can write to — and v1 does not
  claim it.
- **A command is weaker still.** Launching a process follows symlinks by definition, so an `exec`
  ref has the pre-launch check and nothing atomic behind it.

The atomic guarantees are POSIX ones. Where those flags do not exist the check before the open is
the floor, which is the same protection every version of this had and no less honest for being
named.

Content is strict JSON only. Type is never inferred from a filename extension.

## Command observation
`ref` names **one executable**, resolved under the root exactly as a file path is, and run as a
single-element argv.

**No shell, ever.** `shell=False`, no `/bin/sh`, no pipes, redirects, substitutions, globbing, or
variable expansion. An argument containing `;`, `$(...)`, `*`, or spaces stays one literal
argument. Command arguments are not expressible in v1: a `ref` is an executable path and nothing
is split out of it. Supporting arguments would need `ref` to become a list, which is a schema
change, not an adapter convenience.

**The environment is empty by default**, not inherited. A caller may pass an explicit mapping.
Nothing from the parent process reaches the child unless the caller names it, so a hostile or
merely surprising ambient environment cannot reach an evidence command. No `PATH` is passed,
which is consistent with `ref` being a path rather than a name to search for.

Stated precisely, because the convenient phrasing is false: **the guarantee is that the parent's
environment does not reach the child, not that the child observes an empty environment.** A script
whose first line names an interpreter is executed by that interpreter, and a shell that inherits no
`PATH` synthesizes its own compiled-in default. That default belongs to the interpreter and is
outside anything this adapter controls — one more reason the section below says plainly that this
is not a sandbox.

The working directory defaults to the root and may be set explicitly to a directory under it.

1. validate the declaration and the runtime bounds;
2. launch directly with an empty environment;
3. read bounded stdout and stderr;
4. enforce the caller's timeout and terminate the child if it expires;
5. on exit code zero, strict-load stdout as JSON, canonicalize, return `ok`;
6. otherwise return `error`.

Non-zero exit, timeout, a missing or unrunnable executable, empty stdout, unparseable stdout, and
oversized stdout all produce **`error`**. Stderr is read to keep the child from blocking on a full
pipe and is then discarded — it never reaches the result, because stdout of a failing command is
exactly where secrets tend to appear.

**This is not a sandbox.** Running a child process directly is not process isolation: the command
runs with the invoking user's privileges and can do anything that user can. What is bounded is the
interface — no shell, no inherited environment, a path under the root, bounded output, and a
timeout. Nothing here confines what the command itself does.

## Bounds
Operational limits, versioned with the adapter, not universal truths. They exist so that ordinary
input acceptance is decided by a declared number rather than by how much memory a machine happens
to have.

| Bound | Value |
|---|---|
| maximum file bytes | 1 048 576 |
| maximum stdout bytes | 1 048 576 |
| maximum stderr bytes read and discarded | 65 536 |
| timeout | caller-supplied, 1 to 300 seconds |
| argv length | 1 (the executable) |
| single argument length | 4 096 |

Exceeding a content bound is an `error` status. An invalid *configuration* bound — a timeout of
zero, or of a year — is a typed adapter error.

## Integration
An acquisition result's mapping form is exactly what `build_snapshot` accepts, with no translation
layer between them. The id, the status, the `acquired_at` string, an explicit JSON `null`, and any
nested structure all pass through unchanged, and fixtures prove it by running adapter output
straight into the builder and then into the evaluator.

What an adapter cannot do is make a rule reachable. Unsettled is absorbing and the rule walk stops
at the first unsettled rule, so an `error` item early in a rulebook holds the run even when a
later rule would have settled on the candidate alone. `bridge_pipeline_gate_hold_before_a_later_block`
freezes that: an unavailable command holds at `tests-red` and never reaches the `wrong-branch`
BLOCK. Unavailable evidence stops the walk; it does not let a later rule speak in its place.
