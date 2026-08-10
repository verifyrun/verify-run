# Execution — spending one authorization on one exact command
    execution_version: 1

The runtime executes an action that has already been decided. It does not decide anything.

It never evaluates a rule, reacquires evidence, reinterprets a candidate, chooses a different
command, edits a rulebook, issues an authorization, or grants authority after the fact. Every
question about whether the action is permitted was settled before this boundary, and the only
thing left is to spend the permission exactly once, on exactly the action it names.

## Position in the chain
    evaluation → authorization → **verify → consume → execute → acknowledge** → receipt → store → replay

## What is executable
`spec/candidate.schema.json` does not settle this on its own, and it is worth being exact about
what it leaves open: `kind` admits `command`, `tool_call`, `http_request`, and `custom`; `action`
requires only `summary`; `argv` is optional; and **an empty `argv` is schema-valid**. A
schema-valid candidate can therefore be entirely unexecutable, and pretending otherwise would push
the decision into the launcher.

So this unit declares the narrow rule:

| Requirement | Reason |
|---|---|
| `kind == "command"` | the only kind whose action names a process. `tool_call`, `http_request`, and `custom` describe consequences this runtime cannot carry out, and guessing an execution for them would be inventing an action nobody authorized |
| `action.argv` present, non-empty, every member a string | the schema permits an empty list; a command with no program is not a command |
| `argv[0]` names a **path** — absolute, or containing a separator | see below |
| the program is a **real regular file, not a symlink**, and executable by this user | see below |

### The executable is not permitted to be a symlink
This is asked once, of the entry itself, with `lstat` — so the answer cannot depend on how the
caller spelled `argv[0]`. It used to. A bare name was checked for a symlink and refused one; a path
form was checked with `is_file()`, which follows a link and answers for its target, and accepted
one. `bin/deploy.sh` pointing at `elsewhere.sh` was therefore allowed and executed while the
identical link written as `deploy.sh` was refused — and the candidate digest, the authorization and
the receipt all named `bin/deploy.sh` while `elsewhere.sh` ran. A receipt that names a path other
than the program that ran is not a record of the action.

Refusal, rather than resolving to a canonical real path: the workspace config, the signing keys,
the trust registry, every store entry and every evidence path already refuse a symlink instead of
following one, and resolving here would also change what `candidate_digest` denotes.

**What this establishes is path identity, not content identity.** The recorded name is a real
regular executable file and not an alias for something else. Nothing here claims the bytes
inspected are the bytes that later run: the file may be replaced between the check and the launch,
and `docs/security.md` states that boundary rather than implying an immutability guarantee this
runtime cannot make.

`action.summary` is descriptive only and is never executed, never parsed, and never consulted.
`action.tool`, `action.params`, and `action.targets` are likewise never executed — but they are
inside the canonical candidate, so they are inside `candidate_digest`, so changing one changes the
digest and the authorization no longer binds. Ignored by the launcher, still bound by the
signature. That is the intended arrangement, not an oversight.

### Why `argv[0]` must be a path
An empty environment does not mean the child is looked up nowhere. Measured, not assumed:
`os.get_exec_path({})` returns `['/bin', '/usr/bin']` — the interpreter's compiled-in default —
so a bare `argv[0]` like `echo` **does** resolve, to whatever that machine keeps at `/bin/echo`.
The same authorization would then run different programs on different machines while carrying the
identical `action_digest`, which would make the digest a lie.

Requiring a path removes the search entirely: when `argv[0]` contains a separator, no path lookup
happens at all, and the program that runs is the one the receipt records.

A relative `argv[0]` such as `./deploy.sh` satisfies the rule and resolves against the
caller-supplied working directory. Stated exactly, since it is the residue of this decision:
**an absolute `argv[0]` is fully determined by the candidate alone; a relative one is determined
by the candidate together with a working directory the receipt does not record.** Both are
accepted — the existing chain fixtures are written with relative paths and a rule that unmade them
would be a rule about fixtures rather than about safety — and an absolute path is what production
callers should compose.

Resolving a bare name is a real need, and it belongs **before** the candidate is built, not here.
Whoever composes the candidate resolves the name and writes the resolved path into `argv[0]`, so
the resolution is what gets digested, authorized, and recorded. A runtime that resolved names
itself would be choosing the program after the authorization was signed.

## Order, and why it is not negotiable
    argument types
    → executable candidate
    → process configuration
    → authorization verified against the objects in hand
    → authorization consumed, atomically
    → process launched
    → acknowledgment built
    → receipt issued
    → record stored

Every refusal above the consumption line leaves nothing spent and nothing started. Every failure
below it leaves an authorization spent, and says so.

Verification is `verify_authorization` from `spec/authorization.md`, called here, not
reimplemented. It re-checks schema, key identity and status, signature, the rulebook, action, and
snapshot bindings, **recomputes the evaluation** and requires it to equal the supplied result and
to be ALLOW, the runtime binding, the validity interval against the caller's verification instant,
and nonce consumption. Nothing is accepted because some earlier process already verified it.

BLOCK, HOLD, and ERROR are refused before any of it. They carry no authorization to verify, and
the refusal names the outcome rather than failing later on a missing argument.

### Consumption is the gate
`spec/local-store.md` already settled the mechanism: exclusive creation keyed by the SHA-256 of
the nonce, atomic on POSIX and on Windows, first call wins, **every** later call fails. This unit
calls it and does not write a second consumption implementation.

Consumption happens **before process creation**, and the ordering is the whole of the local
single-use guarantee. Checking consumption and then launching would leave a window in which two
callers both pass the check; consuming and then launching leaves no such window, because the
losing caller never reaches the launch at all.

`verify_authorization` is also given a consumed-nonce view, so an already-spent authorization is
refused during verification with a clear reason rather than at the store. That check is a
courtesy, not the guarantee — between it and the consume there is still a window, and
`consume_once` is what actually closes it.

### The gap this cannot close
Stated plainly, because a storage or execution claim that is false only during an outage is worse
than no claim:

> Atomic consumption before execution prevents a second local caller from receiving the same
> execution right. **It does not make an external action exactly-once.**

- Crash after consumption, before launch → the authorization is spent and nothing ran. The right
  is gone and there is no receipt. Correct and irreversible.
- Crash after launch, before the receipt is stored → the external world may have changed with no
  stored record of it. The receipt may exist in memory and be lost.
- Crash after the receipt is issued, before the store commits → same, with a receipt that was
  never persisted.

Moving consumption after execution would make retries convenient and permit duplicate action, so
it is not done. There is no automatic retry anywhere in this unit, and a consumed authorization
stays consumed.

## Runtime identity
`runtime_id` is an explicit argument, and is passed to verification unchanged. No hostname, no
machine id, no username, no environment variable, no process metadata. A runtime that discovered
its own identity could be made to discover a different one.

## The process boundary
| Property | Value |
|---|---|
| argv | the candidate's `action.argv`, verbatim, as a list |
| shell | never |
| working directory | explicit, required, an existing real directory, not a symlink |
| environment | empty unless the caller supplies an explicit mapping of strings |
| stdin | always closed. The candidate contract carries no input, so there is none to give |
| stdout captured | up to 1 048 576 bytes |
| stderr captured | up to 65 536 bytes |
| timeout | caller-supplied, 1 to 3600 seconds |
| process group | the child leads its own, so a timeout can end its descendants |

The timeout ceiling is 3600 here and 300 for evidence adapters. The two are different jobs: an
adapter that cannot answer in five minutes is not going to, while a gated deploy legitimately
takes an hour.

**No shell, ever.** `shell=False`, no interpreter chosen by this code, no pipes, redirects,
substitutions, globbing, or variable expansion. An argument containing `;`, `$(...)`, `*`, or
spaces is one literal argument. Nothing is split, joined, rewritten, aliased, or wrapped. If a
wrapper is wanted, it is part of the authorized `argv` or it does not happen.

**This is not a sandbox.** The command runs with the invoking user's privileges and can do
anything that user can. What is bounded is the interface — no shell, no inherited environment, an
explicit directory, bounded output, a timeout, and a process group that can be ended. Nothing here
confines what the command itself does, and the product must never say otherwise.

### What the timeout actually ends
Measured on this platform, both cases:

- killing only the direct child leaves a backgrounded grandchild **running**;
- killing the child's process group ends the grandchild with it.

So the child is launched in a new session and the timeout kills the **group**. The honest limit:
a descendant that puts itself in a new session escapes, and this is POSIX behavior — on a platform
without process groups the timeout ends the direct child only. Full process-tree termination is
not claimed.

### Two launchers, deliberately
`vfy/evidence/command.py` also launches a child. It is not reused and this one does not extend it.
An adapter *observes* — one executable under a root, argv length one, output parsed as evidence.
A runtime *acts* — the authorized argv, any length, output that is not evidence at all. They make
different promises, and a shared launcher would have to weaken one to serve the other. Unifying
them is a refactor that must reopen both units, not a convenience taken here.

## The acknowledgment
`spec/receipt.schema.json` closes the shape: an `execution` object with `acknowledged`,
`acknowledged_at`, `exit_status`, and `note`, all optional, `additionalProperties: false`. Nothing
may be added, and stdout and stderr are not in it.

It means exactly what `spec/receipt-and-replay.md` says it means: **the runtime reports that it
attempted or completed the authorized action.** It is not proof the world changed. A process
exiting zero proves a process exited zero.

| What happened | `acknowledged` | `exit_status` | `note` |
|---|---|---|---|
| started, exited | `true` | the exit code | — |
| started, exceeded the timeout | `true` | omitted | `timed out` |
| started, killed by a signal | `true` | omitted | `terminated by signal` |
| could not be started | `false` | omitted | `could not start` |

`acknowledged_at` is always present and always caller-supplied. The runtime holds no clock,
constructs no timestamp, and reads nothing it was not handed — exactly as in every unit before it.
The caller supplies the instant one of two ways, never both:

- **as a string**, in `acknowledged_at` and `receipt_created_at`. A caller that already knows the
  instants — a fixture, a replay harness, anything reproducing a run byte for byte — states them.
- **as `completion_clock`**, a callable read **once**, after the child has exited, whose single
  reading dates both the acknowledgment and the receipt that carries it. The instant a command
  finished is not knowable before it starts, so a caller forced to state one in advance can only
  state the instant the run began — which is what `vfy run` did until the 0.1.x hardening pass,
  and why a command that ran for an hour was acknowledged at the instant its evidence was frozen.

Supplying both is refused with `execution_configuration_invalid`, and so is a `completion_clock`
that is not callable; both refusals happen **above** the consume, so nothing is spent. A clock
that raises, or returns anything that is not a date-time in the frozen grammar, is read below the
line — the command has already run and the nonce is already spent — so it is reported as
`execution_recording_failed` at stage `acknowledge`. Nothing is invented and nothing is retried.

**`exit_status` means the process exited with this code, and nothing else.** POSIX reports signal
death as a negative return code, and recording `-9` as an exit status would merge "exited with
status 9" and "killed by signal 9" into one number. Both are omitted instead, and the note says
which happened. The signal number reaches the caller in the returned record, where it is
operational detail rather than signed history.

`note` is drawn from a **closed set** of fixed strings — the four above and nothing else. A note
carrying a path, a pid, a duration, or an error message would put host data and nondeterminism
into a signed artifact, and two identical runs would produce two different receipts.

### A failure to start is still a receipt
The authorization was consumed. Something irrevocable happened, and a spent authorization with no
record of what became of it is exactly the hole this system exists to close. So a launch failure
records `acknowledged: false` and issues a receipt like any other attempt. The runtime reporting
"I could not start it" is the runtime reporting back.

## Output
Stdout and stderr are **operational output, not evidence and not part of the decision**. They are
returned to the caller, bounded. They are not signed, not stored, and not in the acknowledgment.

The reason is narrow and worth keeping: the output of a command is exactly where credentials,
tokens, and customer data tend to appear, and a signed receipt is the last artifact that should
carry them. Truncation is likewise operational and is reported in the returned record only —
recording it in the acknowledgment would put a fact about buffer sizes into a decision record.

## Receipt and storage
Through the closed APIs, unchanged:

1. `issue_receipt` with the acknowledgment, the authorization id, a caller-supplied
   `created_at`, and an explicit receipt key. The receipt key may differ from the authorization
   key and the registries stay separate arguments.
2. `LocalStore.put_record` with the receipt and the complete replay bodies — rulebook, candidate,
   snapshot, and the authorization.
3. The store re-verifies and replays on load exactly as `spec/local-store.md` already requires.

Replay recomputes the **decision**, never the action. A stored record proves what was decided and
what the runtime reported; it does not prove what happened in the world.

## Failure classes
Three new codes, each earning its place by naming a distinct repair.

| Code | When | Consumed? | Started? |
|---|---|---|---|
| `execution_candidate_unsupported` | the candidate is not an executable command: wrong kind, absent or empty `argv`, a non-string member, or an `argv[0]` that is a bare name | no | no |
| `execution_configuration_invalid` | the process configuration is unusable: a working directory that is missing, not a directory, or a symlink; a non-string environment entry; a timeout outside the bounds | no | no |
| `execution_recording_failed` | the attempt finished and the receipt could not be issued or the record could not be committed | **yes** | maybe |

Everything else already has a code and keeps it: `authorization_outcome_ineligible` for a
non-ALLOW result, `authorization_expired`, `authorization_not_yet_valid`,
`authorization_binding_mismatch`, `signing_key_*`, `signature_*`, and
`authorization_nonce_reused` for an authorization already spent — which is what
`LocalStore.consume_once` already raises, so a second code for the same fact would split one
repair in two.

There is deliberately **no** `execution_launch_failed` and no `execution_timeout`. Both are things
that happened, not calls that were malformed: they are acknowledged, receipted, and reported in
the returned record. Raising on them would mean a spent authorization with no receipt.

**An operational failure never becomes BLOCK, HOLD, or ERROR.** The decision was ALLOW and it
stays ALLOW. A command exiting non-zero does not retroactively make the action forbidden — it
makes it an authorized action that failed, which is a different fact recorded in a different
field. Collapsing the two would let a flaky command rewrite a rulebook's judgment.

### The recording seam
`execution_recording_failed` is the most consequential failure in this unit, so it carries what a
caller needs rather than only a message: the `stage` that failed (`issue` or `store`) and the
`receipt` if one was issued before the failure.

A caller holding that receipt still has the pinned rulebook, the candidate, the snapshot, and the
authorization, so it can persist the record later with `put_record` **without re-executing
anything**. That is the whole point of handing the receipt back. What it must not do is run the
command again: the authorization is spent, and this unit will refuse.

## Immutability
`ExecutionRecord` is frozen and carries only what a caller needs: whether the process started, the
exit status where there is one, whether it timed out, the signal where there was one, the bounded
output, whether output was truncated, the canonical acknowledgment, the receipt, and the stored
record. Canonical text is the authority and `value()` reconstructs, as in every unit since Unit 4.

No argument is mutated. The candidate, snapshot, result, and authorization a caller passes in are
the same objects, unchanged, when the call returns.
