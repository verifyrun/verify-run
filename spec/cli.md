# CLI — the one local developer workflow
    cli_version: 1

A thin delivery layer over the closed runtime. It parses arguments, resolves a workspace, calls
already-closed APIs in the already-fixed order, and renders the result. It decides nothing.

It does not evaluate a rule, compute freshness, compare a digest, verify a signature, consume a
nonce, or replay a receipt itself. Every one of those has a closed owner, and a second
implementation at the delivery layer is how a product starts disagreeing with itself.

## The command set
`CLAUDE.md` fixes it — "v1 CLI surface (**nothing more**)" — and the architecture's v1 narrowing
says the same: `vfy init · check · run -- <cmd> · replay · receipts`.

    vfy init [--template agent-guard|pipeline-gate|claims-gate]
    vfy check <candidate.json>
    vfy run -- <command> [args...]
    vfy replay <receipt-path>
    vfy receipts [list|show <receipt-id>]

`watch`, `serve`, and `rules` appear once each in the architecture's illustrative file-tree
comment and are excluded by the same document's v1 narrowing and by `CLAUDE.md`'s "nothing more".
An illustrative listing does not outrank an explicit boundary. Nothing else is added because it
would be conventional.

## Workspace
    project/
      rulebook.yaml            the governing rulebook, copied from a template
      .vfy/
        config.json            delivery configuration, strictly validated
        keys/
          authorization.key    Ed25519 seed, 0600, never printed
          receipt.key          Ed25519 seed, 0600, never printed
          trust.json           the public half: what this workspace verifies against
        store.json             LocalStore's own marker
        index.json             derived, subordinate
        receipts/              committed records and their replay bodies
        consumed/              spent nonces
        tmp/                   store-owned staging

`.vfy/` **is** the `LocalStore` root, so `store.json`, `index.json`, `receipts/`, `consumed/`, and
`tmp/` are the store's, exactly as `spec/local-store.md` lays them out, and the architecture's
`.vfy/receipts/0001.json` path is what a developer sees.

`keys/` and `config.json` sit inside `.vfy/` but are **not** store artifacts. The store never
reads them and never will: it refuses symlinks in its own layout and ignores everything else.
Keys live beside the store rather than in it because a workspace is one unit to copy, move, or
delete, and splitting the two would mean two roots to explain.

Every path is relative to an explicit workspace root — `--workspace`, defaulting to the current
directory. No home directory is inferred, no global configuration is read, and no environment
variable names a path.

## Configuration
`.vfy/config.json` is strict JSON through the closed loader, then checked field by field against
the table below. **An unknown field at any level is refused**, not ignored: a typo in a
security-relevant setting must never be silently discarded, and a config that half-applied would
be worse than one that failed.

It is validated here rather than by a schema in `spec/`, deliberately. `vfy/schema.py` is closed
and its registry declares one reason code per schema id; adding two ids would mean reopening a
closed unit to describe a delivery file that is not a trusted artifact and never enters a digest.
The keyword set it supports has no `maximum` either, so the bounds below could not be expressed in
it. Explicit checking costs a few lines and reopens nothing.

| Field | Type | Constraint |
|---|---|---|
| `config_version` | integer | exactly `1` |
| `runtime_id` | string | `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` |
| `rulebook` | string | non-empty, workspace-relative, no traversal |
| `template` | string | one of the three template names |
| `evidence.file_root` | string | non-empty, workspace-relative, no traversal |
| `evidence.command_working_directory` | string | non-empty, workspace-relative, no traversal |
| `evidence.command_timeout_seconds` | integer | 1 to 300, the adapter's own bounds |
| `keys.authorization` / `.receipt` / `.trust` | string | non-empty, workspace-relative, no traversal |
| `execution.working_directory` | string | non-empty, workspace-relative, no traversal |
| `execution.timeout_seconds` | integer | 1 to 3600, the runtime's own bounds |
| `execution.environment` | object | string keys, string values; `{}` by default |
| `search_path` | array | strings, workspace-relative, no traversal |

Every path is refused if it is absolute or contains a `..` segment. The workspace root is the one
boundary a configuration file may not talk its way out of.

`.vfy/keys/trust.json` is checked the same way: `trust_version` exactly `1`, and `authorization`
and `receipt` lists of `{key_id, key_version, public_key_hex, status}` with a 64-hex public key
and a status of `active` or `retired`. Nothing else.

`environment` defaults to `{}` and is the **only** way a variable reaches a gated command or an
evidence command. The parent environment is never inherited, so what a gated action sees is a
property of the recorded workspace rather than of whoever ran the shell.

`search_path` is a list of workspace-relative or absolute directories. It is not `PATH` and is
never read from the environment.

## Runtime identity
`runtime_id` comes from `.vfy/config.json` and nowhere else. `init` writes
`local-<16 hex of the workspace's own generated authorization public key>`, so it is stable,
workspace-scoped, and derived from something the workspace already holds.

It is never taken from a hostname, username, machine id, environment variable, or directory name.
A runtime that discovers its own identity can be made to discover a different one, and the
identity is inside signed bytes.

## `vfy init`
1. refuse a workspace path that is a symlink or not a directory;
2. refuse an unknown template — only the three in `templates/`;
3. copy the template to `rulebook.yaml` **byte for byte**;
4. generate two Ed25519 keypairs, authorization and receipt, and write the seeds `0600`;
5. write `trust.json` with the two public halves and their status;
6. write `config.json`;
7. create the store by constructing `LocalStore` on `.vfy/`;
8. **load and pin the copied rulebook** — an initialization that produced an unusable workspace
   would have succeeded at nothing.

**Idempotent only on identical bytes.** Re-running over a workspace whose files match exactly
succeeds and changes nothing. Any differing byte in `rulebook.yaml` or `config.json` is refused
with `cli_workspace_conflict`. Keys are never regenerated over an existing workspace: a new
authorization key would silently orphan every receipt the old one signed.

**No fixture key ever reaches a real workspace.** The published test constants in `fixtures/`
authorize nothing and are not copied, read, or defaulted to. Key generation is the one place this
layer draws randomness, it happens at the delivery edge only, and no private byte is ever printed
— not in help, not in errors, not under any flag.

## `vfy check`
    vfy check candidate.json

Steps 1 to 4 of `spec/execution-chain.md`, and then it stops.

It strict-loads the candidate, pins the rulebook, acquires the declared local evidence, freezes a
snapshot, evaluates, and prints the decision. It **issues no authorization, consumes no nonce,
never starts the candidate's action, and writes no receipt.**

Said exactly, because the convenient phrasing is false: **acquiring evidence is not free of side
effects.** Steps 1 to 4 include acquisition, and an `exec` evidence declaration is a local child
process by definition — so `vfy check` does run the evidence commands the rulebook declares, with
the same empty environment and bounded output as `vfy run`. What it never does is start the
candidate's own action. "Executes nothing" would be a claim about subprocesses that this command
cannot make; "never executes the candidate" is the claim it can.

That last one is a decision worth stating rather than assuming. `spec/execution-chain.md` says
every decision emits a receipt — of a *governed run*. A check is a preview: nothing was
authorized and nothing happened. Writing a receipt for it would put decisions that never executed
into the same ledger as ones that did, and `vfy receipts` would stop answering "what has this
workspace done". A preview is rendered and discarded; if you want a record, run it.

`check` can reach ALLOW, BLOCK, HOLD, or ERROR, and the exit code says which. It can never
execute.

## `vfy run`
    vfy run -- <command> [args...]

Everything after `--` is the command, verbatim. The first argument that could be mistaken for an
option is protected by `--` itself, so `vfy run -- ./tool --force` passes `--force` to the tool.

1. resolve the workspace, load and validate the configuration, load the keys;
2. capture **one** run instant from the clock;
3. strict-load and pin the rulebook;
4. resolve `argv[0]` and construct the candidate;
5. acquire every declared local evidence item;
6. build the snapshot with that instant as `frozen_at`;
7. evaluate;
8. **BLOCK or HOLD** — nothing launches and nothing is consumed. The decision is real, so the
   chain's receipt rule applies: a receipt is issued and the complete record is stored;
9. **ERROR** — nothing launches, and no receipt: `spec/execution-chain.md` is explicit that ERROR
   is not a decision and emits none;
10. **ALLOW** — hand the whole thing to `runner.execute_authorized_command`, which verifies,
    consumes, launches, acknowledges, receipts, and stores in the order Unit 12 froze. The CLI
    does not re-implement one step of it;
11. exit with the code for what happened.

## Candidate construction
    vfy run -- ./deploy.sh v1.2.3

produces exactly:

    {"candidate_id": "c-<32 hex>",
     "kind": "command",
     "action": {"summary": "<argv joined by a single space>",
                "argv": ["<resolved argv[0]>", "v1.2.3"]},
     "identity": {...}}

`kind` is always `command` — it is the only kind that names a process. `summary` is descriptive
and never executed. **No argument is altered after construction**, and none is added, removed,
split, joined, quoted, or expanded.

`candidate_id` is `c-` plus the first 32 hex of the digest of the canonical
`{"argv": [...], "frozen_at": "..."}`. Deterministic, non-circular — it is computed from values
that exist before the candidate does — and it never draws randomness.

`identity` carries the rulebook's `track` fields, supplied by repeatable `--identity NAME=VALUE`
flags, and is omitted entirely when none is given. It is a flag rather than a configuration field
because a track value such as the branch being deployed is a property of the run, not of the
workspace. A track field with no value is `absent`, which `spec/execution-chain.md` already
declares is not an error — so a rulebook that gates on one simply does not reach ALLOW without it,
which is the correct answer rather than a failure.

### Resolving `argv[0]`
Unit 12 refuses a bare name, because the interpreter's compiled-in default path would decide what
runs and one `action_digest` would mean different programs on different machines. So the CLI
resolves the name **before** the candidate is built, and the resolved path is what gets digested,
authorized, executed, and recorded.

- a path — contains a separator — is resolved against the execution working directory and used;
- a bare name is searched along `config.search_path`, in order, taking the first entry that is a
  regular file with the executable bit. **Never `PATH`**, never the parent environment;
- nothing resolves → `cli_executable_not_found`, before evaluation, before any evidence is
  acquired, and certainly before anything runs.

## Evidence orchestration
Each declaration in the pinned rulebook, in declared order:

- `file` → `vfy.evidence.acquire_file` under `config.evidence.file_root`;
- `exec` → `vfy.evidence.acquire_command` under the same root, with the configured working
  directory, timeout, and the empty-by-default environment;
- `http` → **not acquired**. No socket is opened and nothing is fabricated.

An unsupported source is neither hidden nor treated as a broken rulebook. Nothing is acquired for
it, `build_snapshot` synthesizes the required item as `missing`, and the rulebook holds on it
exactly as it should. The CLI prints one line naming the id and the source so the developer knows
why, and `claims-gate` — which declares `coverage` over `http` — reaches HOLD locally with that
line explaining it. The rulebook is valid; the evidence is simply not available here.

Every acquisition's `acquired_at` is the same captured run instant. An adapter never constructs a
timestamp, and the caller that does must be the one that also freezes.

## Keys and trust
`.vfy/keys/trust.json` is the workspace's trust anchor: `authorization` and `receipt` lists of
`{key_id, key_version, public_key_hex, status}`. Two registries, kept separate — a system that
rotates one need not rotate the other, and `spec/receipt-and-replay.md` deliberately treats
retirement differently for each.

Private seeds are read from `keys/`, checked to be regular files that are not symlinks, and
**warned about if their mode grants group or other access**. They are never printed, never logged,
never echoed in an error, and never placed in an artifact. No key material is ever read from an
environment variable, and no key is ever trusted because an artifact carried it.

There is no key-rotation command in v1. Nothing requires one yet, and inventing one would mean
inventing a policy for what happens to receipts signed by the old key.

## `vfy replay <path>`
Takes a path to a stored receipt. The workspace's store owns the bodies at the sibling
`.inputs/` directory, so replay reads the receipt id from the path and calls
`LocalStore.get_record`, which re-verifies and replays through the closed API. There is no
shortcut comparison here and no second replay implementation.

A receipt path outside the workspace store, or one whose id is not storable, is refused with
`cli_path_outside_workspace`. Replay of a foreign receipt is a real need and a later one: it wants
a trust registry that is not this workspace's, which is a decision this unit does not have to make
to ship.

Replay executes nothing, acquires nothing, opens no socket, and **reads no clock at all**. Every
input it needs is on disk. A referenced authorization is still cross-checked by content and by
signature; what is not asked is whether it remains spendable now, because replay spends nothing —
see `spec/receipt-and-replay.md`. This is why a receipt written months ago still replays.

**Verification and replay are reported separately**, exactly as `spec/receipt-and-replay.md`
requires: a receipt whose signature verifies but whose bodies are missing is reported as verified
and not replayed, not as a failure of either.

## `vfy receipts`
    vfy receipts list
    vfy receipts show <receipt-id>

`list` calls `LocalStore.list_receipts` and prints what the summaries carry, in the store's
`(created_at, receipt_id)` order. It inherits the repaired store behavior wholesale: the index is
subordinate, a listing reconciles against the committed records, a stale index heals, and an entry
naming a record that does not exist is never believed. The CLI does not read `index.json` itself.

A malformed index surfaces as `store_index_invalid` with the repair named — rebuilding is always
available — rather than as an empty list, because an empty list would read as "nothing happened".

`list` does not verify each receipt: it is a listing, and claiming verification it did not perform
would be the exact confusion this product exists to prevent. `show` loads one record **with**
verification and replay through `get_record`, and says so.

## Output
Human output uses product vocabulary only: rulebook, gate, evidence, snapshot, decision,
authorization, receipt, replay, runtime, verification, and the four outcomes.

    ALLOW   deploy                     rule: tests-green-on-main
            receipt .vfy/receipts/<id>.json   executed, exit 0

    BLOCK   clean up                   rule: no-destructive-shell
            Destructive shell commands are never allowed.
            receipt .vfy/receipts/<id>.json   nothing executed

    HOLD    settle claim
            evidence_unsettled: coverage
            evidence coverage is declared over http, which this local runtime does not acquire
            receipt .vfy/receipts/<id>.json   nothing executed

Never printed: private key bytes, the environment, evidence values, or the gated command's stdout
and stderr — any of which can carry credentials. A gated command's output is returned to the
caller's terminal only when it is the command's own stream, never re-rendered by the CLI into a
diagnostic. Expected typed failures print one line and no traceback.

`--json` prints one canonical JSON object on stdout through the frozen canonicalizer, with every
diagnostic on stderr. It is a stable field set — `command`, `outcome`, `matched_rule`, `reasons`,
`receipt_id`, `receipt_path`, `executed`, `exit_status`, `exit_code` — carrying no timestamp that
is not already in an artifact and no secret. It is canonical because it is produced by the same
canonicalizer everything else uses; calling pretty-printed JSON canonical would be a lie.

## Exit codes
Three different things, never merged: the decision, the child process's status, and the CLI's own
health.

| Code | Meaning |
|---|---|
| 0 | ALLOW, and the authorized command exited 0 — or `check` previewed ALLOW |
| 10 | BLOCK |
| 11 | HOLD |
| 12 | ERROR |
| 13 | ALLOW, execution attempted, and the command did not exit 0 — non-zero, timed out, signalled, or could not start |
| 14 | ALLOW, the attempt finished, and the record could not be written |
| 1 | a CLI operational failure with no decision: bad configuration, missing keys, unknown template, unresolvable program |
| 2 | usage error, from the parser |

**13 is not a demotion.** The decision stays ALLOW and the receipt records ALLOW; the code says
the authorized action failed. A flaky command must never be able to rewrite a rulebook's judgment,
and a caller that wants the child's own status reads `exit_status` from `--json`. A stable bounded
code is what a pipeline can branch on, and passing the child's status through would collide with
the decision codes.

## The clock, and where it stops
The trusted runtime is clock-free and stays that way. Orchestration is not: a real run has to say
when its evidence was frozen and when its authorization was issued.

    class Clock:
        def now_utc(self) -> str: ...

Serialized as `YYYY-MM-DDTHH:MM:SSZ` from `time.gmtime`, integer seconds, no fraction, no local
timezone, no locale-dependent formatting, no floating-point arithmetic. UTC always.

`vfy run` captures **one** instant and uses it for `frozen_at`, every `acquired_at`, `issued_at`,
`verification_time`, `acknowledged_at`, and the receipt's `created_at`. One run is one instant, so
a run cannot be internally inconsistent about when it happened, and no clock is read between the
freeze and the launch where a slow disk could make evidence look stale.

Two consequences follow from that, and both are properties of this design rather than accidents:

- **`acknowledged_at` is the instant the run began, not the instant the command finished.** A
  command that runs for an hour is acknowledged at the same instant its evidence was frozen. The
  acknowledgment records *that* the runtime reported back, and the receipt is not a duration
  measurement; a caller that needs elapsed time measures it around the call.
- **An authorization issued and verified at one instant cannot expire between the two.** `vfy run`
  therefore never reaches `authorization_expired`. `ttl_seconds` bounds a *stored* authorization
  presented later — which is a shape this CLI does not yet offer — so within `vfy run` it is
  carried into the artifact and does not gate anything. `vfy replay` does not consult it at all
  (`spec/receipt-and-replay.md`).

**Only `vfy/cli.py` and `vfy/workflow.py` may hold a clock.** Nothing below imports one, and the
tests inject a fixed instant so no test result depends on the current time.

## Randomness, and where it stops
Two places, both at the delivery edge, both injectable:

- **key generation** in `init` — Ed25519 seeds, from the approved library;
- **the nonce and the receipt id** in `run`.

The nonce is random rather than derived because a derived one would collide when the same command
runs twice against the same evidence in the same second, and the collision would present as
`authorization_nonce_reused` — refusing a legitimate second run. The receipt id is random rather
than a counter because a counter is a read-modify-write across concurrent runs, which is precisely
the shape of defect the store closures spent two repairs removing. The architecture's `0001.json`
is illustration, not contract.

Everything else is derived: `candidate_id` from the argv and the instant, `snapshot_id` from the
candidate id, `authorization_id` from the nonce.

## Typed failures
Four CLI-level codes, for repairs the runtime's closed set does not name:

| Code | When |
|---|---|
| `cli_workspace_invalid` | no workspace, an uninitialized one, or a path that is a symlink or not a directory |
| `cli_workspace_conflict` | initialization would overwrite a file whose bytes differ |
| `cli_config_invalid` | `.vfy/config.json` is malformed, fails its schema, or names an unusable key or path |
| `cli_executable_not_found` | `argv[0]` resolves to nothing along the configured search path |
| `cli_path_outside_workspace` | a receipt path is not inside this workspace's store |

Everything else keeps the code its own closed unit already gives it. No declared failure prints a
traceback. An unexpected defect prints one internal-error line and exits non-zero, with the
traceback shown only under `VFY_DEVELOPER_TRACEBACK` — a test-only switch, read nowhere else, and
never consulted for anything that affects a decision.

## Determinism
For a fixed injected clock, a fixed injected identifier source, fixed keys, and a fixed
configuration, the CLI's artifacts and its `--json` output are byte-identical across runs, hash
seeds, locales, timezones, and UTF-8 modes. Human text may repeat a path the user supplied; it
never prints an object's memory representation or anything else unstable.
