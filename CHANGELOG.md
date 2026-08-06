# Changelog

Notable changes to `verify-run`. This project follows [PEP 440] versioning; the decision
semantics, canonical form, and artifact schemas carry their own `spec_version`, which changes
independently of the package version.

[PEP 440]: https://peps.python.org/pep-0440/

## 0.1.0a3 — unreleased

Final hardening pass before `verify-run` is frozen. Closes the remaining findings from the
external review of `0.1.0a2` and adds no capability.

### What did not change, named exactly

Byte-identical, verified by digest: `spec/receipt.schema.json`, `spec/authorization.schema.json`,
`spec/candidate.schema.json`, `spec/evidence.schema.json`, `spec/outcome.schema.json`,
`spec/rulebook.schema.json`; `conformance/decision-replay-v1/profile.json`, its
`result.schema.json`, its `fixtures/manifest.json` (digest `756029f6…`), and all 30 fixture
bundles. The canonical form, the digest domains, the signed-byte construction, the signature
scheme, and the reason-code set are unchanged. No new reason code, verdict, or artifact field
exists.

**One public interface did change, and it is not a schema.** `vfy receipts list --json` gains a
`refused` array of `{"file", "code"}` alongside the existing `receipts` array. That output has
never had a schema; it is a CLI representation, and the change is additive — a consumer reading
`receipts` is unaffected, and the array is empty when nothing was refused. The human output gains
refusal lines on **stderr**, so stdout stays a clean listing. What is not additive is the exit
code: a store containing an unreadable artifact now exits `1` where it previously exited `1` by
raising, and where a store whose damage happened to sit behind an agreeing index previously exited
`0`. See below.

### Compatibility, as tested rather than inferred

Every version was installed from PyPI into its own clean environment, and all three wrote into one
shared workspace created by `0.1.0a1`:

| Receipt written by | Replays under a1 | under a2 | under a3 |
|---|---|---|---|
| 0.1.0a1 | yes, until its authorization interval elapses | yes | yes |
| 0.1.0a2 | yes, until its authorization interval elapses | yes | yes |
| 0.1.0a3 (this) | yes, until its authorization interval elapses | yes | yes |

**Forward compatibility is complete: every a1 and a2 artifact verifies and replays under a3.**

**Reverse compatibility with `0.1.0a1` as a *reader* is bounded by a1's own defect and is not
claimed.** `0.1.0a1` stops replaying *any* ALLOW receipt — including ones it wrote itself — once
the authorization's validity interval elapses, which is the defect `0.1.0a2` exists to fix. That
boundary was reproduced directly: an ALLOW receipt written by a1 under a one-second interval is
refused by a1 with `authorization_expired` three seconds later, and replays under both a2 and a3.
Anyone keeping receipts should read them with a2 or newer.

The Decision Replay Conformance Profile v1 suite passes 30/30 against this source and against the
published `0.1.0a2` distribution, with an unchanged profile and fixture set.

### Fixed

- **One damaged receipt made `vfy receipts list` useless for the whole store.** A single file that
  was not canonical, not readable, or not a receipt ended the listing, so every healthy record
  became unreachable through that command — an availability failure with no security benefit,
  since a listing verifies nothing and `get_record` still refuses the damaged file. A listing now
  names each artifact it could not read, **by filename with its reason code**, lists every record
  it could, and exits `1`. Nothing is deleted and nothing is repaired. The same rule now covers a
  malformed, unreadable, or symlinked `index.json`, which used to fail a listing the same way;
  writing still refuses a symlinked cache rather than renaming over it.
- **A listing answered from a cache that could not see damage.** Reconciliation compared receipt
  *identities*, which a record damaged after it was indexed still has, so a corrupt receipt
  committed before the last write was reported as healthy. A listing now derives from the
  committed records, which is the only way to answer both "which records are there" and "which of
  them still read". The index remains what `spec/local-store.md` calls it — an optimization, never
  an authority — maintained by `put_record` and rebuilt by `rebuild_index`.
- **`vfy run` captured one instant and used it for every recorded time**, which left three of the
  chain's own questions with only one possible answer while the runtime went through the motions
  of asking them. Evidence was always exactly zero seconds old at the freeze, so `fresh()` was
  always true and `max_age_seconds` bounded nothing. An authorization was verified at the instant
  it was minted, so `ttl_seconds` was unreachable in the one place in this product that spends
  one. A command that ran for an hour was acknowledged at the instant its evidence was frozen.
  The clock is now read once at each point in the chain where a distinct instant exists — start,
  each acquisition, the freeze, the issue, the spend, and the completion — and the readings stay
  monotone, so every ordering rule the chain already enforced still holds. **A fixed clock still
  reproduces a run byte for byte**, `vfy replay` still reads no clock at all, and nothing below
  `vfy/cli.py` and `vfy/workflow.py` holds one: the runtime is handed the completion clock and
  reads it exactly once, after the child has exited.
- **A relative output directory silently broke the conformance reference run.** Step 2 changes
  directory, and the interpreter path was resolved against the new one.

### Changed

- **Conformance: a run that could not be conducted is INCOMPLETE, never FAIL.** An adapter that
  will not start, times out, or does not speak the protocol used to produce thirty errored
  fixtures and a FAIL verdict — a confident, false statement about an implementation that was
  never actually measured. Adapter transport failures are now reported as setup problems on
  stderr with the verdict INCOMPLETE. A leaked private-key marker is the deliberate exception and
  is still FAIL: that is a real defect of the thing under test.
- **Conformance: setup problems are caught before the fixtures run.** The adapter command is
  resolved and checked first; an adapter that answers the capabilities request with an error, or
  that declares a different profile, stops the run with one sentence instead of thirty.
- The reference adapter now **proves the `vfy` it found is this distribution** before using it. An
  unrelated program named `vfy` on `PATH` was previously run as the implementation under test.
- Python version preflight, with the version it needs and the one it has, in the conformance
  runner (3.8), the reference adapter (3.11, from the distribution's own metadata), and
  `tools/conformance_reference_run.sh` (which also accepts `PYTHON=/path/to/python3`).
- `run_conformance.py` accepts repeated `--adapter-arg`, one argv token each, for commands whose
  paths contain spaces. `--adapter` still splits shell-style.

### Added

- `tools/check_conformance_result.py` — checks a result document and the kit that produced it in
  one step, so a PASS against a modified fixture set cannot be mistaken for a PASS.
- A CI job that builds the distribution, installs it into a clean environment, and runs the full
  conformance kit against it. Anything but PASS fails the job, INCOMPLETE included.

### Documentation

- **`vfy replay` exit codes**, stated separately because they are the most misread part of the
  table: `replay` exits with the *decision the receipt records* — `0` ALLOW, `10` BLOCK, `11`
  HOLD — and `1` when it did not verify. A BLOCK receipt that verifies perfectly exits `10`, so
  `vfy replay r.json && echo ok` asks the wrong question. `spec/cli.md`,
  `docs/receipts-and-replay.md`, and the adapter protocol now say so, with the shapes to use
  instead.
- **Three bindings deliberately not added** (`docs/security.md`), each evaluated individually in
  this pass and recorded rather than closed quietly: the executable's bytes are not bound to the
  authorization — and cannot honestly be, without `fexecve` — but are gateable today as recorded
  evidence, which is demonstrated and now regression-tested; `track` still has no executable
  force; and the store still has no identity of its own.

## 0.1.0a2 — unreleased

Maintenance release. Repairs found by an external audit of `0.1.0a1`, reproduced against both the
tagged source and the published PyPI artifact before anything was changed.

**No signed-artifact format, schema, canonical form, digest domain, or reason code changed.** Every
`0.1.0a1` receipt still verifies and replays — including ALLOW receipts that `0.1.0a1` itself had
stopped being able to replay. Upgrading is recommended for anyone keeping receipts.

### Fixed

- **ALLOW receipts stopped replaying once their authorization TTL elapsed.** `vfy replay` and
  `vfy receipts show` compared a recorded authorization's validity interval against the *present*
  clock, so every ALLOW receipt began failing with `authorization_expired` two to ten minutes
  after it was written, depending on the template. BLOCK and HOLD receipts were unaffected, so
  precisely the records of actions that happened were the ones that expired out of the guarantee.
  Replay now checks the interval for internal consistency and cross-checks every binding,
  signature, key identity, and the recomputed ALLOW — but never asks whether the authorization is
  still *spendable*, because replay spends nothing. `vfy replay` now reads no clock at all.
  **Live spending is unchanged and still time-bound**: `vfy run` verifies the interval against the
  instant it is spending at, so an expired or not-yet-valid authorization is still refused.
- **One corrupt historical receipt made an unrelated later run report a failure that had not
  happened.** The subordinate index refresh scans every committed receipt, and a typed failure
  from that scan escaped `put_record` *after* the commit rename — so a run that had executed,
  consumed its nonce, and committed a complete record exited 14 with "its record could not be
  written". Index maintenance can no longer revoke a commit, as `spec/local-store.md` already
  required. Corrupt artifacts are still never deleted, still refused by name on load, and still
  refused by a listing once the index disagrees with the records.
- **Nested list literals bypassed the declared nesting bound.** `MAX_NESTING` was enforced for
  parentheses only, so `[[[…]]]` recursed until the host's stack gave out: a raw `RecursionError`
  crossed `parse_expression`, and whether a given depth was accepted depended on
  `sys.setrecursionlimit` — depth 500 was refused at one limit and accepted at another. Every
  recursive path in the grammar now carries the same bound of 64, and a parsed expression is
  required to reload through the strict loader so an accepted expression is always a usable one.
- **`matches` was exponential in the number of `*` segments.** Measured on `0.1.0a1`: an
  eleven-character pattern with four stars against a two-hundred-character value took over nine
  seconds; six stars did not finish. No bundled template was affected, but a rulebook's patterns
  are written by an operator while the values they run against come from whoever proposes the
  candidate. The matcher is now iterative and bounded by `|pattern| x |value|`. Results are
  unchanged — the previous matcher is kept in the test suite as the semantic reference and
  compared against exhaustively.
- **The registry accepted one public key under two identities.** `key_id` and `key_version` sit
  outside the signed bytes, which is safe only because a substituted `key_id` selects a key the
  signature does not verify under. Registered twice, it selected the same key — so a relabelled
  artifact verified under an identity that never signed it, and a retired identity could be
  escaped by relabelling to an active one. `build_key_registry` now refuses this with
  `signing_key_invalid`. Distinct keys, and one key under several versions, are unaffected.
- **The bundled `agent-guard` template could not enforce its own first rule.** It compared
  `argv[0]` against bare program names, but `vfy run` resolves `argv[0]` to a path before the
  candidate is built, so the rule never fired on a gated command — every run fell through to the
  default HOLD unless the summary happened to contain `rm -rf`. The rule now matches both the
  resolved path and the bare form. This changes the template's digest; templates are versioned
  starting points, not signed artifacts, and receipts record the rulebook that governed them.

### Documentation

- `vfy check` was documented as starting no process while it acquires `exec` evidence, which is a
  local child process by definition. It never starts the *candidate's* action; that is now what is
  claimed, in `spec/cli.md`, the README, and `docs/security.md`.
- `track` was described as naming "the identity fields the receipt binds". It is schema-validated
  and then never consulted; the receipt binds the whole candidate through `candidate_digest`
  regardless. It is now documented as declarative in v1.
- `acknowledged_at` is the instant the run began, not the instant the command finished — a
  consequence of the one-instant-per-run design that no document had stated.
- `spec/expression-language.md` now declares the parser's nesting bound and the matcher's cost
  bound explicitly.

## 0.1.0a1 — unreleased

First alpha. The complete local runtime and its command-line surface.

### Added

- **Canonical serialization** with frozen golden vectors: UTF-8, keys sorted by code point,
  integers only within ±(2⁵³−1), floats and lone surrogates refused.
- **Strict document loading** for JSON and a frozen YAML subset — no anchors, aliases, merge keys,
  tags, or ambiguous plain scalars.
- **Bounded schema validation** against six frozen schemas.
- **Rulebook loading and pinning**, with adoption governing future runs only.
- **Expression language** with three-valued settlement where unsettled is absorbing and does not
  short-circuit.
- **Deterministic evaluation** producing ALLOW, BLOCK, HOLD, or ERROR, with a rule-by-rule trace.
- **Evidence snapshots**, frozen and content-addressed.
- **Local evidence adapters** for `file` and `exec`, bounded, with no shell and an empty
  environment by default.
- **Action-bound single-use authorizations**, Ed25519-signed, verified by recomputing every
  binding including the evaluation itself.
- **Gated execution**: verify, consume atomically, launch directly, acknowledge, receipt, store.
- **Signed receipts** and offline replay that recomputes the decision from recorded inputs.
- **Local store** with atomic commit, authoritative records, and a subordinate rebuildable index.
- **CLI**: `vfy init`, `check`, `run`, `replay`, `receipts`, with `--json` and a stable exit-code
  contract.
- Three templates: `agent-guard`, `pipeline-gate`, `claims-gate`.

### Known limitations

- `http` evidence is declared by the schema and by `claims-gate` but is **not acquired**. The item
  is recorded as missing and the rulebook holds.
- `watch` and `serve` modes are not implemented.
- Exactly-once external execution is not claimed; see `docs/security.md`.
- Windows is untested. Full power-loss durability is not claimed.
- Not independently audited or formally verified.
