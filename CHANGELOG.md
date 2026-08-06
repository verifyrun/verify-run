# Changelog

Notable changes to `verify-run`. This project follows [PEP 440] versioning; the decision
semantics, canonical form, and artifact schemas carry their own `spec_version`, which changes
independently of the package version.

[PEP 440]: https://peps.python.org/pep-0440/

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
