# Changelog

Notable changes to `verify-run`. This project follows [PEP 440] versioning; the decision
semantics, canonical form, and artifact schemas carry their own `spec_version`, which changes
independently of the package version.

[PEP 440]: https://peps.python.org/pep-0440/

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
