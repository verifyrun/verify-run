# CLAUDE.md — verify-run build instructions
You are building **VERIFY** (`verify-run`): a local, deterministic action gate for consequential
software. Package `verify-run`, CLI `vfy`, Python 3.11+, stdlib + PyYAML + cryptography (Ed25519) only.

## The five product rules (non-negotiable)
1. Installs in minutes: `pipx install verify-run`. No database, login, network, browser, or cloud.
2. Free local core; paid hosted plane comes later and lives in a separate service.
3. Architecture must extend cleanly to control loops and devices later — but v1 is agent/command gating only.
4. Small enough for one person to own: v1 core ≤ ~6k LOC.
5. **The product surface never uses theory vocabulary.** Allowed nouns: rulebook, gate, evidence,
   candidate, authorization, receipt, replay, outcome. Allowed outcomes: ALLOW, BLOCK, HOLD, ERROR.

## Banned vocabulary (grep-enforced in CI; build fails if present anywhere in src/docs/errors)
PAS, PAS_s, PAS_h, TEMPOLOCK, CHORDLOCK, GLYPHLOCK, AURA, resonance, coherence, regime,
corridor, entitlement, constitution, forcing, admissibility, kernel (as product noun), lockgraph,
ELF, phase, glyph. Also banned: any import from or reference to the legacy `ric-core-2` tree.

## Authority order
1. `spec/*.schema.json` and `spec/rulebook-language.md` — the contract. Code conforms to spec, never vice versa.
2. `fixtures/` — golden vectors. Every implementation must pass them byte-exactly. When you add a
   feature, add its fixtures FIRST.
3. `docs/EXTRACTION_GUIDE.md` — what may be salvaged from the legacy repo and under what rules.
4. This file.

## Dependency law (violations are build failures)
spec → core (pure) → receipt/authorization → cli. Nothing in `vfy/` may import: requests to
network, database drivers, React/anything web, billing, or legacy code. The evaluator
(`vfy/gate.py`) is a PURE FUNCTION: no clock, no randomness, no filesystem, no network, no float
comparisons on rule thresholds (use decimal/int), no environment reads, no locale/timezone
dependence, stable iteration order (sort keys). All time, sensor, and model values enter ONLY as
recorded evidence fields.

## Execution chain to implement (exactly this, in this order)
candidate → rulebook version pinned → evidence gathered+frozen (snapshot digest) → canonical
evaluation → ALLOW/BLOCK/HOLD/ERROR + reason trace → single-use authorization (nonce, expiry,
action digest, rulebook digest, evidence digest, runtime id) → execution → acknowledgment →
signed receipt → offline replay.

## Semantics that must never collapse
- ALLOW: rulebook+evidence authorize the exact proposed action.
- BLOCK: rulebook reached a negative result. Include which rule.
- HOLD: rulebook cannot settle it (missing/stale/conflicting/uncovered evidence). NOT a failure.
- ERROR: malformed request; evaluation never validly began. NOT a decision.
- An ALLOW authorization is single-use, action-bound, and expires. Reuse must be rejected.
- Replay recomputes the decision from recorded inputs. It does not re-execute the world.
- Rulebook changes create a new version governing FUTURE runs only; receipts record which
  version governed. Never apply a rule change to a run already evaluated.

## v1 CLI surface (nothing more)
vfy init [--template agent-guard|pipeline-gate|claims-gate]
vfy check action.json            # evaluate without executing
vfy run -- <command>             # gate a command
vfy replay <receipt>             # byte-identical recomputation + signature verify
vfy receipts [list|show]

## Definition of done, per module
Fixtures pass; tamper suite rejects; `vfy replay` on any emitted receipt verifies byte-identical;
banned-vocab grep clean; no forbidden imports; README quickstart works on a fresh machine in <90s.

## Explicitly deferred (do not build in v1)
watch/loop mode, GPIO/MQTT, device enrollment, hosted anything, dashboards, SSO, org accounts,
telemetry (never), generalized model adapters, serve mode (build only if an agent integration
demands it in week 5+).
