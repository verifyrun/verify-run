# EXTRACTION_GUIDE — salvaging from the legacy repo (private quarry)
Rule: **port behavior and tests, not dependency trees.** Nothing crosses the boundary with its
imports, schemas, or vocabulary. Define the new schema first (spec/), then recreate the behavior
and attack classes against it. Visual similarity to old code is NOT evidence of correctness —
fixtures are.

## Port now (behavior + attack classes)
1. Canonicalization discipline — source pattern: src/legal/bundle.ts.
   Target: vfy/canon.py. Stable canonical JSON: UTF-8, sorted keys, no insignificant whitespace,
   explicit number handling (no floats in digests — decimals as strings), sha256 digests.
   Fixture: fixtures/canonicalization/.
2. Ed25519 sign/verify — key id + key version in every signature block; reject unknown, retired,
   wrong-key, malformed. Target: vfy/keys.py + vfy/receipt.py.
3. Adversarial vector CLASSES from vectors/v1/{canon,mutate,signing} — recreate against NEW
   schemas: digest mismatch; altered evidence; altered action; extra forbidden field; wrong
   rulebook version; unknown/retired/wrong signer; malformed signature; tampered receipt; replay
   mismatch; stale authorization; reused nonce; rulebook/selector mismatch.
   Target: fixtures/tamper/ + tests. Do not copy old JSON field names.
4. Replay contract from src/cli/verify.ts — recompute decision from recorded canonical inputs;
   never promise re-execution of the world.
5. Deterministic execution discipline (no floats / no randomness / no system time) as
   constraints on vfy/gate.py. The Q32 fixed-point numerical implementation itself is v1.5+
   reference only.

## Port later (paid plane only, separate service, never imported by vfy/)
server/billing-webhook-processor.ts, auth.ts, quota.ts, usage.ts, api-key issuance, supporting
migrations → services/verify-cloud-billing/. Rules: rename every legacy noun; new DB models; new
env vars; webhook fixtures replayed against the extracted service; zero legacy imports.

## Never port
Web UI, electron app, AGI/STEM engines, tenant control plane, decision-flow system, legacy
Python backend under legacy/vendor-dump, unrelated gates, old Postman collections (regenerate
against the new API), old migrations verbatim.

## Company assets that carry over (not repo assets)
Stripe account+prices, Google Workspace, Postman account, domains, AWS, GitHub org, accounting,
legal entity, SOC 2 program (Sprinto), security policies.
