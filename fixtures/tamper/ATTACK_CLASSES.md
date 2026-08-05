# Tamper suite — attack classes to implement in week 2 (recreate against NEW schemas)
Each becomes fixture pair (artifact, expected rejection code). Legacy vectors are the checklist,
not the source. Required classes:
1. receipt digest mismatch (any field altered post-signing)
2. altered evidence value with stale value_digest
3. altered action (argv changed after ALLOW) vs authorization.action_digest
4. extra top-level field (additionalProperties violation)
5. wrong rulebook version claimed vs digest
6. unknown signer key_id
7. retired key_version
8. wrong key signature
9. malformed signature encoding
10. replay trace mismatch (recomputed trace != recorded)
11. expired authorization presented
12. reused nonce presented
13. authorization/receipt identity binding mismatch (track fields altered or absent vs candidate)
14. evidence item with acquired_at after frozen_at, or order not 0..n-1 (must reject at snapshot build)
