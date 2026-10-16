# Scoped producer readiness — isolated service-copy adoption

The additive contract is SERVICE_ADOPTION_CONTRACT.md; implementation is
vfy/service_adoption.py. Existing accepted runtime modules are byte-unchanged.
No real C7 pool transition, service execution or original-source mutation was
performed by the producer. Root owns that independent consumer acceptance.

Installed root: /private/tmp/verify-run-service-adoption-installed-20261016
Wheel: /private/tmp/verify-run-service-adoption-artifacts-20261016/verify_run-0.1.0a7-py3-none-any.whl
Wheel SHA256: e210312b19e18fc0df14fa9d28b23a1cc57cad70cff2f2eb11a2bf79ef25e2e2
Module SHA256: 0c98ad29c930d7a772ebe2203ab0c7a1c12f958ddaa4abb5f14e70d04826be66

Source checks: 114 passed. Installed checks: 114 passed (24 adoption controls,
plus retained checker, service accounting and existing authorization vectors).
Independent read-only review found and then rechecked fixes for repeated failed
validation reads and unrelated-pool inheritance. No remaining concrete blockers
reported within trusted local-controller/cooperative-filesystem scope.

The initial installed harness failed one old static-source inspection because its
fixture root deliberately lacked vfy/. The final driver points that inspection at
the installed source. No runtime change was required; initial failure log retained.

Contract additions: accounting_pool_root and accounting_predecessor_sha256 bind the
exact tested shared head. Wrong authority refuses before selected reads; reservation
is consumed before source/evidence checks, so changed-base or validation failure
retains all charges and cannot retry. Full logical I/O is not claimed: read_bytes
covers selected verification payloads as explicitly listed in the contract.

Preparation, all lifecycle costs, human/Platform current authority, organizational
adoption, semantic sufficiency, ordinary entry and full V1 closure remain OPEN.
Published synthetic development keys establish no external authority. No release.
