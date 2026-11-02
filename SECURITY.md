# Security reporting

This alpha has no supported production release commitment. Candidate-specific verification and
known limits are in docs/security.md and the accompanying artifact evidence. The hosted service
and consumer application adapters have separate boundaries and owners.

For ordinary non-sensitive bugs, use https://github.com/verifyrun/verify-run/issues and provide
the version, artifact digest, platform, minimal reproduction and expected/observed behavior.
Never include private signing keys, customer data or credentials.

For suspected vulnerabilities, use the repository's private reporting form at
https://github.com/verifyrun/verify-run/security/advisories/new **only when the private form is
available**. Do not post exploit details in a public issue. If unavailable, request a private
contact from the maintainer without disclosing technical details publicly.

Release prerequisite: the maintainer must enable and test receipt of a private report or publish
an approved private contact. Private reporting was enabled and its enabled setting read back on 15 October 2026 UTC. Receipt testing remains open; enabled configuration alone does not prove report delivery. No response-time
promise or contact address is invented here. See GitHub's private reporting setup documentation:
https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository
