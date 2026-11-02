# Bounded read-only current source relation

New standalone module CLI vfy.service_source_relation_cli accepts vfy.service-source-relation-request/1; it does not change existing CLI commands or adoption/legacy/current modules. Authenticated original intent, completion, destination and candidate are checked before scanning. Detected metadata/population races, failed reads, bad signatures and exhausted bounds remain UNKNOWN without a diagnostic. A complete differing scan reports MISMATCH with top-level UNKNOWN and no authority/retry/service execution. No cause/time or semantic failure is inferred.

The directory/file stability witness is under the original cooperative lock; arbitrary noncooperating ABA writers and atomic snapshot semantics are not covered. Full physical cost remains UNKNOWN. Output diagnostic digest binds exact request and entire result; consumer must also bind independently selected runtime, historic completion and expected manifest, not trust caller-recomputed digests.

Installed .1 actual retained public changed-copy read passed; seven explicit read-only negative/fault controls passed. No original effect or private baseline was used. MATCH has not received actual new producer acceptance; no authenticated destination was rewritten. Platform consumer integration remains OPEN pending independent review.
