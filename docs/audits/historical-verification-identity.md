# Historical identity projection

The existing historical adoption verifier now returns five additional fields from its already authenticated and recomputed chain: `task_id`, `historical_runtime_id`, `historical_rulebook_value_sha256`, `historical_snapshot_value_sha256`, and `historical_gate_result_value_sha256`. Value digests use the existing canonical JSON digest, not raw nested serialization bytes. `intent_bytes_sha256` continues to bind the original whole intent bytes.

These identify the historical producer task and evaluation basis. They do not identify the current verifier software revision, establish compatibility with a replacement checker, map the producer task to Platform tenant authority, or license current source reliance/retry. A recipient can compare the identities without Platform access using the retained four inputs and independently appointed trust. All previous false-authority flags and UNKNOWN physical accounting remain unchanged. The server still owns any Platform task/revision/basis association.

No new request fields, trust rules, or producer effects. Responses are additive; strict downstream clients must deliberately accept the successor before updating their installed pins. Existing pinned consumers remain unchanged.
