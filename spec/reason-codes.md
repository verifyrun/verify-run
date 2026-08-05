# Reason codes — the closed set for spec_version 1
`outcome.reasons[].code` is drawn from these tables and nothing else. Adding a code requires a new
spec_version and fixtures. A code never crosses outcome classes.

`message` must be byte-stable, because replay compares it: it is either the matched rule's
`reason` copied verbatim, or the fixed text listed here. Variable data never enters `message` —
it goes in `rule_id` and `evidence_id`.

## ERROR — evaluation never validly began
| Code | Raised when |
|---|---|
| `source_encoding_invalid` | source bytes are not UTF-8, or carry a byte-order mark (spec/document-loading.md) |
| `source_syntax_invalid` | source is not well-formed in its format: syntax error, trailing content, more than one document, empty source, or a non-standard literal such as `NaN` or `Infinity` |
| `source_too_deep` | source nests deeper than the loader's declared maximum depth |
| `source_construct_unsupported` | source uses a construct outside the frozen subset of its format: an ambiguous plain scalar, an anchor, alias, merge key, explicit tag, or a container type the subset excludes |
| `candidate_schema_invalid` | the candidate fails spec/candidate.schema.json |
| `rulebook_schema_invalid` | the rulebook fails spec/rulebook.schema.json |
| `snapshot_schema_invalid` | the snapshot fails spec/evidence.schema.json |
| `outcome_schema_invalid` | the outcome fails spec/outcome.schema.json |
| `authorization_schema_invalid` | the authorization fails spec/authorization.schema.json |
| `receipt_schema_invalid` | the receipt fails spec/receipt.schema.json |
| `rulebook_semantic_invalid` | a schema-valid rulebook violates a load-time invariant: a duplicate rule or evidence identifier, or an evidence identifier that does not lex as one (spec/rulebook-loading.md) |
| `rulebook_version_collision` | two rulebooks share `(rulebook_id, version)` but differ in digest, so one version has been made to mean two things |
| `authorization_outcome_ineligible` | an authorization was requested for an outcome other than ALLOW (spec/authorization.md) |
| `authorization_binding_mismatch` | an authorization's bound rulebook, action, snapshot, result, or runtime is not the one supplied |
| `authorization_not_yet_valid` | the verification instant is before `issued_at`, or `issued_at` precedes the snapshot freeze |
| `authorization_expired` | the verification instant is at or after `expires_at`; expiry is exclusive |
| `authorization_nonce_reused` | the authorization's nonce has already been consumed |
| `signature_malformed` | a signature value is not decodable in its declared encoding |
| `signature_invalid` | a signature does not verify over the artifact's canonical payload |
| `signing_key_unknown` | no key in the registry matches the signature's `key_id` and `key_version` |
| `signing_key_retired` | the signing key is retired and authorizes nothing |
| `signing_key_invalid` | key material is not a well-formed Ed25519 key |
| `receipt_outcome_ineligible` | a receipt was requested for ERROR, which is not a decision (spec/receipt-and-replay.md) |
| `receipt_binding_mismatch` | a receipt's bound rulebook, candidate, snapshot, result, authorization, or execution record is not the one supplied, or its shape contradicts its terminal class |
| `replay_body_missing` | replay was asked for without a body it needs; the receipt may still verify cryptographically |
| `replay_body_mismatch` | a body supplied for replay does not match the digest the receipt records for it |
| `replay_result_mismatch` | the recomputed decision differs from the one the receipt records |
| `store_path_invalid` | a store root or artifact identifier is unusable as a path: bad grammar, traversal, or a symlink in the trusted layout (spec/local-store.md) |
| `store_record_missing` | no committed record exists for that receipt id |
| `store_record_incomplete` | a record is present but missing a file its terminal class requires |
| `store_record_conflict` | a record with that receipt id exists with different bytes; one id can never mean two contents |
| `store_artifact_noncanonical` | a stored file parses but its bytes are not the canonical form of what it parses to |
| `store_index_invalid` | the index is malformed; records govern and it must be rebuilt |
| `store_commit_conflict` | a staging path or commit target already exists, so the write is refused rather than overwriting |
| `store_consumption_conflict` | a consumption record exists for that nonce under different bindings |
| `execution_candidate_unsupported` | the candidate is not an executable command: not `kind: command`, absent or empty `argv`, a non-string argv member, or an `argv[0]` that is a bare name rather than a path (spec/execution.md) |
| `execution_configuration_invalid` | the process configuration is unusable: a working directory that is missing, not a directory, or a symlink; a non-string environment entry; or a timeout outside the declared bounds |
| `execution_recording_failed` | the execution attempt finished and the receipt could not be issued or the record could not be committed. The authorization is already consumed and is never re-executed |
| `evidence_adapter_config_invalid` | an evidence declaration or adapter runtime bound is malformed: wrong source, missing ref, invalid timeout, or a malformed acquisition instant (spec/evidence-adapters.md) |
| `evidence_path_invalid` | an evidence path escapes its declared root, is a symlink, or is not a regular file |
| `cli_workspace_invalid` | there is no workspace at the given path, it is not initialized, or it is a symlink or not a directory (spec/cli.md) |
| `cli_workspace_conflict` | initialization would overwrite a workspace file whose bytes differ |
| `cli_config_invalid` | `.vfy/config.json` or the trust file is malformed, carries an unknown field, fails a declared bound, or names an unusable path or key |
| `cli_executable_not_found` | `argv[0]` resolves to no executable along the configured search path |
| `cli_path_outside_workspace` | a receipt path is not inside this workspace's store |
| `schema_registry_invalid` | a schema document is itself invalid: an unsupported keyword, an unanchored or unsupported pattern, an unknown or remote reference, or a missing or duplicate $id (spec/schema-validation.md) |
| `canonical_form_invalid` | duplicate key, non-string key, integer out of range, or malformed decimal string |
| `float_not_permitted` | a float appears in a rulebook, candidate, or evidence value |
| `surrogate_not_permitted` | a string carries a code point in U+D800–U+DFFF and so has no UTF-8 representation |
| `expression_parse_error` | a `when` expression does not parse |
| `expression_type_error` | a STATIC type mismatch, provable from the expression text alone (spec/rulebook-language.md) |
| `undeclared_evidence_id` | an expression or `requires_evidence` names an id the rulebook does not declare |
| `snapshot_item_missing` | a declaration with `required: true` has no snapshot item |
| `snapshot_item_invalid` | a snapshot item's status and value combination is incoherent: `ok` without a value, or `missing` with one (spec/snapshot-construction.md) |
| `snapshot_digest_mismatch` | a snapshot's embedded `snapshot_digest` does not match the digest recomputed over its own payload |
| `snapshot_item_undeclared` | the snapshot carries an item for an id the rulebook does not declare |
| `evidence_order_invalid` | an item's `acquired_at` is after `frozen_at`, or `order` is not 0..n-1 |
| `snapshot_rulebook_mismatch` | the snapshot's `rulebook_digest` is not the pinned rulebook's digest |
| `rulebook_not_adopted` | the snapshot's `frozen_at` is before the rulebook's `adopted_at` |

## HOLD — the rulebook could not settle it
| Code | Raised when | `message` |
|---|---|---|
| `evidence_unsettled` | a rule references evidence whose item is absent or not `ok` | "Evidence could not settle this rule." |
| `operand_unsettled` | an operand cannot support its operator: `absent`, or a data-dependent type mismatch | "An operand could not settle this rule." |
| `rule_hold` | a rule whose outcome is HOLD is `true` | the rule's `reason` |
| `default_outcome_hold` | no rule is non-`false` and `default_outcome` is HOLD | "No rule matched." |

## BLOCK — the rulebook reached a negative result
| Code | Raised when | `message` |
|---|---|---|
| `rule_block` | a rule whose outcome is BLOCK is `true` | the rule's `reason` |
| `default_outcome_block` | no rule is non-`false` and `default_outcome` is BLOCK | "No rule matched." |

## ALLOW
| Code | Raised when | `message` |
|---|---|---|
| `rule_allow` | a rule whose outcome is ALLOW is `true` | the rule's `reason` |

## Trace
`outcome.trace` carries one entry per rule evaluated, in `rules` order, ending at the rule where
the walk stopped:

    "<ordinal>:<rule_id>:<true|false|unsettled>"

`ordinal` is the rule's 0-based index in `rules`. No timestamps, no values, no host data: the
trace is a function of the recorded inputs alone, which is what makes byte-identical replay
checkable at all.
