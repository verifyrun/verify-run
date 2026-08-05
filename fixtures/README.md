# Fixtures — how each kind is read
Golden vectors. Implementations match them byte-exactly. They are never edited to suit an
implementation.

## canonicalization/
Two shapes.

A `canon_case_*` file is a value that has a canonical form. `input` is the value to canonicalize,
`canonical` is the exact expected string, and `sha256` is the lowercase hex of sha256 over
`canonical` encoded as UTF-8 — bare hex here, because the field name already names the algorithm.
Digest fields inside artifacts carry the `sha256:` prefix instead (spec/canonicalization.md).

A `canon_reject_*` file is a value that has no canonical form. `input` is the value, and
`expected` states the outcome class and the reason code the rejection must carry
(spec/reason-codes.md). A rejected value has no `canonical` and no `sha256`: nothing is hashed
before it is known to be valid.

## loading/
Source-boundary vectors for spec/document-loading.md. `source_base64` is authoritative and holds
the exact source bytes, base64-encoded — the only representation that survives a byte-order mark,
malformed UTF-8, and trailing content intact. `format` names the source format.

A `load_*_accept_*` file records what the bytes mean: `value` is the expected loaded value,
`canonical` its canonical text, and `sha256` the lowercase hex digest of those canonical bytes.

A `load_*_reject_*` file records `expected` — the outcome class and the reason code the rejection
must carry. A rejected source has no `value`, no `canonical`, and no `sha256`.

## schema/
Instance vectors for spec/schema-validation.md, against the six schemas in `spec/`. `schema` names
the target by `$id`, and `value` is the already-loaded instance — source encoding and syntax are
the loader's business, settled before validation starts.

A `valid_*` file asserts the instance validates, and carries its `canonical` text and `sha256` so
that a schema-valid document also has a pinned canonical form.

An `invalid_*` file records the exact failure: `reason_code`, `instance_path`, `schema_path`, and
`keyword`. It carries **no** `canonical` and no `sha256` — a document can be syntactically fine,
canonically representable, and still schema-invalid, and the three are kept separate.

A `registry_invalid_*` file holds `documents`, a list of schema documents that must be refused at
registry load with `schema_registry_invalid`, proving an unsupported construct is never silently
ignored.

## rulebooks/
End-to-end vectors for spec/rulebook-loading.md: YAML source bytes to a pinned rulebook.

An `accept_*` file carries the authoritative `source_base64`, the expected loaded `value`, its
`canonical` text, the bare `sha256`, the prefixed `digest`, the identity fields `rulebook_id` and
`version`, the `adopted_at` instant, and `applies` — a list of `[instant, expected]` pairs stating
applicability against declared evaluation instants. Several accepted vectors are deliberately
different source bytes with the same digest: presentation does not change identity.

A `reject_*` file carries `source_base64`, the `stage` at which the load must fail — `source`,
`schema`, or `semantic` — and the expected reason code. It carries **no** digest and no canonical
form, because a failed load hashes nothing.

A `collision_*` file carries two sources under `first_base64` and `second_base64`. Both load
successfully on their own; the comparison of the pair must be refused.

## expressions/
Vectors for spec/expression-language.md: one `when` string to one canonical abstract syntax tree.
Nothing here is evaluated.

An `accept_*` file carries the `source`, the `declared_evidence` a rulebook would have to declare,
the expected `ast`, its `canonical` text and `sha256`, and `evidence_ids` — the ids the expression
names statically, in source order and without repetition.

An `equivalent_*` file carries several `sources` that differ only in formatting and one
`canonical` text they must all produce.

A `reject_syntax_*` file expects `expression_parse_error`, a `reject_type_*` file expects
`expression_type_error` — the static mismatches the text alone proves, including wrong arity —
and a `reject_static_*` file carries `declared_evidence` and the `undeclared_id` that validation
against a pinned rulebook must name. None carries a digest.

## snapshots/
Vectors for spec/snapshot-construction.md: declared acquisitions to a frozen snapshot. Nothing
here acquires anything.

An `accept_*` file carries an inline `rulebook` value, the `snapshot_id`, `frozen_at`, the
`acquisitions` a caller supplies, the expected `payload` — the snapshot **without**
`snapshot_digest`, since that is the digest domain — and the expected item `order`. The
`rulebook_digest` in the payload reads `PINNED`, which the harness replaces with the pinned
rulebook's real digest.

A `reject_*` file expects construction to fail, and a `verify_reject_*` file carries a whole
`snapshot` value that `verify_snapshot_value` must refuse. Both record the `stage` and the reason
code, and neither carries a digest.

A `bridge_*` file builds a snapshot for one evidence status and runs the closed evaluator against
`present`, `fresh`, a direct value reference, or `requires_evidence`, proving the builder changes
no evaluation semantics.

## store/
Frozen on-disk trees for spec/local-store.md, one per terminal decision.

An `accept_tree_*` file records the committed layout as a map from store-relative path to either
`dir` or the SHA-256 of that file's **exact bytes**, plus the resulting `index` document. The
layout follows `spec/execution-chain.md` §9: a receipt at `receipts/<receipt_id>.json` with its
bodies in `receipts/<receipt_id>.inputs/`. A BLOCK or HOLD tree carries no `authorization.json`,
because a negative decision authorizes nothing.

`accept_consumption_record.json` freezes one spent authorization: the filename is the SHA-256 of
the nonce, so a caller-supplied nonce never reaches the filesystem as a path, and the record binds
the authorization id and all three digests with **no timestamp** — no clock is read.

## receipts/
Vectors for spec/receipt-and-replay.md: recording a decision, verifying the record, and
recomputing the decision from the recorded inputs.

**The keys here are TEST-ONLY published constants**, distinct from the authorization keys so that
the two registries are visibly separate. They authorize nothing.

An `accept_*` file carries everything replay needs: the exact `rulebook_source`, the `candidate`,
the `acquisitions` and resulting `snapshot`, the `authorization` when the outcome is ALLOW, the
`unsigned_payload` with its `unsigned_canonical` text, the `signature`, the complete `receipt` and
its canonical text, both key halves in hex, and the expected outcome. Every terminal decision
class is represented — ALLOW, BLOCK, HOLD. ERROR has no receipt, by `spec/execution-chain.md`.

A `reject_*` file names a `base`, one `mutation`, and the `stage` it must fail at —
`verification` for anything a receipt alone can catch, `replay` for anything needing the bodies.
Mutations cover altered fields, altered nested results, substituted and copied signatures, key-id
and key-version substitution, unknown and revoked keys, untrusted signers, and missing or
mismatched replay bodies. A `reject_issue_*` file mutates issuance instead.

## authorization/
Vectors for spec/authorization.md: one permitted action, bound and signed.

**The keys in this directory are TEST-ONLY published constants.** The private seeds are fixed
byte ranges committed to this repository in the clear. They authorize nothing, they are not
secrets, and they must never be used outside these fixtures.

An `accept_*` file carries the inline `rulebook`, `candidate`, `acquisitions`, and `frozen_at`
that produce the bound objects, plus `authorization_id`, `nonce`, `runtime_id`, `issued_at`, the
key identity and both key halves in hex, the `unsigned_payload` and its `unsigned_canonical` text,
the `signature`, the complete `authorization` and its canonical text, the `verification_time`, and
the `expected_expires_at`. Ed25519 is deterministic, so those signature bytes are reproducible.

A `reject_*` file names a `base` fixture and one `mutation` to apply — a changed payload field, a
substituted signature, an absent or retired key, a shifted verification time, a consumed nonce, or
a deliberately mismatched supplied object — together with the reason code that mutation must
produce. A `reject_issue_*` file mutates issuance instead of verification. None carries a
signature that verifies.

## evaluation/
Each case names a rulebook by repo-root-relative path, supplies a candidate, and may supply
`evidence_overrides`. The harness builds the snapshot deterministically:

- `frozen_at` is the fixed constant `2026-08-05T00:00:00Z`.
- one item per `evidence_overrides` key, taken in ascending key order, with `order` counting from
  0, `acquired_at` = `frozen_at` minus `age_seconds`, and `status` and `value` copied from the
  override.
- a declared id with `required: true` and no override becomes an item with status `missing` and
  `acquired_at` = `frozen_at`, ordered after the overrides. A `required: false` id with no
  override is omitted, as spec/execution-chain.md permits.
- `rulebook_digest` and `snapshot_digest` are computed per spec/canonicalization.md.

`expected.outcome` must equal the result's outcome. `expected.matched_rule`, when present, must
equal `result.matched_rule`. `expected.reason_code`, when present, must appear among
`result.reasons[].code`. Anything a fixture does not state is not constrained by that fixture.

A `probe_*` file isolates **one expression**. It carries `when`, the evidence `declare`ations and
snapshot `items` that expression needs, a `candidate`, and `expected` — `true`, `false`, or
`unsettled`. The harness wraps the expression in a rulebook with a single ALLOW rule and
`default_outcome: BLOCK`, so the terminal outcome reports the expression's own value: ALLOW means
true, BLOCK means false, HOLD means unsettled. That keeps every algebra, path, evidence,
freshness, numeric, membership, and pattern vector readable as one line of source.

A `walk_*` file exercises the **rule walk**. It carries an inline `rulebook` value, `items`, a
`candidate`, and the exact expected `outcome`, `matched_rule`, ordered reason `codes`, and
`trace`.

For both, `items` may give `age_seconds` instead of `acquired_at`; the harness subtracts it from
the fixed `frozen_at` of `2026-08-05T00:00:00Z`.

## adapters/
Vectors for spec/evidence-adapters.md: one bounded local observation becoming one acquisition
result. These are the only fixtures that describe a filesystem rather than a value.

Every file carries a `tree` — a map from root-relative path to one entry, materialized under a
fresh temporary root and torn down afterwards. An entry is `{"kind": "dir"}`,
`{"kind": "file", "bytes_base64": ..., "mode": "0644"}` with the exact bytes and permission bits,
`{"kind": "symlink", "target": ...}`, or `{"kind": "fifo"}`. Directories are created first and
links last, so a link to something inside the tree resolves and a deliberately dangling one stays
dangling. The `mode` matters: an executable bit is the difference between a command that runs and
one that cannot.

**The adapter under test is the filename prefix, not the declaration's `source`.** That is
deliberate: the wrong-source cases exist to prove each adapter refuses a declaration it does not
own, so reading the adapter off the declaration would make them untestable.

A `file_*` or `command_*` file carries the `declaration`, the caller-supplied `acquired_at`, and
`expected`. Two expectation classes, kept apart because they have different repairs:

- `{"class": "acquisition", "acquisition": {...}}` — the call succeeded and reports what it found.
  The `acquisition` is the exact mapping `build_snapshot` accepts: `id`, `status`, `acquired_at`,
  and `value` only when the status is `ok`. An accepted case also carries the `canonical` text and
  bare `sha256` of the observed value. There is no `order`, no `source`, and no diagnostic text,
  because nothing an adapter learns about a failure enters the signed snapshot.
- `{"class": "adapter_error", "reason_code": ...}` — the call was malformed or unsafe and returned
  nothing at all.

A `command_*` file may also carry `timeout_seconds`, an explicit `environment`, a
root-relative `working_directory`, and `parent_environment` — variables the harness exports in the
*parent* so a fixture can prove they never reach the child.

Sizes at the bounds are written as generated padding rather than committed megabytes: the exact
byte counts are what the fixture asserts, and both the accepted bound and the bound plus one are
present for files and for stdout.

A `bridge_*` file runs the whole local chain — tree, then every declaration of a real template
acquired in declared order, then `build_snapshot`, then the closed evaluator. It carries
`rulebook_ref`, `tree`, `snapshot_id`, `frozen_at`, `acquired_at`, a `candidate`, and `expected`
with the per-id `statuses` and the terminal `outcome`. Declarations whose source has no v1 adapter
are not acquired at all, and the builder synthesizes them as `missing`; `claims-gate`'s `http`
item is the case that matters, and its fixture states in full what the rulebook can and cannot
reach without it.

## execution/
Vectors for spec/execution.md: spending one authorization on one exact command. These are the
only fixtures that both describe a filesystem and cause something to happen.

**The keys here are TEST-ONLY published constants**, the same ones `fixtures/authorization/` and
`fixtures/receipts/` already publish in the clear. They authorize nothing.

Every `accept_*` and `reject_*` file carries the whole run: `rulebook_ref`, a `candidate`, the
`acquisitions` and `frozen_at` that freeze the snapshot, the `authorization` identity to issue, the
two key sets, `runtime_id`, `verification_time`, `acknowledged_at`, the receipt identity, a `tree`
in the same entry shapes `adapters/` uses, and the explicit `cwd`, `environment`, and
`timeout_seconds`. The harness pins, freezes, evaluates, and issues the authorization itself, so
nothing under test is also what proves the test. `parent_environment` names variables exported in
the *parent*, so a fixture can prove they never reach the child. An `argv[0]` written
`ABSOLUTE:<path>` is rewritten to the sandbox's absolute path before the candidate is digested —
the one way to test an absolute program path without freezing a machine-specific digest.

Four fields deliberately break the run *after* the authorization is signed, which is the only way
to test a binding: `mutate_candidate_after_issue`, `mutate_snapshot_after_issue`,
`registry_key_id` / `registry_key_status`, and `preconsume`.

An `accept_*` file expects `class: executed` and records `consumed`, `started`, `exit_status`,
`timed_out`, the exact `acknowledgment` the receipt must carry, and optionally the exact
`stdout_base64` and `stderr_base64`. Output appears in the expectation but never in the
acknowledgment: stdout and stderr are operational, and a signed artifact is the last place
credentials should land.

A `reject_*` file expects `class: refused` with a `reason_code`, and the harness additionally
proves the negative: the nonce is no more consumed than it already was, no launch marker exists,
and no record was stored.

A `seam_*` file is not a run at all — it is the frozen state table for one crash or failure
boundary, recording whether the authorization was consumed, whether a process started, and
whether an acknowledgment, a receipt, and a stored record exist, plus whether automatic retry is
permitted (it never is) and what recovery is actually available. Several say plainly that the
answer is none.

`concurrency_eight_callers.json` states what eight processes racing for one authorization must
produce: one consumption, one launch, one receipt, and seven refusals before any launch.

## cli/
Vectors for spec/cli.md: the five public commands and the workflow they compose. Every case runs
through the real `vfy.cli.main` with an injected fixed clock and fixed identifiers, so the
artifacts a run produces are byte-identical between rounds.

A `parse_*` file carries an `argv` and the exit code the parser must return. Several exist only
to prove a command is **not** there: `watch`, `serve`, and `rules` each appear once in the
architecture's illustrative file tree, and the v1 surface is "nothing more".

An `init_*` file carries the template and the exact workspace that must result — every path, the
key file mode, the configuration field by field, and that `rulebook.yaml` matches the template
byte for byte. `init_no_test_key_leakage` names the published fixture seeds and requires that
neither ever appears in a generated workspace.

A `check_*` file carries a workspace `tree`, a `candidate`, and the outcome, exit code, and the
three counts that make a preview a preview: zero receipts, zero consumptions, nothing launched.

A `run_*` file carries the `tree`, the `argv` after `--`, repeatable `identity` pairs for the
rulebook's track fields, and optionally a `parent_environment` the harness exports in the parent
or a `config_environment` the workspace declares — so a fixture can prove which of the two reaches
a gated command. Its expectation records the outcome, exit code, whether a process started, its
exit status, how many receipts and consumption records exist, and whether the stored record
replays.

A `replay_accept_*` file proves a decision recomputes and that nothing is launched while it does.
A `replay_reject_*` file names one `mutation` — deleted bodies, a corrupted body, an unknown or
retired key, a path outside the store — and the reason code it must produce. The retired-key case
expects success, because `spec/receipt-and-replay.md` deliberately lets a retired receipt key
still verify what it already signed.

A `receipts_*` file runs a sequence of decisions and then checks the listing, including with a
truncated index and with an index entry naming no record: the listing derives from the committed
records, which govern.

`exit_codes.json` freezes the whole table. The four outcomes stay distinguishable, and the child
process's status, the decision, and the CLI's own health never share a code.

## tamper/
ATTACK_CLASSES.md is the checklist for weeks 2–3. Each class becomes a pair — an artifact, and the
reason code it must be rejected with, drawn from the closed set in spec/reason-codes.md.
