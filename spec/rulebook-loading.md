# Rulebook loading — source bytes to a pinned rulebook
    rulebook_loader_version: 1

Turns YAML source into one immutable, validated, content-addressed rulebook whose identity is its
semantic content and whose applicability to a recorded instant is decidable without a clock.

This layer pins. It decides nothing. It does not parse `when`, resolve evidence, or reach an
outcome, and it never reads a file, a clock, an environment variable, or a network.

## Load order
Exactly this, and no step may run on the output of a failed one:

1. strict YAML loading (`spec/document-loading.md`);
2. canonical-value acceptance, which that loader already performs;
3. rulebook schema validation (`spec/schema-validation.md`);
4. the load-time semantic checks below;
5. canonical serialization of the complete validated value;
6. SHA-256 over those bytes;
7. the immutable pinned representation.

**A failed load produces no digest.** Nothing is hashed until it is known to be valid, which is
the same rule canonicalization already states.

## Digest domain
The rulebook digest is taken over the canonical JSON bytes of the complete validated rulebook
value, exactly as `spec/canonicalization.md` already declares: "the validated rulebook document,
after YAML parsing and schema validation, before evaluation. Never the YAML bytes."

Semantic value determines identity; source presentation does not. Therefore the digest is
unchanged by comments, insignificant whitespace, mapping key order in the source, and quote style
where the parsed strings agree. It **is** changed by any change to a parsed value — including a
block scalar whose chomping changes the resulting string, because that is a different string, not
a different presentation.

Schema defaults are **not** inserted before hashing. What was written is what is hashed.

The digest is carried as `sha256:` followed by 64 lowercase hex digits, the same form every
artifact field uses. Fixture fields named `sha256` continue to hold bare hex, as
`fixtures/README.md` already specifies.

## Identity
Identity is the pair `(rulebook_id, version)`. The digest identifies exact semantic content.

Two rulebooks sharing an identity but differing in digest are a **version collision**: the same
version has been made to mean two different things. Wherever a pair is compared or registered,
that is refused with ERROR `rulebook_version_collision`. This layer exposes the comparison
primitive; it does not implement a registry, and it never selects among rulebooks.

Source formatting can never create a new identity, because it never changes the digest.

## Version
The schema's grammar, unchanged: `^[0-9]+\.[0-9]+\.[0-9]+$`. Versions are compared for equality
only. No ranges, no prerelease precedence, no build metadata, no migration, and no automatic
latest-version selection — the schema supports none of them and nothing in v1 requires them.

## Adoption and applicability
`adopted_at` governs runs starting at or after that instant, and `spec/execution-chain.md` fixes
the run's start instant as the evidence snapshot's `frozen_at`. So applicability is:

    applies  ⇔  evaluation_instant >= adopted_at

The evaluation instant is **supplied by the caller** as a recorded date-time string — in the
execution chain, the snapshot's `frozen_at`, already validated by the evidence schema. It is never
read from a clock. This layer offers the comparison; `spec/execution-chain.md` step 3 remains the
one place adoption is enforced, and a violation there is ERROR `rulebook_not_adopted`.

Comparison parses both strings into an exact integer instant — days from the civil calendar,
seconds, and nanoseconds scaled from the fractional part, minus the offset. Integer arithmetic
only: no locale, no timezone database, no wall clock, no floating-point timestamp, and no
ambiguous local time, because the frozen grammar admits only `Z` or an explicit `±HH:MM`.

**Nothing is normalized in the hashed value.** `2026-08-05T00:00:00Z` and
`2026-08-05T01:00:00+01:00` denote the same instant and are two different strings: they are
distinct rulebook content with distinct digests, and they compare equal for applicability. Content
identity and instant equality are different questions and are answered separately.

Stored date-times stay strings. Nothing is converted to a native date or datetime anywhere in the
loaded value.

## Load-time semantic checks
Only what must hold before a rulebook can be pinned. Each is a property of the rulebook alone,
decidable without evidence, a candidate, or an expression parser.

- **Rule identifiers are unique.** A receipt names `matched_rule` by identifier; duplicates make
  that name ambiguous. → ERROR `rulebook_semantic_invalid`.
- **Evidence identifiers are unique.** `evidence.<id>` must resolve to one declaration, and
  `spec/execution-chain.md` requires exactly one snapshot item per declared id. → ERROR
  `rulebook_semantic_invalid`.
- **Evidence identifiers lex as identifiers**, `[A-Za-z_][A-Za-z0-9_]*`. The schema states this in
  the field's description but expresses no pattern, and `spec/rulebook-language.md` requires it so
  that expressions can name them. → ERROR `rulebook_semantic_invalid`.
- **`requires_evidence` names declared evidence.** `spec/execution-chain.md`: "Every listed id
  must be declared." It is a declared list, not an expression, so it is checkable here. → ERROR
  `undeclared_evidence_id`.

Already closed elsewhere and not repeated: a non-empty rule list, outcome and `default_outcome`
vocabularies, identifier, version, and date-time grammars — all schema obligations. Rule order is
preserved because canonicalization never reorders an array.

**`when` is not parsed here.** A rulebook is not refused because an expression might later fail to
parse; that belongs to the expression closure. This layer treats `when` as an opaque string.

## Defaults
`spec/rulebook.schema.json` declares two: `evidence.items.required` is `true` and
`authorization.ttl_seconds` is `300`. Schema validation does not insert them, and neither does
this layer — inserting either would change the canonical bytes and therefore the identity of a
rulebook its author never wrote.

They are **semantic defaults applied by the consumer**, at the point of use, from the values
declared in the schema: snapshot construction reads an absent `required` as `true`
(`spec/execution-chain.md` §3), and authorization issuance reads an absent `ttl_seconds` as `300`.
A pinned rulebook reports what it contains, nothing more.

## Immutability
The pinned representation is a frozen record of strings only. It does not hold a mutable mapping.

That is forced rather than chosen: the frozen value model admits `dict` and `list` and nothing
else, so a recursively "frozen" structure built from tuples or mapping proxies would be refused by
canonicalization itself. Instead the canonical bytes are the authority, and the value is
reconstructed on request by loading those bytes through the strict JSON loader. Every reader gets
its own copy, mutating it changes nothing, and the reconstruction is guaranteed to be inside the
value model because the loader says so.

## Public boundary
    load_rulebook_bytes(data: bytes, registry) -> LoadedRulebook
    rulebook_applies(loaded: LoadedRulebook, evaluation_instant: str) -> bool
    check_no_version_collision(first: LoadedRulebook, second: LoadedRulebook) -> None

`LoadedRulebook` exposes `canonical`, `canonical_bytes`, `digest`, `rulebook_id`, `version`,
`adopted_at`, and `value()`.

Bytes in, as everywhere else: reading a file is an adapter's job in a later closure. The registry
is supplied by the caller and is never mutated.

`rulebook_applies` requires an evaluation instant that is a string in the frozen date-time
grammar, which snapshot schema validation already guarantees. Anything else is a caller-contract
violation and raises `TypeError` — the same posture `load_json_bytes` takes toward a `str`. It is
not an input class and carries no reason code.

## Failure typing
Each stage keeps its own code, because each is a different repair.

| Stage | Code |
|---|---|
| YAML source | `source_encoding_invalid`, `source_syntax_invalid`, `source_construct_unsupported`, `source_too_deep`, `canonical_form_invalid`, `float_not_permitted` |
| schema | `rulebook_schema_invalid`, with instance path, schema path, and keyword |
| load-time semantics | `rulebook_semantic_invalid`, `undeclared_evidence_id` |
| identity comparison | `rulebook_version_collision` |
