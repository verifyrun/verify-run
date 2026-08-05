# Canonical form and digests
One byte string per value; one digest domain per digest field. Every implementation — the Python
reference first, any shim later — must produce the same bytes from the same input.

## Canonical JSON
- UTF-8, no byte-order mark. No insignificant whitespace anywhere: `{"a":1,"b":[1,2]}`.
- Object members are sorted ascending by the key's sequence of Unicode scalar values, compared
  position by position. That order is byte-for-byte identical to sorting the keys by their UTF-8
  encodings, and comparing UTF-8 bytes is the rule a shim should implement.
  **UTF-16 code-unit order is not equivalent and must never be used.** The two agree across the
  Basic Multilingual Plane and disagree above it: by scalar value a supplementary-plane key sorts
  after every U+E000–U+FFFF key, and by UTF-16 code unit it sorts before them. JavaScript's
  default array sort and its `<` operator on strings are UTF-16 comparisons and are wrong here.
  `fixtures/canonicalization/canon_case_4.json` pins the difference.
- Keys are always strings. Duplicate keys are invalid → ERROR `canonical_form_invalid`, but
  canonicalization cannot detect them: it receives an already-constructed value, and a permissive
  parser has by then collapsed `{"a":1,"a":2}` into one member. Enforcement belongs to the strict
  JSON and YAML loaders, which see the source text. No canonicalizer may claim this check.
- No normalization, ever. Canonicalization does not apply NFC, NFD, NFKC, NFKD, case folding, or
  whitespace trimming to any key or value. Precomposed U+00E9 and decomposed `e` + U+0301 look
  alike, and they are two different values with two different digests; as keys they are two
  distinct members. What was recorded is what is hashed.
- Canonicalization imposes no limit on nesting depth, document size, string length, or member
  count. Every accepted value has a canonical form. Resource control is an outer runtime concern:
  a loader may bound what it is willing to parse and must declare that bound where it lives. An
  implementation's own stack or memory limit is never product semantics — a host recursion limit
  must not decide whether a document is acceptable, because that limit is host-configurable and
  would make the same bytes acceptable on one machine and rejected on another.
- Arrays keep their order exactly. An array is ordered data and is never sorted.
- `true`, `false`, and `null` are emitted literally.
- Strings escape exactly two characters and one range: `"` → `\"`, `\` → `\\`, and the C0
  controls U+0000–U+001F, written `\b \t \n \f \r` where those names exist and `\u00xx`
  otherwise. Hex digits are always lowercase and always four.
  Nothing else is ever escaped. These stay literal, and a shim that escapes any of them produces
  different bytes and a different digest: `/` (solidus), U+007F (DEL), U+2028 (line separator),
  U+2029 (paragraph separator), and every other valid non-ASCII scalar, emitted as UTF-8. U+2028
  and U+2029 are literal here even though some JavaScript string contexts require them escaped;
  that governs how a shim embeds the text, never the canonical bytes themselves.
- Numbers are integers only: no leading `+`, no leading zeros, no decimal point, no exponent;
  `-0` is written `0`. An integer must lie in −(2^53−1) … 2^53−1 so that every implementation
  holds it exactly; outside that range → ERROR `canonical_form_invalid`.
- **A float is never valid input.** A float anywhere in a rulebook, candidate, or evidence value
  → ERROR `float_not_permitted`. Non-integer numbers are carried as canonical decimal strings.
- Only JSON's own types are canonicalizable. A loader that hands back a native date, set, or byte
  string — an unquoted timestamp in YAML, for instance — is invalid input → ERROR
  `canonical_form_invalid`. Timestamps are quoted strings everywhere in this spec suite.
- **A string may not carry a code point in the surrogate range U+D800–U+DFFF**, in a key or in a
  value. Such a string has no UTF-8 representation, so it is not a canonical input → ERROR
  `surrogate_not_permitted`. Rejection happens here, before anything is hashed, signed,
  evaluated, authorized, or written into a receipt: nothing is hashed before it is known to be
  valid. No implementation may replace, normalize, drop, or escape a surrogate into an accepted
  value — there is no `\ud800` escape in canonical output, and lossy or permissive encoder
  settings are forbidden. A properly paired surrogate escape in JSON source — the two escapes
  U+D834 then U+DD1E written in a JSON string — denotes the scalar U+1D11E. Pairing is the
  parser's business; what reaches canonicalization is the scalar, and the scalar is valid.

## Canonical decimal string
    -?(0|[1-9][0-9]*)(\.[0-9]+)?

Optional leading `-`; no leading zeros except `0` itself; no exponent; no trailing `.`; at least
one digit after a `.`. `"12.50"` is valid, keeps its trailing zero in the bytes, and compares
under ordering operators as the exact decimal 12.50. A string that does not match this form is an
ordinary string, not a number.

Canonicalization neither validates nor coerces this form. To the canonicalizer a decimal string
is an ordinary string, emitted byte for byte whether or not it matches: `"01"`, `"+1"`, `"1e3"`,
and `"NaN"` are all just strings here. The form is enforced where numbers are actually compared —
the ordering operators in spec/rulebook-language.md — and the malformed-decimal-string clause of
`canonical_form_invalid` is raised there, not at this boundary.

## Digest
    digest(payload) = "sha256:" + lowercase_hex( sha256( canonical_bytes(payload) ) )

The `sha256:` prefix is part of the field value, matching `^sha256:[a-f0-9]{64}$`.

## Digest domains — one per field, no exceptions
| Field | Canonical payload |
|---|---|
| `rulebook_digest` | the validated rulebook document, after YAML parsing and schema validation, before evaluation. Never the YAML bytes — formatting must not change the identity of the rules. |
| `candidate_digest` | the validated candidate document. |
| `action_digest` | **the same value as `candidate_digest`.** The candidate carries the action, so a different command is a different candidate is a different digest. |
| `snapshot_digest` | the evidence snapshot object with its own `snapshot_digest` member omitted. |
| `evidence_digest` | **the same value as the governing snapshot's `snapshot_digest`.** |
| `value_digest` | that evidence item's `value` member. No `value` ⇒ no `value_digest`. |

## Signature payload
Ed25519 over the canonical bytes of the artifact with its own `signature` member omitted — the
receipt for a receipt signature, the authorization for an authorization signature.
`signature.value` is base64 with padding (RFC 4648 §4). Verification recomputes those bytes from
the artifact and never trusts a recorded copy of them.
