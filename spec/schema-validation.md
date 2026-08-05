# Schema validation — the bounded subset
    validator_version: 1

What "valid document" means, for exactly the six schemas in `spec/` and nothing else. This is not
a JSON Schema engine. It implements the keywords those schemas use, rejects every keyword they do
not, and resolves only references to schemas already in the registry.

Validation runs on a value the strict loader has already accepted (`spec/document-loading.md`), so
encoding, syntax, duplicate keys, parser typing, and the value model are settled before it starts.
It reads no files, opens no sockets, and never fetches a reference.

## Non-mutating
Validation answers a question. It returns nothing on success and raises a typed failure otherwise.
It never inserts a default, coerces a type, normalizes a string, reorders an array, removes an
unknown member, or fills a missing field from anywhere. The value is exactly as loaded, before and
after.

Two `default` annotations exist in `spec/rulebook.schema.json` — `evidence.items.required` is
`true` and `authorization.ttl_seconds` is `300`. **They are annotations and are never applied
here.** Whoever consumes a rulebook applies them as documented in `spec/execution-chain.md`. A
validated document that omitted them still omits them.

## Types
The frozen value model only: object is `dict`, array is `list`, string is `str`, integer is `int`,
boolean is `bool`, null is `None`.

**A boolean is never an integer.** Python makes `bool` a subclass of `int`; the subset does not.
`true` fails `type: integer`, and `1` fails `type: boolean`. No schema in the registry uses type
`number` or type `null`, and neither is implemented — a schema introducing either is refused at
registry load rather than quietly accepted.

## Supported keywords
Exactly what the six schemas use, and nothing more. Anything else refuses the schema at registry
load with ERROR `schema_registry_invalid`, so an unsupported construct can never be silently
ignored.

**Assertions** — `type`, `required`, `properties`, `additionalProperties`, `items`, `enum`,
`const`, `pattern`, `format`, `minItems`, `minLength`, `minimum`.

**Annotations, accepted and ignored** — `$schema`, `$id`, `title`, `description`, `default`.

**Structural** — `$defs`, `$ref`.

Deliberately absent because no schema uses them: `maximum`, `maxItems`, `maxLength`,
`exclusiveMinimum`, `exclusiveMaximum`, `multipleOf`, `uniqueItems`, `prefixItems`, `contains`,
`patternProperties`, `propertyNames`, `dependentRequired`, `allOf`, `anyOf`, `oneOf`, `not`,
`if`/`then`/`else`. Adding one to a schema is a specification change, and the registry will say so.

## Objects
`required`, `properties`, and `additionalProperties` only.

`additionalProperties: false` refuses every undeclared member. `additionalProperties: <schema>`
validates every undeclared member against it. **Omitted means unconstrained**, which is the JSON
Schema default and is deliberate here: exactly one object in the registry omits it,
`candidate.action`, because an action carries `params` whose shape is the caller's. Every other
object in all six schemas sets it to `false`.

## Order of checks
Deterministic and independent of how any mapping was built:

1. `type`;
2. `required`, in the order the schema's `required` array declares — an array, so its order is
   part of the document;
3. declared `properties`, in **canonical key order**, ascending by Unicode scalar value;
4. undeclared members against `additionalProperties`, in canonical key order;
5. remaining assertions on this node: `enum`, `const`, `minItems`, `items`, `minLength`,
   `pattern`, `format`, `minimum`.

Canonical key order, not insertion order, is what makes the *first* reported failure the same on
every machine. Arrays are validated in ascending index order.

## Strings
`minLength` counts **Unicode scalar values**, not UTF-8 bytes and not UTF-16 code units.

`pattern` is matched as a **full-string match** over Unicode scalars, case-sensitive, with no
multiline mode. Every pattern in the registry is explicitly anchored `^…$`, and the registry
refuses an unanchored pattern, so full-match and JSON Schema's search semantics agree on every
pattern that can exist here — with one deliberate exception, which is the reason for the rule.

**The trailing-newline hole.** In Python, `$` also matches immediately before a final newline, so
`re.match(r'^sha256:[a-f0-9]{64}$', "sha256:…\n")` succeeds while JavaScript's `/…$/.test` on the
same string fails. A digest carrying a trailing newline would therefore pass validation in the
reference implementation and fail in a shim — under the cryptographic contract. Full-match closes
it: the newline is not consumed, so the match fails in both runtimes.

The permitted regex constructs are literals, escaped literals, character classes with ranges,
`^`, `$`, `|`, grouping, and the quantifiers `*`, `+`, `?`, `{n}`, `{n,m}`. Refused at registry
load: backreferences, lookahead, lookbehind, inline flags, named groups, and the shorthand classes
`\d`, `\w`, `\s`, `\b`, whose meaning differs between ASCII and Unicode modes and between engines.
All three patterns in the registry — `^[a-z0-9][a-z0-9-]{1,63}$`,
`^[0-9]+\.[0-9]+\.[0-9]+$`, and `^sha256:[a-f0-9]{64}$` — are inside that subset.

## Formats
`date-time` is the only format any schema uses, and it is an **assertion**, not an annotation.
JSON Schema leaves that optional; the product does not, because `spec/execution-chain.md` compares
`frozen_at` against `adopted_at` and a malformed instant would reach that comparison.

The accepted grammar is RFC 3339 narrowed to one spelling:

    YYYY-MM-DDTHH:MM:SS(.fff…)?(Z|(+|-)HH:MM)

- `T` and `Z` uppercase only. RFC 3339 permits lowercase and a space separator; all three are
  refused so that one instant has one text.
- An offset is `+HH:MM` or `-HH:MM`, always with the colon, or the literal `Z`.
- A fractional part is optional, `.` followed by one to nine digits.
- The date must exist: month 01–12, day valid for that month, Gregorian leap years.
- Seconds are 00–59. Leap second 60 is refused.
- The string is validated and **left as a string**. Nothing is converted to a native date or
  datetime, and no timezone database, locale, or clock is consulted.

## Numbers
`minimum` only, on integers only. Every number reaching validation is already a canonical integer
in the frozen interval, so there is no float comparison, coercion, or exponent handling here.

## enum and const
Compared by exact canonical value and type. `1` does not equal `true`, `"1"` does not equal `1`,
and containers compare by exact structural equality. Nothing is coerced.

## References
`$ref` resolves against a frozen registry assembled in memory by the caller from repository schema
documents, keyed by `$id`. Three references exist and all resolve offline:

| From | Reference |
|---|---|
| `authorization.schema.json` `$.properties.signature` | `#/$defs/sig` |
| `receipt.schema.json` `$.properties.result` | `…/outcome.schema.json` |
| `receipt.schema.json` `$.properties.signature` | `…/authorization.schema.json#/$defs/sig` |

The graph is acyclic. A local `#/…` fragment resolves inside its own document; an absolute
reference resolves by `$id`, then by fragment. Refused at registry load: a reference to an `$id`
not in the registry, a fragment that does not exist, any scheme that would require a fetch, and
any duplicate or missing `$id`. **Nothing is ever fetched.** A reference is either already in the
registry or the registry is invalid.

## Failure
One failure, the first in the order above, so the result is deterministic. The raised object
carries the machine-readable fields; the message is a fixed string per keyword and never contains
instance data.

- `code` — the schema-specific reason code below;
- `instance_path` — where in the value, e.g. `$.rules[2].outcome`;
- `schema_path` — where in the schema, e.g. `$.properties.rules.items.properties.outcome.enum`;
- `keyword` — the assertion that failed.

Path notation: `$` is the root. A member is `.name` when the name matches
`[A-Za-z_][A-Za-z0-9_]*`, otherwise `["name"]` with JSON string escaping. An array element is
`[index]`, 0-based.

| Schema | Reason code |
|---|---|
| `candidate.schema.json` | `candidate_schema_invalid` |
| `rulebook.schema.json` | `rulebook_schema_invalid` |
| `evidence.schema.json` | `snapshot_schema_invalid` |
| `outcome.schema.json` | `outcome_schema_invalid` |
| `authorization.schema.json` | `authorization_schema_invalid` |
| `receipt.schema.json` | `receipt_schema_invalid` |
| any schema document itself | `schema_registry_invalid` |

## Precondition
Instances come from the strict loader and are therefore at most 64 deep
(`spec/document-loading.md`). The validator enforces that same bound and refuses a deeper value
with the schema's own code and keyword `depth`, so a value built directly in Python cannot exhaust
the stack through this boundary.

## What this boundary does not do
Schema validity is not semantic validity. These are checked elsewhere and are **not** claimed here:
duplicate evidence item identifiers, which no keyword in the subset can express; whether a
receipt's outcome is one that may be emitted at all — the outcome schema admits ERROR while
`spec/execution-chain.md` forbids a receipt for it; whether `reasons[].code` is in the closed set,
which the schema leaves as a free string; and every relationship between fields, such as
`frozen_at` against `adopted_at`, or which reason codes may accompany which outcome.
