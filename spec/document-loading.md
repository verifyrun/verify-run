# Document loading — source bytes to canonical value
    loader_version: 1

The boundary between the bytes on disk and the value canonicalization is defined to accept.
Everything a parser might decide on its own is decided here instead, in writing, so that Python
and any shim turn the same bytes into the same value.

The loader sits between source and schema. It does not validate schemas, does not hash, does not
read files, and does not touch the clock, network, environment, locale, or process state. Reading
a file is an adapter's job in a later closure; the loader is handed bytes.

## Scope of loader_version 1
JSON, and a bounded subset of YAML for rulebooks. The YAML subset exists to give one semantic
document across Python and a future JavaScript implementation. It is deliberately far smaller than
the YAML language, and compatibility with full YAML is a non-goal.

## Public boundary
    load_json_bytes(data: bytes) -> canonical value
    load_yaml_bytes(data: bytes) -> canonical value

Bytes, not text. Every v1 call site — `vfy check action.json`, and `vfy replay` reading a receipt
and its three input bodies — holds bytes read from a file, and half of this contract is about how
bytes become characters. A text entry point would let a caller skip the encoding rules, so none is
offered. Passing anything other than `bytes` is a caller error and raises `TypeError`; that is a
programming mistake, not an ERROR outcome, and it is not part of the input model.

## 1. Source bytes
- The source must be UTF-8. Malformed UTF-8 → ERROR `source_encoding_invalid`.
- A UTF-8 byte-order mark is refused → ERROR `source_encoding_invalid`. Canonical output carries
  no BOM and nothing in this spec suite permits one on input. UTF-16 and UTF-32 byte-order marks
  are not UTF-8 and fail decoding, reaching the same code.

## 2. Bounds
Parsing is the one place where a host limit could otherwise decide meaning: the JSON scanner is
recursive in its pure-Python form and not in its C form, so the same document can load on one
build and exhaust the stack on another. That is the defect removed from canonicalization in
`spec/canonicalization.md`, and it is closed here the same way — with a declared number, not a
host setting.

- **Maximum nesting depth: 64.** Counted over `{` and `[` in the source, outside strings. Deeper
  → ERROR `source_too_deep`. The check runs on the source text before parsing begins, so it never
  depends on how deep a particular runtime can recurse.
- No other limit is declared. Source size, member count, and scalar length are bounded only by
  available memory. Resource exhaustion is a runtime concern and cross-runtime conformance over
  it is **not claimed**.

A raw `RecursionError` must never cross this boundary. The depth check exists so that it cannot.

## 3. JSON parsing
Refused, each → ERROR `source_syntax_invalid`:
- any JSON syntax error;
- trailing non-whitespace content after the document;
- more than one document in the source;
- an empty source;
- `NaN`, `Infinity`, and `-Infinity`. These are not JSON — RFC 8259 has no such literals — and a
  parser that accepts them is extending the format. The failure is that the source is not JSON,
  which is a different fix from writing a number the value model rejects.

Refused with the codes the value model already assigns:
- a duplicate object key, at any depth → ERROR `canonical_form_invalid`. Detected from the parsed
  key/value pairs **before** a mapping is built, because by the time a mapping exists the earlier
  member is gone. `spec/canonicalization.md` assigns this check here and forbids the canonicalizer
  from claiming it.
- a number with a fraction or an exponent → ERROR `float_not_permitted`. `1.5`, `1e3`, and `2.0`
  are well-formed JSON and forbidden values; carry non-integer numbers as canonical decimal
  strings.
- an integer outside −(2^53−1) … 2^53−1 → ERROR `canonical_form_invalid`.
- a string carrying a lone surrogate, which `"\ud800"` in the source produces → ERROR
  `surrogate_not_permitted`.

Strings are preserved exactly. No Unicode normalization, no trimming, no case folding. A properly
paired surrogate escape denotes its scalar and is valid.

## 4. Result
The loader returns only `dict`, `list`, `str`, `int`, `bool`, and `None`, with string keys
throughout — the value model in `spec/canonicalization.md` and nothing else.

Before returning, the parsed value is put through canonical-value validation by canonicalizing it
and discarding the text. That is not hashing; it is the one existing, exhaustively pinned
statement of which values are acceptable, and reusing it means the loader cannot drift from the
canonicalizer about what it will hand on. Whatever that step refuses, the loader refuses, with the
same code.

JSON cannot express a cyclic value, so no loaded JSON value can be cyclic.

## 5. The YAML subset
Sections 1 and 2 apply unchanged: same UTF-8 rule, same BOM rule, same maximum depth of 64.

The subset is read from the parser's **event stream**, not from a loaded object graph. Two reasons.
Anchors, aliases, and explicit tags are visible as events and gone by the time an object exists, so
they can be refused rather than cleaned up afterwards. And the event stream is produced without
recursion, while the object-building layer above it recurses — a document 2000 deep exhausts the
stack through the ordinary loading entry point and does not through the event stream. Depth stays a
declared number rather than a host limit.

**An implementation trap, pinned here because it is silent.** A plain scalar reports its style as
`None` under the pure-Python parser and as the empty string under the libyaml-backed parser.
Everything else — value, tag, anchor, event order — is identical. An implementation that tests
`style is None` to recognise a plain scalar is correct on one build and, on the other, treats every
plain scalar as quoted: `true` becomes the string `"true"` and every integer becomes a string, with
no error anywhere. **Both spellings mean plain.** The reference implementation defaults to the
pure-Python parser so that the presence of a C extension never changes which path runs, and the
fixtures are executed under both.

### Structure
Exactly one document, whose root is a mapping. Refused:
- an empty source, or a document with no content → ERROR `source_syntax_invalid`;
- more than one document → ERROR `source_syntax_invalid`;
- any YAML syntax error, including tab indentation → ERROR `source_syntax_invalid`;
- a root that is not a mapping → ERROR `source_construct_unsupported`;
- a duplicate mapping key at any depth → ERROR `canonical_form_invalid`, detected from the key
  sequence before a mapping is built;
- a key that is not a string after the scalar rules below → ERROR `canonical_form_invalid`;
- an anchor, an alias, a merge key (`<<`), or any explicit tag — including `!!int`, `!!str`,
  `!!timestamp`, `!!binary`, `!!set`, `!!omap`, `!!pairs`, and any application tag → ERROR
  `source_construct_unsupported`.

Comments and ordinary whitespace carry no meaning and are permitted anywhere YAML allows them.

Because anchors and aliases are refused, **no YAML source can construct a cycle**, and every loaded
value is an acyclic tree. That guarantee covers this loader only; see §7.

### Scalars
A quoted scalar — single or double — is always a string, character for character after YAML's own
escape processing. It is never inspected for type.

A literal (`|`) or folded (`>`) block scalar is always a string. Block scalars are permitted
because a current template uses one. Their folding and chomping results are pinned by fixtures for
all six forms: `|`, `|-`, `|+`, `>`, `>-`, `>+`. Folding replaces a single line break with a space;
clip keeps one trailing newline, strip keeps none, keep keeps them all. An explicit indentation
indicator is accepted and passed through but is not exercised by any template and is not pinned.

A plain scalar resolves by exactly these rules, in order:
1. `true` → boolean true, `false` → boolean false. Lowercase only.
2. `null` → null. Lowercase only.
3. A canonical base-10 integer — optional `-`, no `+`, no leading zero except `0` itself — becomes
   an integer. Outside −(2^53−1) … 2^53−1 → ERROR `canonical_form_invalid`.
4. A **reserved ambiguous form**, listed below, is refused. It is never silently converted and
   never silently treated as an ordinary string.
5. Anything else is a string.

Rule 4 is the point of the subset. Every reserved form is one that some YAML implementation
resolves to a value other than a string, and implementations disagree: this parser reads `1e3` and
`0o17` as strings while a YAML 1.2 reader reads them as a float and an integer. Rather than pick a
winner, the subset refuses the form and asks the author to quote it or write it canonically.

Reserved, refused as ERROR `source_construct_unsupported`:
- other boolean spellings: `True`, `False`, `TRUE`, `FALSE`, `yes`, `Yes`, `YES`, `no`, `No`, `NO`,
  `on`, `On`, `ON`, `off`, `Off`, `OFF`. The single letters `y`, `Y`, `n`, `N` are **not** reserved:
  no mainstream implementation resolves them, and they are ordinary identifiers a rulebook may
  legitimately use;
- other null spellings: `~`, `Null`, `NULL`, and the empty plain scalar;
- non-canonical integer notation: a leading `+`, a leading zero (`01`), hexadecimal (`0x1F`),
  octal (`0o17`, `017`), binary (`0b101`), and sexagesimal (`1:30`);
- date and timestamp shapes such as `2026-08-05` and `2026-08-05T00:00:00Z`.

Reserved, refused as ERROR `float_not_permitted`, so that a number written with a fraction or an
exponent fails the same way it fails in JSON:
- `1.5`, `1e3`, `1E3`, `1.0e3`, and any signed variant;
- `.inf`, `-.inf`, `+.inf`, `.nan`, in any case.

Rejection applies only when the **complete** plain scalar matches a reserved form. A scalar is
never refused for merely containing digits or punctuation, and these all remain ordinary strings:
`1.0.0`, `./claim/authority.json`, `.vfy/approvals.json`, `https://api.internal.example/coverage`,
`*rm -rf*`, `ALLOW`, and prose containing a colon where YAML permits one. A decimal such as
`12.50` is written quoted and stays a string; unquoted it is reserved and refused.

## 6. Result, both formats
The loader returns only `dict`, `list`, `str`, `int`, `bool`, and `None`, with string keys
throughout. No native date, datetime, Decimal, bytes, set, tuple, or parser-specific object can
reach canonicalization. Every loaded value is put through canonical-value validation as described
in §4.

## 7. Cycles
YAML loading guarantees an acyclic value tree, because anchors and aliases are refused and JSON
cannot express a cycle at all. **That guarantee does not extend to the Python API.** A caller can
still hand canonicalization a cyclic object built in memory, and canonicalization has no cycle
detection: it does not raise, it does not terminate. Direct-cycle handling is an open canonicalizer
hardening obligation and is **not** closed by this loader.
