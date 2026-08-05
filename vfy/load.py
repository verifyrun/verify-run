"""Strict document loading, per spec/document-loading.md.

Source bytes in, canonical value out. Every choice a permissive parser would make on its own is
made here instead. No schema validation, no hashing, no file reading, no clock, network,
environment, locale, or process state.

loader_version 1 covers JSON only. The YAML subset is not yet frozen and no YAML loader exists.
"""

import json
import re

import yaml

from vfy import canon
from vfy.errors import (
    CanonicalFormInvalid,
    FloatNotPermitted,
    SourceConstructUnsupported,
    SourceEncodingInvalid,
    SourceSyntaxInvalid,
    SourceTooDeep,
)

LOADER_VERSION = 1
MAX_DEPTH = 64

_UTF8_BOM = b"\xef\xbb\xbf"

# A plain scalar reports style None under the pure-Python parser and "" under the libyaml-backed
# one. Everything else about the two event streams is identical. Testing `style is None` would be
# correct on one build and would turn every plain scalar into a string on the other, silently.
_PLAIN_STYLES = (None, "")

_CANONICAL_INTEGER = re.compile(r"\A-?(0|[1-9][0-9]*)\Z")

# Single letters y/Y/n/N are deliberately absent: no mainstream implementation resolves them,
# and they are ordinary identifiers a rulebook may legitimately use as a key or a value.
_RESERVED_BOOLEANS = frozenset(
    "True False TRUE FALSE yes Yes YES no No NO on On ON off Off OFF".split()
)
_RESERVED_NULLS = frozenset(["~", "Null", "NULL", ""])

# Integer notations some implementation resolves to a number, none of them canonical.
_RESERVED_INTEGER_NOTATION = re.compile(
    r"""\A(
          [-+]?0[xX][0-9a-fA-F_]+          # hexadecimal
        | [-+]?0[bB][01_]+                 # binary
        | [-+]?0[oO][0-7_]+                # octal
        | [-+]?[0-9][0-9_]*(:[0-5]?[0-9])+ # sexagesimal
        | \+[0-9]+                         # leading plus
        | -?0[0-9]+                        # leading zero
    )\Z""",
    re.VERBOSE,
)

_RESERVED_TIMESTAMP = re.compile(
    r"""\A[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}
        ([Tt ][0-9]{1,2}:[0-9]{2}:[0-9]{2}(\.[0-9]*)?
         ([ ]*([Zz]|[-+][0-9]{1,2}(:[0-9]{2})?))?)?\Z""",
    re.VERBOSE,
)

_RESERVED_FLOAT = re.compile(
    r"""\A(
          [-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?
        | [-+]?\.(inf|Inf|INF|nan|NaN|NAN)
    )\Z""",
    re.VERBOSE,
)

_MERGE_KEY = "<<"
_NO_KEY = object()


def load_json_bytes(data):
    """Return the canonical value the JSON source bytes denote.

    Raises a typed VerifyError for every declared malformed-input class. No parser exception
    reaches the caller.
    """
    if not isinstance(data, bytes):
        # A caller contract violation, not an input class: it has no reason code and is not an
        # ERROR outcome.
        raise TypeError("load_json_bytes takes bytes, not " + type(data).__name__)

    text = _decode_utf8(data)
    _reject_excess_depth(text)

    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_float=_reject_float,
            parse_int=_integer_within_interval,
            parse_constant=_reject_non_json_constant,
        )
    except json.JSONDecodeError:
        raise SourceSyntaxInvalid(
            "Source is not well-formed JSON, carries trailing content, holds more than one "
            "document, or is empty."
        ) from None

    # Canonical-value validation. Canonicalizing and discarding the text is not hashing: it is the
    # one pinned statement of which values are acceptable, so the loader cannot drift from the
    # canonicalizer about what it hands on. Whatever that refuses, this refuses, with its code.
    canon.canonicalize(value)
    return value


def load_yaml_bytes(data, _loader_class=yaml.SafeLoader):
    """Return the canonical value the YAML source bytes denote, per the frozen subset.

    The default parser is the pure-Python one, so that whether a C extension happens to be
    installed never changes which code path runs. `_loader_class` exists so the fixtures can be
    executed under both parsers; it is not part of the public contract.
    """
    if not isinstance(data, bytes):
        raise TypeError("load_yaml_bytes takes bytes, not " + type(data).__name__)

    text = _decode_utf8(data)
    try:
        events = list(yaml.parse(text, Loader=_loader_class))
    except yaml.YAMLError:
        raise SourceSyntaxInvalid("Source is not well-formed YAML.") from None

    value = _value_from_yaml_events(events)
    canon.canonicalize(value)
    return value


def _value_from_yaml_events(events):
    """Build the value from the parser's event stream.

    Events, not a loaded object graph: anchors, aliases, and explicit tags are visible here and
    gone by the time an object exists, and the event stream is produced without recursion while
    the object-building layer above it recurses. Depth stays a declared number.
    """
    starts = [i for i, e in enumerate(events) if isinstance(e, yaml.DocumentStartEvent)]
    if not starts:
        raise SourceSyntaxInvalid("Source contains no document.")
    if len(starts) > 1:
        raise SourceSyntaxInvalid("Source contains more than one document.")

    end = next(i for i, e in enumerate(events) if isinstance(e, yaml.DocumentEndEvent))
    body = events[starts[0] + 1:end]

    if len(body) == 1 and isinstance(body[0], yaml.ScalarEvent) \
            and body[0].style in _PLAIN_STYLES and body[0].value == "":
        raise SourceSyntaxInvalid("Source contains an empty document.")
    if not body or not isinstance(body[0], yaml.MappingStartEvent):
        raise SourceConstructUnsupported("The root of a YAML document must be a mapping.")

    root = [_NO_KEY]
    stack = []
    for event in body:
        if isinstance(event, yaml.AliasEvent):
            raise SourceConstructUnsupported("An alias is not part of the subset.")
        if getattr(event, "anchor", None):
            raise SourceConstructUnsupported("An anchor is not part of the subset.")

        if isinstance(event, yaml.ScalarEvent):
            _place(stack, root, _yaml_scalar_value(event))
        elif isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            if event.tag:
                raise SourceConstructUnsupported(
                    "An explicit tag is not part of the subset: " + event.tag
                )
            if isinstance(event, yaml.MappingStartEvent):
                stack.append(["map", {}, [_NO_KEY], set()])
            else:
                stack.append(["seq", []])
            if len(stack) > MAX_DEPTH:
                raise SourceTooDeep(
                    "Source nests deeper than the declared maximum of %d." % MAX_DEPTH
                )
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            frame = stack.pop()
            if frame[0] == "map" and frame[2][0] is not _NO_KEY:
                raise SourceSyntaxInvalid("Mapping ended with a key and no value.")
            _place(stack, root, frame[1])

    if stack or root[0] is _NO_KEY:
        raise SourceSyntaxInvalid("Source is not well-formed YAML.")
    return root[0]


def _place(stack, root, value):
    if not stack:
        root[0] = value
        return
    frame = stack[-1]
    if frame[0] == "seq":
        frame[1].append(value)
        return
    mapping, pending, seen = frame[1], frame[2], frame[3]
    if pending[0] is _NO_KEY:
        if not isinstance(value, str):
            raise CanonicalFormInvalid("Mapping keys are always strings in the subset.")
        if value == _MERGE_KEY:
            raise SourceConstructUnsupported("A merge key is not part of the subset.")
        if value in seen:
            raise CanonicalFormInvalid("Duplicate mapping key in source.")
        seen.add(value)
        pending[0] = value
    else:
        mapping[pending[0]] = value
        pending[0] = _NO_KEY


def _yaml_scalar_value(event):
    if event.tag:
        raise SourceConstructUnsupported(
            "An explicit tag is not part of the subset: " + event.tag
        )
    if event.style in _PLAIN_STYLES:
        return _plain_scalar(event.value)
    # Quoted and block scalars are strings, verbatim, never inspected for type.
    return event.value


def _plain_scalar(text):
    if text == "true":
        return True
    if text == "false":
        return False
    if text == "null":
        return None
    if _CANONICAL_INTEGER.match(text):
        value = int(text)
        if value < canon.MIN_SAFE_INTEGER or value > canon.MAX_SAFE_INTEGER:
            raise CanonicalFormInvalid(
                "Integer outside the range every implementation holds exactly."
            )
        return value
    if text in _RESERVED_BOOLEANS or text in _RESERVED_NULLS:
        raise SourceConstructUnsupported(
            "Only lowercase true, false, and null are typed; quote this scalar or write it "
            "canonically."
        )
    if _RESERVED_INTEGER_NOTATION.match(text) or _RESERVED_TIMESTAMP.match(text):
        raise SourceConstructUnsupported(
            "This plain scalar resolves to a number or a timestamp in some YAML "
            "implementations; quote it or write a canonical integer."
        )
    if _RESERVED_FLOAT.match(text):
        raise FloatNotPermitted(
            "A number with a fraction or an exponent is a float and is never valid input; carry "
            "non-integer numbers as canonical decimal strings."
        )
    return text


def _decode_utf8(data):
    if data.startswith(_UTF8_BOM):
        raise SourceEncodingInvalid("Source carries a UTF-8 byte-order mark.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise SourceEncodingInvalid("Source bytes are not UTF-8.") from None


def _reject_excess_depth(text):
    """Bound nesting from the source text, before the parser recurses.

    The JSON scanner recurses in its pure-Python form and not in its C form, so without this the
    same document could load on one build and exhaust the stack on another. Counting here means
    the limit is a declared number rather than a host setting.
    """
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character == "{" or character == "[":
            depth += 1
            if depth > MAX_DEPTH:
                raise SourceTooDeep(
                    "Source nests deeper than the declared maximum of %d." % MAX_DEPTH
                )
        elif character == "}" or character == "]":
            depth -= 1


def _object_from_pairs(pairs):
    """Build a mapping, refusing a duplicate key while both members still exist."""
    seen = set()
    for key, _value in pairs:
        if key in seen:
            raise CanonicalFormInvalid("Duplicate object key in source.")
        seen.add(key)
    return dict(pairs)


def _reject_float(text):
    raise FloatNotPermitted(
        "A number with a fraction or an exponent is a float and is never valid input; carry "
        "non-integer numbers as canonical decimal strings."
    )


def _integer_within_interval(text):
    value = int(text)
    if value < canon.MIN_SAFE_INTEGER or value > canon.MAX_SAFE_INTEGER:
        raise CanonicalFormInvalid(
            "Integer outside the range every implementation holds exactly."
        )
    return value


def _reject_non_json_constant(name):
    raise SourceSyntaxInvalid(
        "%s is not JSON; a parser that accepts it is extending the format." % name
    )
