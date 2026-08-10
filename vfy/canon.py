"""Canonical serialization and digests, per spec/canonicalization.md.

Pure: no clock, no randomness, no filesystem, no network, no environment, no locale, no
timezone. The same value produces the same bytes on every machine.
"""

import base64
import hashlib

from vfy.errors import CanonicalFormInvalid, FloatNotPermitted, SurrogateNotPermitted

MAX_SAFE_INTEGER = 2 ** 53 - 1
MIN_SAFE_INTEGER = -(2 ** 53 - 1)

_FIRST_SURROGATE = "\ud800"
_LAST_SURROGATE = "\udfff"

_NAMED_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

_FIRST_PRINTABLE = " "  # U+0020: everything below it is a C0 control

# Frame kinds for the explicit work stack in canonicalize().
_TEXT = 0    # already-rendered text, emit as is
_VALUE = 1   # a value still to be written
_KEY = 2     # an object key still to be rendered, followed by its colon


# One signature byte string has one accepted textual encoding.
#
# Strict base64 already refuses a bad alphabet and bad padding, but it does not refuse *unused
# trailing bits*. A 64-byte Ed25519 signature encodes to 88 characters whose third-from-last
# carries four bits that decode to nothing, so **sixteen distinct texts** decoded to the same
# signature and every one of them verified. No forgery — the bytes are identical and Ed25519 is
# untouched — but an artifact that is supposed to have one canonical form had sixteen, which is
# exactly the property canonicalization exists to remove. Anything that compares, indexes, dedupes
# or digests the encoded text would have disagreed with itself.
SIGNATURE_BYTES = 64


def decode_signature(text):
    """Decode a signature and require the text to be its one canonical encoding.

    Length is deliberately **not** checked here. `fixtures/` pins a truncated signature as
    `signature_invalid` — the answer Ed25519 verification itself gives — and a length guard in
    front of it would re-answer that as `signature_malformed`. The golden vectors are the
    authority, and this function has one job: whether the text is the canonical spelling of the
    bytes it decodes to. Nothing about which bytes are a valid signature.
    """
    if not isinstance(text, str):
        raise CanonicalFormInvalid("A signature value must be a string.")
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:
        raise CanonicalFormInvalid("The signature value is not valid base64.") from None
    # The check that closes it: re-encode and require the presented text back, exactly.
    if base64.b64encode(raw).decode("ascii") != text:
        raise CanonicalFormInvalid(
            "The signature value is not the canonical base64 encoding of its own bytes.")
    return raw


def canonicalize(value):
    """Return the canonical text for value.

    The walk carries its own stack rather than recursing. Depth is therefore bounded by memory
    alone, never by the host's recursion limit, which is mutable and would otherwise decide
    whether a document is acceptable differently on different machines. Frames are pushed
    reversed so they pop in document order, which keeps a rejection deep in the value reporting
    the same code it would have reported under a recursive walk.
    """
    out = []
    stack = [(_VALUE, value)]
    while stack:
        kind, item = stack.pop()
        if kind == _TEXT:
            out.append(item)
        elif kind == _KEY:
            out.append(_string_text(item) + ":")
        elif item is None:
            out.append("null")
        elif isinstance(item, bool):
            out.append("true" if item else "false")
        elif isinstance(item, float):
            raise FloatNotPermitted(
                "A float is never valid input; carry non-integer numbers as canonical decimal "
                "strings."
            )
        elif isinstance(item, int):
            out.append(_integer_text(item))
        elif isinstance(item, str):
            out.append(_string_text(item))
        elif isinstance(item, list):
            stack.extend(reversed(_array_frames(item)))
        elif isinstance(item, dict):
            stack.extend(reversed(_object_frames(item)))
        else:
            raise CanonicalFormInvalid(
                "Only JSON's own types are canonicalizable; got " + type(item).__name__ + "."
            )
    return "".join(out)


def canonical_bytes(value):
    """Return the canonical UTF-8 bytes for value."""
    return canonicalize(value).encode("utf-8")


def hex_digest_of_text(text):
    """Return the lowercase hex sha256 of text encoded as UTF-8.

    This entry point takes text that has not passed through the writer below, so it carries its
    own guard. A Python string is unencodable as UTF-8 exactly when it holds a surrogate, so the
    mapping is exact and no other failure is being folded into this code.
    """
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        raise SurrogateNotPermitted(
            "A string may not carry a code point in U+D800-U+DFFF."
        ) from None
    return hashlib.sha256(encoded).hexdigest()


def digest(value):
    """Return the prefixed digest of value: "sha256:" followed by 64 lowercase hex digits."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _integer_text(value):
    if value < MIN_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
        raise CanonicalFormInvalid(
            "Integer outside the range every implementation holds exactly."
        )
    return str(value)


def _string_text(value):
    pieces = ['"']
    for character in value:
        escape = _NAMED_ESCAPES.get(character)
        if escape is not None:
            pieces.append(escape)
        elif character < _FIRST_PRINTABLE:
            pieces.append("\\u%04x" % ord(character))
        elif _FIRST_SURROGATE <= character <= _LAST_SURROGATE:
            # Refused, never repaired: a surrogate is not escaped, replaced, normalized, or
            # dropped into an accepted value. Nothing is hashed before it is known to be valid.
            raise SurrogateNotPermitted(
                "A string may not carry a code point in U+D800-U+DFFF."
            )
        else:
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


def _array_frames(value):
    frames = [(_TEXT, "[")]
    for index, item in enumerate(value):
        if index:
            frames.append((_TEXT, ","))
        frames.append((_VALUE, item))
    frames.append((_TEXT, "]"))
    return frames


def _object_frames(value):
    # Keys are checked before anything is emitted, so a non-string key is refused for the whole
    # object rather than after part of it has been rendered.
    for key in value:
        if not isinstance(key, str):
            raise CanonicalFormInvalid(
                "Object keys are always strings; got " + type(key).__name__ + "."
            )
    frames = [(_TEXT, "{")]
    for index, key in enumerate(sorted(value)):
        if index:
            frames.append((_TEXT, ","))
        frames.append((_KEY, key))
        frames.append((_VALUE, value[key]))
    frames.append((_TEXT, "}"))
    return frames
