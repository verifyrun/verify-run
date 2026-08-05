"""Bounded schema validation, per spec/schema-validation.md.

The keywords the six schemas in spec/ actually use, and nothing more. Not a JSON Schema engine.

Pure: no filesystem, no network, no clock, no environment, no randomness, no locale. Schemas
arrive as already-loaded canonical values through an in-memory registry the caller assembles;
nothing here opens a file or fetches a reference.
"""

import re

from vfy.errors import (
    AuthorizationSchemaInvalid,
    CandidateSchemaInvalid,
    OutcomeSchemaInvalid,
    ReceiptSchemaInvalid,
    RulebookSchemaInvalid,
    SchemaRegistryInvalid,
    SnapshotSchemaInvalid,
)

VALIDATOR_VERSION = 1
MAX_DEPTH = 64

ASSERTIONS = frozenset([
    "type", "required", "properties", "additionalProperties", "items", "enum", "const",
    "pattern", "format", "minItems", "minLength", "minimum",
])
ANNOTATIONS = frozenset(["$schema", "$id", "title", "description", "default"])
STRUCTURAL = frozenset(["$defs", "$ref"])
SUPPORTED = ASSERTIONS | ANNOTATIONS | STRUCTURAL

SUPPORTED_TYPES = frozenset(["object", "array", "string", "integer", "boolean"])
SUPPORTED_FORMATS = frozenset(["date-time"])

CODE_BY_ID = {
    "https://verifyrun.com/spec/v1/candidate.schema.json": CandidateSchemaInvalid,
    "https://verifyrun.com/spec/v1/rulebook.schema.json": RulebookSchemaInvalid,
    "https://verifyrun.com/spec/v1/evidence.schema.json": SnapshotSchemaInvalid,
    "https://verifyrun.com/spec/v1/outcome.schema.json": OutcomeSchemaInvalid,
    "https://verifyrun.com/spec/v1/authorization.schema.json": AuthorizationSchemaInvalid,
    "https://verifyrun.com/spec/v1/receipt.schema.json": ReceiptSchemaInvalid,
}

# Regex constructs whose meaning differs between engines or between ASCII and Unicode modes.
_FORBIDDEN_REGEX = ("(?=", "(?!", "(?<", "(?P", "(?i", "(?m", "(?s", "(?x",
                    "\\d", "\\w", "\\s", "\\b", "\\B", "\\A", "\\Z", "\\z", "\\G")
_BACKREFERENCE = re.compile(r"\\[1-9]")

_PLAIN_MEMBER = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")

_DATE_TIME = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})"
    r"T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?"
    r"(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)


def build_registry(documents):
    """Return a frozen registry mapping $id to schema document.

    Every document is checked against the supported subset here, so an unsupported construct is
    refused at registry load and can never be silently ignored while validating an instance.
    """
    registry = {}
    for document in documents:
        if not isinstance(document, dict):
            raise SchemaRegistryInvalid("A schema document must be an object.")
        identifier = document.get("$id")
        if not isinstance(identifier, str) or not identifier:
            raise SchemaRegistryInvalid("A schema document must declare a string $id.")
        if identifier in registry:
            raise SchemaRegistryInvalid("Duplicate $id in the registry: " + identifier)
        registry[identifier] = document
    for identifier, document in registry.items():
        _check_schema_node(document, identifier, registry)
    return registry


def validate(value, schema_id, registry):
    """Validate value against the registry schema named by schema_id.

    Returns None on success. Raises the schema's typed failure otherwise. Never mutates value.
    """
    if schema_id not in registry:
        raise SchemaRegistryInvalid("No schema in the registry with $id " + schema_id)
    failure = CODE_BY_ID.get(schema_id)
    if failure is None:
        raise SchemaRegistryInvalid("No reason code is declared for schema " + schema_id)
    _validate_node(value, registry[schema_id], "$", "$", schema_id, registry, failure, 0)


# --- registry checking ------------------------------------------------------------------------

def _check_schema_node(node, identifier, registry):
    if not isinstance(node, dict):
        raise SchemaRegistryInvalid("A schema node must be an object in " + identifier)
    for keyword in sorted(node):
        if keyword not in SUPPORTED:
            raise SchemaRegistryInvalid(
                "Unsupported schema keyword %r in %s" % (keyword, identifier)
            )
    declared_type = node.get("type")
    if declared_type is not None:
        if not isinstance(declared_type, str) or declared_type not in SUPPORTED_TYPES:
            raise SchemaRegistryInvalid(
                "Unsupported schema type %r in %s" % (declared_type, identifier)
            )
    if "format" in node and node["format"] not in SUPPORTED_FORMATS:
        raise SchemaRegistryInvalid(
            "Unsupported format %r in %s" % (node["format"], identifier)
        )
    if "pattern" in node:
        _check_pattern(node["pattern"], identifier)
    if "$ref" in node:
        _resolve(node["$ref"], identifier, registry)
    for key in ("properties", "$defs"):
        for name, child in node.get(key, {}).items():
            _check_schema_node(child, identifier, registry)
    if isinstance(node.get("items"), dict):
        _check_schema_node(node["items"], identifier, registry)
    additional = node.get("additionalProperties")
    if isinstance(additional, dict):
        _check_schema_node(additional, identifier, registry)


def _check_pattern(pattern, identifier):
    if not isinstance(pattern, str):
        raise SchemaRegistryInvalid("A pattern must be a string in " + identifier)
    if not (pattern.startswith("^") and pattern.endswith("$")):
        raise SchemaRegistryInvalid(
            "A pattern must be anchored ^...$ so full-match and search agree: %r in %s"
            % (pattern, identifier)
        )
    for construct in _FORBIDDEN_REGEX:
        if construct in pattern:
            raise SchemaRegistryInvalid(
                "Regex construct %r is outside the subset: %r in %s"
                % (construct, pattern, identifier)
            )
    if _BACKREFERENCE.search(pattern):
        raise SchemaRegistryInvalid(
            "A backreference is outside the subset: %r in %s" % (pattern, identifier)
        )
    try:
        re.compile(pattern)
    except re.error:
        raise SchemaRegistryInvalid(
            "A pattern does not compile: %r in %s" % (pattern, identifier)
        ) from None


def _resolve(reference, identifier, registry):
    """Resolve a reference to a schema node. Never fetches anything."""
    if not isinstance(reference, str) or not reference:
        raise SchemaRegistryInvalid("A $ref must be a non-empty string in " + identifier)
    document_id, _, fragment = reference.partition("#")
    if not document_id:
        document_id = identifier
    if document_id not in registry:
        raise SchemaRegistryInvalid(
            "A $ref names a schema outside the registry, and nothing is ever fetched: "
            + reference
        )
    node = registry[document_id]
    if fragment:
        if not fragment.startswith("/"):
            raise SchemaRegistryInvalid("Unsupported $ref fragment: " + reference)
        for step in fragment[1:].split("/"):
            step = step.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or step not in node:
                raise SchemaRegistryInvalid("A $ref fragment does not resolve: " + reference)
            node = node[step]
    return node, document_id


# --- instance validation ----------------------------------------------------------------------

def _fail(failure, message, instance_path, schema_path, keyword):
    raise failure(message, instance_path, schema_path, keyword)


def _member(path, name):
    if _PLAIN_MEMBER.match(name):
        return path + "." + name
    return path + "[" + _json_string(name) + "]"


def _json_string(text):
    out = ['"']
    for character in text:
        if character in ('"', "\\"):
            out.append("\\" + character)
        elif character < " ":
            out.append("\\u%04x" % ord(character))
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _type_of(value):
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    return type(value).__name__


def _validate_node(value, schema, instance_path, schema_path, identifier, registry,
                   failure, depth):
    if depth > MAX_DEPTH:
        _fail(failure, "Value nests deeper than the loader admits.",
              instance_path, schema_path, "depth")

    if "$ref" in schema:
        target, target_id = _resolve(schema["$ref"], identifier, registry)
        target_path = "$" if "#" not in schema["$ref"] else \
            "$" + schema["$ref"].partition("#")[2].replace("/", ".")
        _validate_node(value, target, instance_path, target_path, target_id, registry,
                       failure, depth)
        return

    declared_type = schema.get("type")
    if declared_type is not None and _type_of(value) != declared_type:
        _fail(failure, "Value is not of the declared type.",
              instance_path, schema_path + ".type", "type")

    if declared_type == "object" or isinstance(value, dict):
        _validate_object(value, schema, instance_path, schema_path, identifier, registry,
                         failure, depth)

    if "enum" in schema and not any(_equal(value, member) for member in schema["enum"]):
        _fail(failure, "Value is not one of the enumerated values.",
              instance_path, schema_path + ".enum", "enum")
    if "const" in schema and not _equal(value, schema["const"]):
        _fail(failure, "Value is not the constant value.",
              instance_path, schema_path + ".const", "const")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            _fail(failure, "Array has too few items.",
                  instance_path, schema_path + ".minItems", "minItems")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_node(item, item_schema, instance_path + "[%d]" % index,
                               schema_path + ".items", identifier, registry, failure,
                               depth + 1)

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            _fail(failure, "String is shorter than the minimum length.",
                  instance_path, schema_path + ".minLength", "minLength")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            _fail(failure, "String does not match the required pattern.",
                  instance_path, schema_path + ".pattern", "pattern")
        if schema.get("format") == "date-time" and not _is_date_time(value):
            _fail(failure, "String is not a date-time in the accepted grammar.",
                  instance_path, schema_path + ".format", "format")

    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            _fail(failure, "Integer is below the minimum.",
                  instance_path, schema_path + ".minimum", "minimum")


def _validate_object(value, schema, instance_path, schema_path, identifier, registry,
                     failure, depth):
    if not isinstance(value, dict):
        return
    properties = schema.get("properties", {})

    for name in schema.get("required", []):
        if name not in value:
            _fail(failure, "Required member is missing.",
                  _member(instance_path, name), schema_path + ".required", "required")

    for name in sorted(value):
        if name in properties:
            _validate_node(value[name], properties[name], _member(instance_path, name),
                           _member(schema_path + ".properties", name), identifier, registry,
                           failure, depth + 1)

    additional = schema.get("additionalProperties")
    if additional is None:
        return
    for name in sorted(value):
        if name in properties:
            continue
        if additional is False:
            _fail(failure, "Undeclared member is not permitted.",
                  _member(instance_path, name), schema_path + ".additionalProperties",
                  "additionalProperties")
        if isinstance(additional, dict):
            _validate_node(value[name], additional, _member(instance_path, name),
                           schema_path + ".additionalProperties", identifier, registry,
                           failure, depth + 1)


def _equal(left, right):
    """Exact canonical equality: a boolean is never an integer."""
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(_equal(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, (dict, list)) or isinstance(right, (dict, list)):
        return False
    return type(left) is type(right) and left == right


_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_date_time(text):
    match = _DATE_TIME.match(text)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    if not 1 <= month <= 12 or hour > 23 or minute > 59 or second > 59:
        return False
    limit = _DAYS[month - 1]
    if month == 2 and (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)):
        limit = 29
    if not 1 <= day <= limit:
        return False
    offset = match.group(8)
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        return False
    return True
