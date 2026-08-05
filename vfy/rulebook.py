"""Rulebook loading and pinning, per spec/rulebook-loading.md.

Source bytes become one immutable, validated, content-addressed rulebook. This layer pins; it
decides nothing. It does not parse `when`, resolve evidence, or reach an outcome, and it reads no
file, clock, environment variable, or network.
"""

import re
from dataclasses import dataclass

from vfy import canon, load, schema
from vfy.errors import (
    RulebookSemanticInvalid,
    RulebookVersionCollision,
    UndeclaredEvidenceId,
)

RULEBOOK_LOADER_VERSION = 1
RULEBOOK_SCHEMA_ID = "https://verifyrun.com/spec/v1/rulebook.schema.json"

# spec/rulebook.schema.json states this in the field description; the schema expresses no
# pattern for it, so it is enforced here.
_EVIDENCE_IDENTIFIER = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")

_NANOS_PER_SECOND = 1000000000


@dataclass(frozen=True)
class LoadedRulebook:
    """A pinned rulebook. Every field is a string, so the record itself cannot be mutated.

    The canonical bytes are the authority. `value()` reconstructs a fresh copy from them rather
    than handing out a shared mapping, because the frozen value model admits only dict and list —
    a recursively frozen structure built from tuples or mapping proxies would be refused by
    canonicalization itself.
    """

    canonical: str
    digest: str
    rulebook_id: str
    version: str
    adopted_at: str

    @property
    def canonical_bytes(self):
        return self.canonical.encode("utf-8")

    @property
    def identity(self):
        return (self.rulebook_id, self.version)

    def value(self):
        """Return a fresh reconstruction of the rulebook value.

        Every caller gets its own copy; mutating it changes nothing here, and the result is
        inside the frozen value model because the strict loader says so.
        """
        return load.load_json_bytes(self.canonical_bytes)


def load_rulebook_bytes(data, registry):
    """Return the pinned rulebook the YAML source bytes denote.

    Order is fixed by spec/rulebook-loading.md: strict YAML load, schema validation, load-time
    semantic checks, canonical serialization, digest. A failed load produces no digest, because
    nothing is hashed before it is known to be valid.
    """
    value = load.load_yaml_bytes(data)
    schema.validate(value, RULEBOOK_SCHEMA_ID, registry)
    _check_load_time_semantics(value)
    canonical = canon.canonicalize(value)
    return LoadedRulebook(
        canonical=canonical,
        digest="sha256:" + canon.hex_digest_of_text(canonical),
        rulebook_id=value["rulebook_id"],
        version=value["version"],
        adopted_at=value["adopted_at"],
    )


def rulebook_applies(loaded, evaluation_instant):
    """Return whether the rulebook governs a run starting at the recorded instant.

    The instant is supplied by the caller — in the execution chain, the evidence snapshot's
    frozen_at. No clock is read here or anywhere below.
    """
    return _instant(evaluation_instant) >= _instant(loaded.adopted_at)


def check_no_version_collision(first, second):
    """Refuse a pair that gives one identity two meanings."""
    if first.identity == second.identity and first.digest != second.digest:
        raise RulebookVersionCollision(
            "Two rulebooks share (rulebook_id, version) but differ in content: %s %s"
            % (first.rulebook_id, first.version)
        )


def _check_load_time_semantics(value):
    declared = []
    for item in value["evidence"]:
        identifier = item["id"]
        if not _EVIDENCE_IDENTIFIER.match(identifier):
            raise RulebookSemanticInvalid(
                "An evidence id must lex as an identifier so expressions can name it."
            )
        if identifier in declared:
            raise RulebookSemanticInvalid("Duplicate evidence id in the rulebook.")
        declared.append(identifier)

    seen_rules = set()
    for rule in value["rules"]:
        identifier = rule["id"]
        if identifier in seen_rules:
            raise RulebookSemanticInvalid("Duplicate rule id in the rulebook.")
        seen_rules.add(identifier)
        for needed in rule.get("requires_evidence", []):
            if needed not in declared:
                raise UndeclaredEvidenceId(
                    "A rule requires evidence the rulebook does not declare."
                )


def _instant(text):
    """Return an exact integer nanosecond instant. Integer arithmetic only.

    No locale, no timezone database, no wall clock, no floating point. The frozen date-time
    grammar admits only Z or an explicit offset, so no local time is ambiguous.
    """
    if not isinstance(text, str) or not schema._is_date_time(text):
        raise TypeError(
            "An evaluation instant must be a date-time string in the frozen grammar; snapshot "
            "schema validation guarantees this."
        )
    parts = schema._DATE_TIME.match(text)
    year, month, day, hour, minute, second = (int(parts.group(i)) for i in range(1, 7))
    fraction = parts.group(7)
    nanoseconds = int((fraction[1:] + "000000000")[:9]) if fraction else 0
    offset = parts.group(8)
    offset_seconds = 0
    if offset != "Z":
        sign = 1 if offset[0] == "+" else -1
        offset_seconds = sign * (int(offset[1:3]) * 3600 + int(offset[4:6]) * 60)
    seconds = (_days_from_civil(year, month, day) * 86400
               + hour * 3600 + minute * 60 + second - offset_seconds)
    return seconds * _NANOS_PER_SECOND + nanoseconds


def _days_from_civil(year, month, day):
    """Days from 1970-01-01, by exact integer arithmetic over the proleptic Gregorian calendar."""
    year -= month <= 2
    era = (year if year >= 0 else year - 399) // 400
    year_of_era = year - era * 400
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    day_of_era = year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year
    return era * 146097 + day_of_era - 719468
