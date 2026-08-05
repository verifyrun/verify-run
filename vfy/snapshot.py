"""Snapshot construction and freeze, per spec/snapshot-construction.md.

A pinned rulebook, a recorded freeze instant, and already-acquired evidence results become one
immutable, schema-valid, content-addressed snapshot.

Nothing is acquired here. No file is read, no command runs, no endpoint is called, nothing is
retried, and no clock is consulted. Freshness is not computed either — that is the evaluator's,
and putting it in two layers would put one rule in two places.
"""

from dataclasses import dataclass

from vfy import canon, load, rulebook, schema
from vfy.errors import (
    EvidenceOrderInvalid,
    RulebookNotAdopted,
    SnapshotDigestMismatch,
    SnapshotItemInvalid,
    SnapshotItemMissing,
    SnapshotItemUndeclared,
    SnapshotRulebookMismatch,
    SnapshotSchemaInvalid,
)

SNAPSHOT_BUILDER_VERSION = 1
SNAPSHOT_SCHEMA_ID = "https://verifyrun.com/spec/v1/evidence.schema.json"

STATUSES = ("ok", "missing", "stale", "error")
_ACQUISITION_REQUIRED = ("id", "status", "acquired_at")
_ACQUISITION_PERMITTED = frozenset(_ACQUISITION_REQUIRED) | {"value"}


@dataclass(frozen=True)
class FrozenSnapshot:
    """A frozen snapshot. Canonical text is the authority; `value()` rebuilds a fresh copy."""

    canonical: str
    digest: str
    frozen_at: str
    snapshot_id: str

    @property
    def canonical_bytes(self):
        return self.canonical.encode("utf-8")

    def value(self):
        return load.load_json_bytes(self.canonical_bytes)


def build_snapshot(pinned, snapshot_id, frozen_at, acquisitions, registry):
    """Return the frozen snapshot for one run's declared acquisitions."""
    if not isinstance(snapshot_id, str):
        raise TypeError("snapshot_id must be a string")
    if not isinstance(acquisitions, (list, tuple)):
        raise TypeError("acquisitions must be a sequence")

    frozen_instant = _instant_or_raise(frozen_at, "frozen_at")
    if not rulebook.rulebook_applies(pinned, frozen_at):
        raise RulebookNotAdopted("The rulebook was not adopted when this run started.")

    declarations = {d["id"]: d for d in pinned.value()["evidence"]}
    items, seen = [], set()

    for position, acquisition in enumerate(acquisitions):
        _check_acquisition_shape(acquisition)
        identifier = acquisition["id"]
        if identifier not in declarations:
            raise SnapshotItemUndeclared(
                "The rulebook does not declare this evidence id: " + identifier)
        if identifier in seen:
            _duplicate(identifier, position)
        seen.add(identifier)

        _check_status_and_value(acquisition)
        acquired = _instant_or_raise(acquisition["acquired_at"], "acquired_at")
        if acquired > frozen_instant:
            raise EvidenceOrderInvalid(
                "Evidence was acquired after the freeze: " + identifier)

        item = {"id": identifier, "order": position, "status": acquisition["status"],
                "acquired_at": acquisition["acquired_at"]}
        if "value" in acquisition:
            item["value"] = acquisition["value"]
        items.append(item)

    # A required declaration with no acquisition is still an observation worth recording.
    for identifier, declaration in declarations.items():
        if identifier in seen:
            continue
        if declaration.get("required", True):
            items.append({"id": identifier, "order": len(items), "status": "missing",
                          "acquired_at": frozen_at})

    payload = {"snapshot_id": snapshot_id, "rulebook_digest": pinned.digest,
               "frozen_at": frozen_at, "items": items}
    return _seal(payload, registry)


def verify_snapshot_value(value, pinned, registry):
    """Accept a snapshot the builder did not make, trusting nothing it carries."""
    if not isinstance(value, dict):
        raise TypeError("a snapshot value must be a mapping")
    schema.validate(value, SNAPSHOT_SCHEMA_ID, registry)

    payload = {key: member for key, member in value.items() if key != "snapshot_digest"}
    recomputed = canon.digest(payload)
    if recomputed != value["snapshot_digest"]:
        raise SnapshotDigestMismatch(
            "The embedded snapshot digest does not match the snapshot's own payload.")

    if value["rulebook_digest"] != pinned.digest:
        raise SnapshotRulebookMismatch("The snapshot names a rulebook other than the pinned one.")

    frozen_instant = _instant_or_raise(value["frozen_at"], "frozen_at")
    if not rulebook.rulebook_applies(pinned, value["frozen_at"]):
        raise RulebookNotAdopted("The rulebook was not adopted when this run started.")

    declarations = {d["id"]: d for d in pinned.value()["evidence"]}
    seen = set()
    for position, item in enumerate(value["items"]):
        identifier = item["id"]
        if identifier not in declarations:
            raise SnapshotItemUndeclared(
                "The rulebook does not declare this evidence id: " + identifier)
        if identifier in seen:
            _duplicate(identifier, position)
        seen.add(identifier)
        if item["order"] != position:
            raise EvidenceOrderInvalid("Item order must be 0..n-1 in array order.")
        _check_status_and_value(item)
        if _instant_or_raise(item["acquired_at"], "acquired_at") > frozen_instant:
            raise EvidenceOrderInvalid("Evidence was acquired after the freeze: " + identifier)

    for identifier, declaration in declarations.items():
        if declaration.get("required", True) and identifier not in seen:
            raise SnapshotItemMissing(
                "A required evidence declaration has no snapshot item: " + identifier)

    return FrozenSnapshot(canonical=canon.canonicalize(value), digest=value["snapshot_digest"],
                          frozen_at=value["frozen_at"], snapshot_id=value["snapshot_id"])


def _seal(payload, registry):
    """Digest the payload, then complete and validate the snapshot. Never self-referential."""
    digest = canon.digest(payload)
    completed = dict(payload)
    completed["snapshot_digest"] = digest
    schema.validate(completed, SNAPSHOT_SCHEMA_ID, registry)
    return FrozenSnapshot(canonical=canon.canonicalize(completed), digest=digest,
                          frozen_at=payload["frozen_at"], snapshot_id=payload["snapshot_id"])


def _duplicate(identifier, position):
    """One declaration, one item. Uniqueness is beyond what the schema can express, so the
    failure carries its own location rather than a schema keyword."""
    raise SnapshotSchemaInvalid(
        "Duplicate evidence id: " + identifier,
        "$.items[%d].id" % position,
        "$.properties.items",
        "unique")


def _check_acquisition_shape(acquisition):
    if not isinstance(acquisition, dict):
        raise SnapshotItemInvalid("An acquisition must be a mapping.")
    for key in _ACQUISITION_REQUIRED:
        if key not in acquisition:
            raise SnapshotItemInvalid("An acquisition needs id, status, and acquired_at.")
    for key in acquisition:
        if key not in _ACQUISITION_PERMITTED:
            raise SnapshotItemInvalid("An acquisition carries an unexpected field: " + str(key))
    if not isinstance(acquisition["id"], str) or not acquisition["id"]:
        raise SnapshotItemInvalid("An acquisition id must be a non-empty string.")
    if acquisition["status"] not in STATUSES:
        raise SnapshotItemInvalid("An acquisition status must be one of the four declared.")


def _check_status_and_value(item):
    status, has_value = item["status"], "value" in item
    if status == "ok" and not has_value:
        raise SnapshotItemInvalid("An ok item records nothing without a value: " + item["id"])
    if status == "missing" and has_value:
        raise SnapshotItemInvalid("A missing item observed nothing to record: " + item["id"])


def _instant_or_raise(text, field):
    try:
        return rulebook._instant(text)
    except TypeError:
        raise EvidenceOrderInvalid(
            "%s is not a date-time in the frozen grammar." % field) from None
