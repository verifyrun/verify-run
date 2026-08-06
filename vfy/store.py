"""Local artifact store, per spec/local-store.md.

Persists the exact artifacts a later process needs to verify and replay a decision.

**The store is not a trust anchor.** A file being local proves nothing: every load re-verifies
signatures and re-runs replay against caller-supplied keys, exactly as if the bytes had arrived
from a stranger. The store never evaluates, authorizes, issues, or executes anything, and reads no
clock, randomness, environment, or network.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from vfy import canon, load, receipt as receipt_module
from vfy.errors import (
    AuthorizationNonceReused,
    StoreArtifactNoncanonical,
    StoreCommitConflict,
    StoreConsumptionConflict,
    StoreIndexInvalid,
    StorePathInvalid,
    StoreRecordConflict,
    StoreRecordIncomplete,
    StoreRecordMissing,
    VerifyError,
)

STORE_FORMAT_VERSION = 1
STORABLE_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

_RECEIPTS = "receipts"
_CONSUMED = "consumed"
_TMP = "tmp"
_INDEX = "index.json"
_STORE = "store.json"
_INPUTS_SUFFIX = ".inputs"
_BODY_NAMES = ("rulebook", "candidate", "snapshot", "authorization")
_MAX_CONSUMPTION_SLOTS = 64
_MAX_INDEX_SLOTS = 64


@dataclass(frozen=True)
class ReceiptSummary:
    receipt_id: str
    created_at: str
    outcome: str
    rulebook_id: str
    rulebook_version: str
    authorization_id: str | None
    key_id: str


@dataclass(frozen=True)
class StoredRecord:
    """A committed record, reloaded and re-verified. Canonical text is the authority."""

    receipt_id: str
    outcome: str
    receipt_canonical: str
    rulebook_canonical: str
    candidate_canonical: str
    snapshot_canonical: str
    authorization_canonical: str | None
    replay_verified: bool
    authorization_verified: bool

    def receipt(self):
        return load.load_json_bytes(self.receipt_canonical.encode("utf-8"))

    def candidate(self):
        return load.load_json_bytes(self.candidate_canonical.encode("utf-8"))

    def snapshot(self):
        return load.load_json_bytes(self.snapshot_canonical.encode("utf-8"))


@dataclass(frozen=True)
class ConsumptionRecord:
    nonce: str
    authorization_id: str
    action_digest: str


@dataclass(frozen=True)
class StoreScan:
    """What a scan of the root found that is not a committed record."""

    abandoned_staging: tuple
    orphaned_inputs: tuple


class LocalStore:
    def __init__(self, root):
        if not isinstance(root, Path):
            raise TypeError("store root must be a pathlib.Path")
        self.root = root
        _reject_symlink(root)
        for child in (root, root / _RECEIPTS, root / _CONSUMED, root / _TMP):
            child.mkdir(parents=True, exist_ok=True)
            _reject_symlink(child)
        marker = root / _STORE
        if not marker.exists():
            _write_exact(marker, canon.canonical_bytes(
                {"store_format_version": STORE_FORMAT_VERSION}))
        _reject_symlink(marker)

    # --- writing ------------------------------------------------------------------------------

    def put_record(self, frozen_receipt, pinned, candidate, snapshot, authorization=None):
        """Commit one record. The receipt file's rename is the commit point."""
        receipt_id = frozen_receipt.receipt_id
        _check_storable(receipt_id)
        bodies = self._bodies(frozen_receipt, pinned, candidate, snapshot, authorization)

        final_receipt = self._receipt_path(receipt_id)
        final_inputs = self._inputs_path(receipt_id)

        if final_receipt.exists():
            return self._idempotent_or_conflict(receipt_id, frozen_receipt, bodies)

        staging = self.root / _TMP / (receipt_id + ".staging")
        try:
            staging.mkdir()                       # exclusive: refuses an existing staging path
        except FileExistsError:
            raise StoreCommitConflict(
                "A staging path already exists for " + receipt_id) from None

        try:
            for name, text in bodies.items():
                _write_exact(staging / (name + ".json"), text.encode("utf-8"))
            _write_exact(staging / "receipt.json", frozen_receipt.canonical_bytes)
            for name, text in bodies.items():
                if (staging / (name + ".json")).read_bytes() != text.encode("utf-8"):
                    raise StoreCommitConflict("A staged body did not write as written.")

            if final_inputs.exists():
                raise StoreCommitConflict("An inputs directory already exists for " + receipt_id)
            staged_receipt = staging / "receipt.json"
            staged_receipt.rename(staging.parent / (receipt_id + ".json.staged"))
            staging.rename(final_inputs)
            (staging.parent / (receipt_id + ".json.staged")).rename(final_receipt)
        except StoreCommitConflict:
            raise
        except OSError as failure:
            raise StoreCommitConflict("The record could not be committed: " + str(failure)) \
                from None

        # The record is committed above; the rename was the commit point. What follows
        # maintains a rebuildable cache, so its failure is not this record's failure. This is not
        # error suppression: nothing about the committed artifact is being hidden, and
        # `list_receipts` derives from the records themselves when the cache disagrees.
        self._refresh_index()
        return self.get_record(receipt_id, verify=False)

    def _bodies(self, frozen_receipt, pinned, candidate, snapshot, authorization):
        outcome = frozen_receipt.outcome
        bodies = {"rulebook": pinned.canonical,
                  "candidate": canon.canonicalize(candidate),
                  "snapshot": snapshot.canonical}
        if outcome == "ALLOW":
            if authorization is not None:
                bodies["authorization"] = authorization.canonical
        elif authorization is not None:
            raise StoreRecordConflict(
                "A %s decision authorizes nothing, so it stores no authorization." % outcome)
        return bodies

    def _idempotent_or_conflict(self, receipt_id, frozen_receipt, bodies):
        existing_receipt = self._receipt_path(receipt_id)
        _reject_symlink(existing_receipt)
        if existing_receipt.read_bytes() != frozen_receipt.canonical_bytes:
            raise StoreRecordConflict(
                "A different receipt is already stored under " + receipt_id)
        inputs = self._inputs_path(receipt_id)
        for name, text in bodies.items():
            path = inputs / (name + ".json")
            if not path.exists():
                raise StoreRecordIncomplete("Stored record is missing " + name)
            _reject_symlink(path)
            if path.read_bytes() != text.encode("utf-8"):
                raise StoreRecordConflict("A different " + name + " is stored under " + receipt_id)
        return self.get_record(receipt_id, verify=False)

    # --- reading ------------------------------------------------------------------------------

    def get_record(self, receipt_id, receipt_keys=None, registry=None,
                   authorization_keys=None, verification_time=None, verify=True):
        """Load and re-verify one committed record. Local bytes are never trusted as such."""
        _check_storable(receipt_id)
        receipt_path = self._receipt_path(receipt_id)
        if not receipt_path.exists():
            raise StoreRecordMissing("No committed record for " + receipt_id)
        _reject_symlink(receipt_path)

        receipt_value = _load_canonical(receipt_path)
        outcome = _receipt_outcome(receipt_value)
        inputs = self._inputs_path(receipt_id)
        if not inputs.is_dir():
            raise StoreRecordIncomplete("Record has no inputs directory: " + receipt_id)
        _reject_symlink(inputs)

        required = ["rulebook", "candidate", "snapshot"]
        if outcome == "ALLOW" and receipt_value.get("authorization_id") is not None:
            required.append("authorization")
        loaded = {}
        for name in required:
            path = inputs / (name + ".json")
            if not path.exists():
                raise StoreRecordIncomplete("Record is missing " + name + ".json")
            _reject_symlink(path)
            loaded[name] = _load_canonical(path)
        for name in _BODY_NAMES:
            if name not in required and (inputs / (name + ".json")).exists():
                raise StoreRecordConflict(
                    "A %s record must not store %s.json" % (outcome, name))

        replay_verified = authorization_verified = False
        if verify:
            if receipt_keys is None or registry is None:
                raise TypeError("verification needs a receipt key registry and a schema registry")
            report = receipt_module.replay_receipt(
                receipt_value,
                canon.canonicalize(loaded["rulebook"]).encode("utf-8"),
                loaded["candidate"], loaded["snapshot"], receipt_keys, registry,
                authorization=loaded.get("authorization"),
                authorization_keys=authorization_keys,
                verification_time=verification_time)
            replay_verified = report.result_matched
            authorization_verified = report.authorization_verified

        return StoredRecord(
            receipt_id=receipt_id, outcome=outcome,
            receipt_canonical=canon.canonicalize(receipt_value),
            rulebook_canonical=canon.canonicalize(loaded["rulebook"]),
            candidate_canonical=canon.canonicalize(loaded["candidate"]),
            snapshot_canonical=canon.canonicalize(loaded["snapshot"]),
            authorization_canonical=(canon.canonicalize(loaded["authorization"])
                                     if "authorization" in loaded else None),
            replay_verified=replay_verified, authorization_verified=authorization_verified)

    def list_receipts(self):
        """Return the index if it is usable, else rebuild. Records always govern."""
        index_path = self.root / _INDEX
        if not index_path.exists():
            return self.rebuild_index()
        _reject_symlink(index_path)
        try:
            value = load.load_json_bytes(index_path.read_bytes())
        except Exception:
            raise StoreIndexInvalid("The index is not a canonical JSON document.") from None
        if not isinstance(value, dict) or "receipts" not in value:
            raise StoreIndexInvalid("The index has no receipts array.")
        summaries = []
        for entry in value["receipts"]:
            if set(entry) != {"receipt_id", "created_at", "outcome", "rulebook_id",
                              "rulebook_version", "authorization_id", "key_id"}:
                raise StoreIndexInvalid("An index entry has unexpected fields.")
            summaries.append(ReceiptSummary(**entry))

        # Records govern. Comparing identities is enough to detect every disagreement: a record
        # is never overwritten, so an entry naming a committed receipt describes it correctly,
        # and any other difference is a name present or absent on one side.
        committed = {path.stem for path in (self.root / _RECEIPTS).glob("*.json")}
        if {s.receipt_id for s in summaries} != committed:
            return self._summaries_from_records()
        return tuple(summaries)

    def rebuild_index(self):
        summaries = self._summaries_from_records()
        self._write_index(summaries)
        return summaries

    def scan(self):
        """Report what is present but not committed. Nothing is deleted."""
        staging = tuple(sorted(p.name for p in (self.root / _TMP).iterdir()))
        orphans = []
        for path in sorted((self.root / _RECEIPTS).iterdir()):
            if path.name.endswith(_INPUTS_SUFFIX):
                receipt_id = path.name[: -len(_INPUTS_SUFFIX)]
                if not self._receipt_path(receipt_id).exists():
                    orphans.append(receipt_id)
        return StoreScan(abandoned_staging=staging, orphaned_inputs=tuple(orphans))

    # --- consumption --------------------------------------------------------------------------

    def consume_once(self, authorization):
        """Spend one authorization, atomically. Every later call fails."""
        value = authorization.value()
        nonce = value["nonce"]
        path = self._consumption_path(nonce)
        record = {"nonce": nonce, "authorization_id": value["authorization_id"],
                  "action_digest": value["action_digest"],
                  "rulebook_digest": value["rulebook_digest"],
                  "evidence_digest": value["evidence_digest"]}
        payload = canon.canonical_bytes(record)

        # Write the record in full, then publish it with one link. Creating the entry first and
        # writing into it afterwards would publish a name whose content does not exist yet, and a
        # second caller reading it in that window sees an empty file instead of the record it is
        # required to compare against. The link is the consumption point: it either creates a
        # complete entry or fails because one is already there.
        staged = self._stage_consumption(nonce, payload)
        try:
            os.link(staged, path)
        except FileExistsError:
            existing = _load_canonical(path)
            if existing != record:
                raise StoreConsumptionConflict(
                    "A different authorization already consumed this nonce.") from None
            raise AuthorizationNonceReused(
                "This authorization's nonce has already been consumed.") from None
        except OSError as failure:
            raise StoreCommitConflict(
                "The consumption record could not be committed: " + str(failure)) from None
        finally:
            # Safe here, unlike the index publish: `link` adds a second name rather than moving
            # this one, so the staging slot is still held by this caller and no one else can have
            # taken it. Publishing by rename would make this unlink destroy another writer's slot.
            staged.unlink(missing_ok=True)
        return ConsumptionRecord(nonce=nonce, authorization_id=record["authorization_id"],
                                 action_digest=record["action_digest"])

    def _stage_consumption(self, nonce, payload):
        """Write the record's exact bytes to a staging path this caller alone holds.

        The slot is found by the same exclusive creation the publish uses, so two callers racing
        for one nonce never share a staging file and nothing names it from a clock, a process id,
        or randomness. An abandoned slot is reported by `scan`, never silently reused.
        """
        digest = _nonce_digest(nonce)
        for slot in range(_MAX_CONSUMPTION_SLOTS):
            staged = self.root / _TMP / ("consume-%s.%d" % (digest, slot))
            try:
                descriptor = os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                continue
            except OSError as failure:
                raise StoreCommitConflict(
                    "The consumption record could not be staged: " + str(failure)) from None
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
            return staged
        raise StoreCommitConflict(
            "Every consumption staging slot for this nonce is occupied; scan the store.")

    def is_consumed(self, nonce):
        return self._consumption_path(nonce).exists()

    # --- paths --------------------------------------------------------------------------------

    def _receipt_path(self, receipt_id):
        return self.root / _RECEIPTS / (receipt_id + ".json")

    def _inputs_path(self, receipt_id):
        return self.root / _RECEIPTS / (receipt_id + _INPUTS_SUFFIX)

    def _consumption_path(self, nonce):
        return self.root / _CONSUMED / (_nonce_digest(nonce) + ".json")

    def _summaries_from_records(self):
        summaries = []
        for path in sorted((self.root / _RECEIPTS).glob("*.json")):
            _reject_symlink(path)
            value = _load_canonical(path)
            block = value["signature"]
            summaries.append(ReceiptSummary(
                receipt_id=value["receipt_id"], created_at=value["created_at"],
                outcome=value["result"]["outcome"],
                rulebook_id=value["rulebook"]["rulebook_id"],
                rulebook_version=value["rulebook"]["version"],
                authorization_id=value.get("authorization_id"), key_id=block["key_id"]))
        return tuple(sorted(summaries, key=lambda s: (s.created_at, s.receipt_id)))

    def _refresh_index(self):
        """Rebuild the cache from the committed records, tolerating its own failure.

        A committed record must never be reported as uncommitted because a cache write raced, a
        disk filled, or an unrelated historical record turned out to be unreadable, so nothing
        here propagates. The refresh reads every committed receipt, which means it can fail for a
        reason that has nothing to do with the record just written — and a `VerifyError` from
        that scan travelling outward would revoke a commit the rename already made, which
        `spec/local-store.md` forbids. A stale cache is corrected by the next listing, which
        reconciles against the records; a corrupt record stays present and is still refused
        there, by name.
        """
        try:
            self._write_index(self._summaries_from_records())
        except (OSError, VerifyError):
            pass

    def _write_index(self, summaries):
        document = {"store_format_version": STORE_FORMAT_VERSION,
                    "receipts": [{"receipt_id": s.receipt_id, "created_at": s.created_at,
                                  "outcome": s.outcome, "rulebook_id": s.rulebook_id,
                                  "rulebook_version": s.rulebook_version,
                                  "authorization_id": s.authorization_id, "key_id": s.key_id}
                                 for s in summaries]}
        # A staging path this writer alone holds. One shared name meant two concurrent writers
        # published over each other: the loser renamed a file the winner had already moved, and
        # a raw error escaped from a cache write onto an already committed record.
        staging = self._index_staging_slot()
        try:
            _write_exact(staging, canon.canonical_bytes(document))
            # The rename consumes the staging name, which frees the slot for the next writer.
            # Nothing may unlink it afterwards: by then the name can belong to someone else, and
            # removing it would let two writers hold one slot and tear each other's bytes.
            staging.replace(self.root / _INDEX)
        except BaseException:
            # The rename did not happen, so this slot is still ours to clean up.
            staging.unlink(missing_ok=True)
            raise

    def _index_staging_slot(self):
        """Find a free index staging slot by the same exclusive creation the commit uses.

        Deterministic: no clock, no process id, no randomness names a path under this root.
        """
        for slot in range(_MAX_INDEX_SLOTS):
            staging = self.root / _TMP / ("index.%d.staging" % slot)
            try:
                os.close(os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError:
                continue
            return staging
        raise StoreCommitConflict(
            "Every index staging slot is occupied; scan the store.")


def _check_storable(receipt_id):
    if not isinstance(receipt_id, str):
        raise TypeError("a receipt id must be a string")
    if not STORABLE_ID.match(receipt_id) or receipt_id in (".", ".."):
        raise StorePathInvalid(
            "This receipt id cannot be stored as a filename: " + repr(receipt_id))


def _receipt_outcome(value):
    """Read the outcome without trusting the file to be a receipt at all.

    Full schema validation happens inside replay; this guard exists so a stored file that is
    canonical JSON but structurally something else cannot leak a KeyError across the boundary.
    """
    try:
        outcome = value["result"]["outcome"]
    except (TypeError, KeyError):
        raise StoreRecordIncomplete(
            "The stored receipt file is not a receipt.") from None
    if not isinstance(outcome, str):
        raise StoreRecordIncomplete("The stored receipt file is not a receipt.")
    return outcome


def _reject_symlink(path):
    if path.is_symlink():
        raise StorePathInvalid("A symlink is not permitted in the store layout: " + str(path))


def _nonce_digest(nonce):
    """A caller-supplied nonce has no pattern and never reaches the filesystem as a path."""
    if not isinstance(nonce, str):
        raise TypeError("a nonce must be a string")
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def _write_exact(path, payload):
    with open(path, "wb") as handle:
        handle.write(payload)


def _load_canonical(path):
    """Strict-load a stored file and require its bytes to be the canonical form."""
    raw = path.read_bytes()
    value = load.load_json_bytes(raw)
    if canon.canonical_bytes(value) != raw:
        raise StoreArtifactNoncanonical("Stored bytes are not canonical: " + str(path))
    return value
