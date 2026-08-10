"""Local artifact store, per spec/local-store.md.

Persists the exact artifacts a later process needs to verify and replay a decision.

**The store is not a trust anchor.** A file being local proves nothing: every load re-verifies
signatures and re-runs replay against caller-supplied keys, exactly as if the bytes had arrived
from a stranger. The store never evaluates, authorizes, issues, or executes anything, and reads no
clock, randomness, environment, or network.
"""

import errno
import hashlib
import json
import os
import re
import stat
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
# An action that executed but whose record could not be committed. Under `tmp/` on
# purpose: it is evidence that something happened, not a committed record of it.
_UNRECORDED_SUFFIX = ".unrecorded.json"
# A receipt is a bounded document. Nothing in the store reads more than this from an
# untrusted entry, so a local file cannot decide how much memory a listing allocates.
# Derived from the envelope: identifiers, three digests, a result with its reason trace,
# and one signature — orders of magnitude below this. A product bound, not a host one.
MAX_RECEIPT_BYTES = 1 << 20
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
class RefusedRecord:
    """One artifact in the receipts directory that a listing would not read.

    Named rather than hidden, and never deleted. A damaged artifact is a fact about that file
    alone: it is reported by filename so the repair is obvious, and it does not decide what the
    listing may say about every other record.
    """

    filename: str
    code: str
    message: str


@dataclass(frozen=True)
class ReceiptListing:
    """What a listing found: the records it could read, and the artifacts it refused."""

    summaries: tuple
    refused: tuple


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
    """One local store root, opened either to write to or only to look at.

    The two are different objects and not one object in two moods. A store opened for reading
    creates nothing, and the only method that can create the layout is unreachable from it — so
    "does `receipts list` initialize a store?" is answered by which constructor ran, not by
    auditing every path a listing might take.
    """

    def __init__(self, root):
        """Open the store for writing, creating the declared layout if it is not there."""
        self.root = _store_root(root)
        self._writable = True
        self._initialize_layout()

    @classmethod
    def for_reading(cls, root):
        """Open an existing store to read. Creates nothing, repairs nothing, migrates nothing.

        A missing layout member is reported, never supplied: a command that only reads must be
        unable to leave a trace, and a store that has lost `receipts/` has a problem worth being
        told about rather than one worth papering over on the way past.
        """
        store = cls.__new__(cls)
        store.root = _store_root(root)
        store._writable = False
        store._require_layout()
        return store

    def _initialize_layout(self):
        """The only place in this class that creates anything at the layout level."""
        root = self.root
        for child in (root, root / _RECEIPTS, root / _CONSUMED, root / _TMP):
            child.mkdir(parents=True, exist_ok=True)
            _reject_symlink(child)
        marker = root / _STORE
        if _entry_kind(marker) is None:
            _write_exact(marker, canon.canonical_bytes(
                {"store_format_version": STORE_FORMAT_VERSION}))
        _require_regular(marker)

    def _require_layout(self):
        """Say what the layout is missing or what has replaced it. Supplies nothing."""
        _require_directory(self.root, StorePathInvalid(
            "There is no store at " + str(self.root)))
        _require_directory(self.root / _RECEIPTS, StorePathInvalid(
            "The store has no receipts directory: " + str(self.root / _RECEIPTS)))
        _require_regular(self.root / _STORE)

    # --- writing ------------------------------------------------------------------------------

    def put_record(self, frozen_receipt, pinned, candidate, snapshot, authorization=None):
        """Commit one record. The receipt file's rename is the commit point."""
        receipt_id = frozen_receipt.receipt_id
        _check_storable(receipt_id)
        bodies = self._bodies(frozen_receipt, pinned, candidate, snapshot, authorization)

        final_receipt = self._receipt_path(receipt_id)
        final_inputs = self._inputs_path(receipt_id)

        # `_entry_kind` and not `exists()`: a link planted at this name is an entry that is in the
        # way, and following it would let a commit be redirected out of the store.
        if _entry_kind(final_receipt) is not None:
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

            if _entry_kind(final_inputs) is not None:
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
        existing = _require_store_file(
            self._receipt_path(receipt_id),
            StoreRecordMissing("No committed record for " + receipt_id))
        if existing != frozen_receipt.canonical_bytes:
            raise StoreRecordConflict(
                "A different receipt is already stored under " + receipt_id)
        inputs = self._inputs_path(receipt_id)
        for name, text in bodies.items():
            stored = _require_store_file(
                inputs / (name + ".json"),
                StoreRecordIncomplete("Stored record is missing " + name))
            if stored != text.encode("utf-8"):
                raise StoreRecordConflict("A different " + name + " is stored under " + receipt_id)
        return self.get_record(receipt_id, verify=False)

    # --- reading ------------------------------------------------------------------------------

    def get_record(self, receipt_id, receipt_keys=None, registry=None,
                   authorization_keys=None, verification_time=None, verify=True):
        """Load and re-verify one committed record. Local bytes are never trusted as such."""
        _check_storable(receipt_id)
        receipt_path = self._receipt_path(receipt_id)
        # Absence is decided by the same open that classifies the entry: a link to nothing is a
        # link, not a missing record, and saying "no committed record" of one would let a store be
        # emptied by planting symlinks.
        receipt_value = _load_canonical(
            receipt_path, StoreRecordMissing("No committed record for " + receipt_id))
        outcome = _receipt_outcome(receipt_value)
        inputs = self._inputs_path(receipt_id)
        _require_directory(inputs, StoreRecordIncomplete(
            "Record has no inputs directory: " + receipt_id))

        required = ["rulebook", "candidate", "snapshot"]
        if outcome == "ALLOW" and receipt_value.get("authorization_id") is not None:
            required.append("authorization")
        loaded = {}
        for name in required:
            loaded[name] = _load_canonical(
                inputs / (name + ".json"),
                StoreRecordIncomplete("Record is missing " + name + ".json"))
        for name in _BODY_NAMES:
            if name not in required and _entry_kind(inputs / (name + ".json")) is not None:
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
        """The summaries a listing could read. `listing()` also names what it refused."""
        return self.listing().summaries

    def listing(self):
        """What the committed records say, and which artifacts could not be read.

        One rule, applied to every file this reads: **no single damaged artifact may make the
        listing unavailable, and no damaged artifact may pass as healthy.** Each one is named by
        filename with the code that refused it, the rest of the listing is still answered, and
        nothing is deleted or repaired here.

        The answer is derived from the records rather than from the index, and that is the
        correction rather than an oversight. The reconciliation this used to perform compares
        *identities*, which a record damaged after it was indexed still has — so the cache
        answered for a file it could not see was unreadable, while a single unreadable file
        anywhere ended the whole listing. Only a scan can say both things truthfully. The index
        stays exactly what `spec/local-store.md` calls it, an optimization and never an
        authority; it is maintained by `put_record` and rebuilt by `rebuild_index`, and a listing
        neither believes it nor writes it.
        """
        listing = self._listing_from_records()
        problem = self._index_problem()
        return listing if problem is None else ReceiptListing(
            summaries=listing.summaries, refused=listing.refused + (problem,))

    def _index_problem(self):
        """Refuse the cache by name if it is unusable. An absent index is not a fault.

        `exists()` may not ask the first question here. It follows links, so it answers *false*
        for a dangling symlink — and a store whose cache has been replaced by a link to nothing
        would report a clean listing with no cache at all. The distinction that matters is
        whether a **directory entry** is there, which only an open that follows nothing can make:
        no entry is an absence, and an entry that is a link is a fault whatever it points at.
        """
        index_path = self.root / _INDEX
        try:
            raw = read_store_file(index_path)
            if raw is None:
                return None               # a store that has committed nothing has no cache
            _check_index(raw)
        except VerifyError as typed:
            return RefusedRecord(_INDEX, typed.code, str(typed))
        except OSError as failure:
            return RefusedRecord(_INDEX, StoreIndexInvalid.code,
                                 "The index could not be read: " + str(failure))
        return None

    def rebuild_index(self):
        listing = self._listing_from_records()
        self._write_index(listing.summaries)
        return listing.summaries

    def scan(self):
        """Report what is present but not committed. Nothing is deleted."""
        staging = tuple(p.name for p in _entries(self.root / _TMP))
        orphans = []
        for path in _entries(self.root / _RECEIPTS):
            if path.name.endswith(_INPUTS_SUFFIX):
                receipt_id = path.name[: -len(_INPUTS_SUFFIX)]
                if _entry_kind(self._receipt_path(receipt_id)) is None:
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

    def preserve_unrecorded(self, frozen_receipt):
        """Keep the signed receipt for an action that happened but could not be committed.

        Below the consume line the world may already have changed and the authority is spent, so
        the signed account of it is the only thing left that can still be true. Losing it made
        `receipts list` answer "no receipts yet" about a command that had run — the store denying
        what the runtime did, which is the one thing a record keeper may never do.

        This is **not** a committed record and must never be mistaken for one. It lives under
        `tmp/`, so `list_receipts` (which globs `receipts/`) cannot see it and `scan` reports it
        as present-but-uncommitted, exactly like any other artifact that is on disk without
        having reached the commit point.

        Returns the path written, or raises. The caller is already handling a failure; this one
        is allowed to fail too, and says so rather than pretending.
        """
        receipt_id = frozen_receipt.receipt_id
        _check_storable(receipt_id)
        path = self.root / _TMP / (receipt_id + _UNRECORDED_SUFFIX)
        payload = frozen_receipt.canonical_bytes
        # Whatever is already at this path is untrusted local input, exactly like a committed
        # receipt is, and it is read through the same primitive rather than a weaker local one.
        # A FIFO here used to block the process until a writer appeared, and a directory escaped
        # as a raw IsADirectoryError.
        preserved = read_store_file(path)
        if preserved is not None:
            # Idempotent on identical bytes; a different receipt under one id is a conflict, not
            # something to overwrite. Nothing here destroys an earlier account of an action.
            if preserved != payload:
                raise StoreRecordConflict(
                    "A different unrecorded receipt is already preserved under " + receipt_id)
            return path
        staging = self.root / _TMP / (receipt_id + _UNRECORDED_SUFFIX + ".partial")
        try:
            descriptor = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError as failure:
            # Exclusive creation refuses anything already standing there, hostile or merely
            # abandoned. Typed, so it is a store condition rather than a host traceback.
            raise StoreCommitConflict(
                "The unrecorded receipt could not be staged: %s" % failure) from None
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
            staging.replace(path)          # the rename is the point at which it exists at all
        except OSError as failure:
            staging.unlink(missing_ok=True)
            raise StoreCommitConflict(
                "The unrecorded receipt could not be preserved: %s" % failure) from None
        except BaseException:
            staging.unlink(missing_ok=True)
            raise
        return path

    def unrecorded_path(self, receipt_id):
        """Where an unrecorded receipt for this id would be kept. Reads nothing."""
        _check_storable(receipt_id)
        return self.root / _TMP / (receipt_id + _UNRECORDED_SUFFIX)

    def is_consumed(self, nonce):
        # `_entry_kind` and not `exists()`: a link to nothing is still an entry, and answering
        # "not consumed" about one would be a way to make a spent authorization look unspent.
        return _entry_kind(self._consumption_path(nonce)) is not None

    # --- paths --------------------------------------------------------------------------------

    def _receipt_path(self, receipt_id):
        return self.root / _RECEIPTS / (receipt_id + ".json")

    def _inputs_path(self, receipt_id):
        return self.root / _RECEIPTS / (receipt_id + _INPUTS_SUFFIX)

    def _consumption_path(self, nonce):
        return self.root / _CONSUMED / (_nonce_digest(nonce) + ".json")

    def _listing_from_records(self):
        """Read every committed receipt, keeping the ones that read and naming the ones that do not.

        A refusal is scoped to its own file. Nothing is deleted, nothing is repaired, and nothing
        about a damaged artifact is inferred onto its neighbours.
        """
        summaries, refused = [], []
        for path in _entries(self.root / _RECEIPTS):
            if path.suffix != ".json":
                continue
            try:
                summaries.append(_summary_of(path))
            except VerifyError as typed:
                refused.append(RefusedRecord(path.name, typed.code, str(typed)))
            except OSError as failure:
                refused.append(RefusedRecord(
                    path.name, StoreRecordIncomplete.code,
                    "The stored receipt file could not be read: " + str(failure)))
        return ReceiptListing(
            summaries=tuple(sorted(summaries, key=lambda s: (s.created_at, s.receipt_id))),
            refused=tuple(refused))

    def _refresh_index(self):
        """Rebuild the cache from the committed records, tolerating its own failure.

        A committed record must never be reported as uncommitted because a cache write raced, a
        disk filled, or an unrelated historical record turned out to be unreadable, so nothing
        here propagates. The scan itself no longer refuses on a damaged historical record — it
        names it and carries on — but the write can still fail for reasons that have nothing to
        do with the record just committed, and either failure travelling outward would revoke a
        commit the rename already made, which `spec/local-store.md` forbids. A stale cache is
        corrected by the next listing; a damaged record stays present, is named by any listing
        that scans, and is still refused by `get_record`.
        """
        try:
            self._write_index(self._listing_from_records().summaries)
        except (OSError, VerifyError):
            pass

    def _write_index(self, summaries):
        # Checked here rather than only where the cache is read: the publish below renames over
        # this name, and renaming over a symlink is how a store would be made to remove one.
        _reject_symlink(self.root / _INDEX)
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



def _store_root(root):
    if not isinstance(root, Path):
        raise TypeError("store root must be a pathlib.Path")
    _reject_symlink(root)
    return root


def _require_directory(path, absent):
    """Require a real directory at this name, following nothing. `absent` says what is missing."""
    info = _entry_kind(path)
    if info is None:
        raise absent
    if stat.S_ISLNK(info.st_mode):
        raise StorePathInvalid("A symlink is not permitted in the store layout: " + str(path))
    if not stat.S_ISDIR(info.st_mode):
        raise StorePathInvalid("Not a directory: " + str(path))
    return info


def _entries(directory):
    """List a store directory, or say plainly that it could not be listed.

    `Path.glob` answers an unreadable directory with an empty iterator, and an empty iterator is
    how a store says *there is nothing here*. Those are different sentences and this product does
    not merge them anywhere else either.
    """
    try:
        with os.scandir(directory) as found:
            return sorted(Path(entry.path) for entry in found)
    except FileNotFoundError:
        raise StorePathInvalid(
            "The store has no receipts directory: " + str(directory)) from None
    except OSError as failure:
        raise StorePathInvalid(
            "The store directory could not be listed: %s" % failure) from None


def _entry_kind(path):
    """lstat once and say what is there, following nothing. None when absent.

    One observation, one object. `Path.is_file()` follows symlinks and is a *different* look at
    the filesystem from the read that follows it, so a check-then-read pair can be given two
    different objects. Everything that matters is decided from this single lstat.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as failure:
        raise StorePathInvalid("The store entry could not be examined: %s" % failure) from None
    return info


def _require_regular(path, info=None):
    """Refuse any store entry that is not a plain regular file, before reading a byte.

    A FIFO at a receipt path blocks the reader until a writer appears — a local file that hangs
    the command. A directory raises `IsADirectoryError`, a device reads unbounded. None of these
    may reach a read, and none may escape as a raw host exception.
    """
    info = _entry_kind(path) if info is None else info
    if info is None:
        return None
    if stat.S_ISLNK(info.st_mode):
        raise StorePathInvalid("A symlink is not permitted in the store layout: " + str(path))
    if not stat.S_ISREG(info.st_mode):
        raise StorePathInvalid("Not a regular file: " + str(path))
    if info.st_size > MAX_RECEIPT_BYTES:
        raise StoreArtifactNoncanonical(
            "The stored file is larger than a receipt may be: " + str(path))
    return info


# `O_NOFOLLOW` decides the symlink question inside the open itself, and `O_NONBLOCK` stops a FIFO
# from parking the process there. Both are POSIX; where a host lacks either, the flag is absent
# and the guarantee below narrows to what `_require_regular` can say from an lstat alone. That
# narrowing is stated in spec/local-store.md rather than assumed away.
_NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NON_BLOCKING = getattr(os, "O_NONBLOCK", 0)
_FOLLOWS_NOTHING = bool(_NO_FOLLOW)


def read_store_file(path, bound=None):
    """Read one untrusted store entry, or refuse it. `None` means no directory entry exists.

    The whole point is that **one object is classified, opened, and read**. `is_file()` then
    `read_bytes()` is two separate looks at a name, and a name can be made to refer to two
    different objects between them; so can `stat()` then `open()`. Here the open is the
    classification: `O_NOFOLLOW` refuses a symlink as part of acquiring the descriptor, and every
    later question — kind, size, contents — is asked of *that descriptor*, never of the path again.

    A dangling symlink is therefore a symlink and not an absence, which is the distinction
    `exists()` cannot make and the one a hostile store depends on.

    The race this closes is between classification and read. It does not make the enclosing
    directories immutable: a parent component may still be swapped before the open resolves, and
    the store does not claim otherwise.
    """
    bound = MAX_RECEIPT_BYTES if bound is None else bound
    try:
        descriptor = os.open(path, os.O_RDONLY | _NO_FOLLOW | _NON_BLOCKING)
    except FileNotFoundError:
        return None
    except IsADirectoryError:
        raise StorePathInvalid("Not a regular file: " + str(path)) from None
    except OSError as failure:
        if failure.errno in (errno.ELOOP, errno.EMLINK):
            raise StorePathInvalid(
                "A symlink is not permitted in the store layout: " + str(path)) from None
        raise StorePathInvalid(
            "The store entry could not be opened: %s" % failure) from None
    try:
        info = os.fstat(descriptor)
        if stat.S_ISLNK(info.st_mode):                       # only reachable without O_NOFOLLOW
            raise StorePathInvalid(
                "A symlink is not permitted in the store layout: " + str(path))
        if not stat.S_ISREG(info.st_mode):
            raise StorePathInvalid("Not a regular file: " + str(path))
        if info.st_size > bound:
            # Refused from the descriptor's own size, before any allocation proportional to it.
            raise StoreArtifactNoncanonical(
                "The stored file is larger than a receipt may be: " + str(path))
        raw = _read_bounded(descriptor, bound)
    finally:
        os.close(descriptor)
    return raw


def _read_bounded(descriptor, bound):
    """Read at most `bound` bytes and refuse a file that grew past it while being read."""
    chunks, total = [], 0
    while True:
        try:
            chunk = os.read(descriptor, 65536)
        except OSError as failure:
            raise StorePathInvalid("The store entry could not be read: %s" % failure) from None
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > bound:
            raise StoreArtifactNoncanonical("The stored file is larger than a receipt may be.")
        chunks.append(chunk)


def _require_store_file(path, absent):
    """`read_store_file`, but an absent entry is the caller's own typed refusal."""
    raw = read_store_file(path)
    if raw is None:
        raise absent
    return raw


def _check_storable(receipt_id):
    if not isinstance(receipt_id, str):
        raise TypeError("a receipt id must be a string")
    if not STORABLE_ID.match(receipt_id) or receipt_id in (".", ".."):
        raise StorePathInvalid(
            "This receipt id cannot be stored as a filename: " + repr(receipt_id))


def _check_index(raw):
    """Refuse a cache that is not the document this store writes. Nothing is believed from it."""
    try:
        value = load.load_json_bytes(raw)
    except VerifyError:
        raise StoreIndexInvalid("The index is not a canonical JSON document.") from None
    if not isinstance(value, dict) or "receipts" not in value:
        raise StoreIndexInvalid("The index has no receipts array.")
    if not isinstance(value["receipts"], list):
        raise StoreIndexInvalid("The index has no receipts array.")
    for entry in value["receipts"]:
        if not isinstance(entry, dict) or set(entry) != {
                "receipt_id", "created_at", "outcome", "rulebook_id", "rulebook_version",
                "authorization_id", "key_id"}:
            raise StoreIndexInvalid("An index entry has unexpected fields.")


def _summary_of(path):
    """Summarize one committed receipt file, or refuse it.

    Nothing here verifies a signature or replays anything — a summary is a convenience over bytes
    the store never treats as trustworthy. What it does guarantee is that a file which is not a
    receipt cannot leave this function as anything but a typed refusal: a raw `KeyError` from a
    foreign document would cross the store boundary and be reported as an internal defect.
    """
    value = _load_canonical(path, StoreRecordMissing("No committed receipt at " + path.name))
    try:
        summary = ReceiptSummary(
            receipt_id=value["receipt_id"], created_at=value["created_at"],
            outcome=value["result"]["outcome"],
            rulebook_id=value["rulebook"]["rulebook_id"],
            rulebook_version=value["rulebook"]["version"],
            authorization_id=value.get("authorization_id"),
            key_id=value["signature"]["key_id"])
    except (TypeError, KeyError, IndexError, AttributeError):
        raise StoreRecordIncomplete(
            "The stored receipt file is not a receipt: " + path.name) from None
    for name in ("receipt_id", "created_at", "outcome", "rulebook_id", "rulebook_version",
                 "key_id"):
        if not isinstance(getattr(summary, name), str):
            # Every listed field is ordered, compared, or printed. A number where a string
            # belongs would sort against its neighbours and fail there instead of here.
            raise StoreRecordIncomplete(
                "The stored receipt file is not a receipt: " + path.name)
    if summary.authorization_id is not None and not isinstance(summary.authorization_id, str):
        raise StoreRecordIncomplete("The stored receipt file is not a receipt: " + path.name)
    return summary


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


def _load_canonical(path, absent=None):
    """Strict-load a stored file and require its bytes to be the canonical form.

    Every byte arrives through `read_store_file`, so a non-regular or oversized entry is refused
    before there is anything to parse.
    """
    raw = read_store_file(path)
    if raw is None:
        raise absent or StoreRecordMissing("No stored file at " + str(path))
    value = load.load_json_bytes(raw)
    if canon.canonical_bytes(value) != raw:
        raise StoreArtifactNoncanonical("Stored bytes are not canonical: " + str(path))
    return value
