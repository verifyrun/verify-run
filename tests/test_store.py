"""Closure Unit 10 — local artifact store, exact bodies, indexing, atomic consumption."""

import copy
import dataclasses
import json
import pathlib
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vfy import authorization, canon, gate, load, receipt, rulebook, schema, snapshot, store
from vfy.errors import VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
RECEIPT_DIR = REPO_ROOT / "fixtures" / "receipts"

AUTH_SEED = bytes(range(32))
RECEIPT_SEED = bytes(range(64, 96))
FROZEN_AT = "2026-08-05T00:00:00Z"


def _public(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _receipt_keys():
    return {("receipt-key", 1): {"public_key": _public(RECEIPT_SEED), "status": "active"}}


def _auth_keys():
    return authorization.build_key_registry(
        [{"key_id": "auth-key", "key_version": 1, "public_key": _public(AUTH_SEED)}])


class Built:
    """One complete governed computation, rebuilt from a Unit 9 receipt fixture."""

    def __init__(self, fixture, registry, receipt_id="r-1"):
        case = json.loads((RECEIPT_DIR / fixture).read_text(encoding="utf-8"))
        self.registry = registry
        self.case = case
        self.pinned = rulebook.load_rulebook_bytes(
            case["rulebook_source"].encode("utf-8"), registry)
        self.candidate = case["candidate"]
        self.snapshot = snapshot.build_snapshot(self.pinned, "s-1", FROZEN_AT,
                                                case["acquisitions"], registry)
        self.result = gate.evaluate(self.pinned, self.candidate, self.snapshot.value(),
                                    registry)
        self.authorization = None
        execution = None
        if self.result.outcome == "ALLOW":
            self.authorization = authorization.issue_authorization(
                self.pinned, self.candidate, self.snapshot, self.result, "auth-1",
                "n" * 16, "runtime-1", FROZEN_AT, "auth-key", 1, AUTH_SEED, registry)
            execution = case["receipt"].get("execution")
        self.receipt = receipt.issue_receipt(
            self.pinned, self.candidate, self.snapshot, self.result, self.authorization,
            execution, receipt_id, "2026-08-05T00:00:0%d Z".replace(" ", "")[:20]
            if False else "2026-08-05T00:00:06Z",
            "receipt-key", 1, RECEIPT_SEED, registry)

    def put(self, local):
        return local.put_record(self.receipt, self.pinned, self.candidate, self.snapshot,
                                self.authorization)


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.registry = _registry()
        self.parent = pathlib.Path(tempfile.mkdtemp())
        self.root = self.parent / "store"
        self.store = store.LocalStore(self.root)

    def tearDown(self):
        shutil.rmtree(self.parent, ignore_errors=True)

    def build(self, fixture="accept_allow_with_authorization_and_execution.json",
              receipt_id="r-1"):
        return Built(fixture, self.registry, receipt_id)

    def load(self, receipt_id, **overrides):
        arguments = dict(receipt_keys=_receipt_keys(), registry=self.registry,
                         authorization_keys=_auth_keys(),
                         verification_time="2026-08-05T00:01:00Z")
        arguments.update(overrides)
        return self.store.get_record(receipt_id, **arguments)


class Layout(StoreTestCase):
    def test_an_empty_store_initializes_the_declared_layout(self):
        for child in ("receipts", "consumed", "tmp"):
            self.assertTrue((self.root / child).is_dir())
        marker = load.load_json_bytes((self.root / "store.json").read_bytes())
        self.assertEqual(marker["store_format_version"], store.STORE_FORMAT_VERSION)

    def test_the_layout_follows_the_execution_chain_convention(self):
        self.build().put(self.store)
        self.assertTrue((self.root / "receipts" / "r-1.json").is_file())
        inputs = self.root / "receipts" / "r-1.inputs"
        self.assertTrue(inputs.is_dir())
        self.assertEqual(sorted(p.name for p in inputs.iterdir()),
                         ["authorization.json", "candidate.json", "rulebook.json",
                          "snapshot.json"])

    def test_stored_bytes_are_exactly_canonical_with_no_trailing_newline(self):
        built = self.build()
        built.put(self.store)
        receipt_bytes = (self.root / "receipts" / "r-1.json").read_bytes()
        self.assertEqual(receipt_bytes, built.receipt.canonical_bytes)
        self.assertFalse(receipt_bytes.endswith(b"\n"))
        for name, expected in (("rulebook", built.pinned.canonical),
                               ("snapshot", built.snapshot.canonical),
                               ("candidate", canon.canonicalize(built.candidate)),
                               ("authorization", built.authorization.canonical)):
            with self.subTest(body=name):
                path = self.root / "receipts" / "r-1.inputs" / (name + ".json")
                self.assertEqual(path.read_bytes(), expected.encode("utf-8"))
                self.assertFalse(path.read_bytes().endswith(b"\n"))


class RoundTrip(StoreTestCase):
    FIXTURES = ("accept_allow_with_authorization_and_execution.json",
                "accept_block_decision.json", "accept_hold_decision.json")

    def test_every_terminal_decision_stores_and_reloads_with_full_replay(self):
        for index, fixture in enumerate(self.FIXTURES):
            with self.subTest(fixture=fixture):
                built = self.build(fixture, receipt_id="r-%d" % index)
                built.put(self.store)
                loaded = self.load("r-%d" % index)
                self.assertTrue(loaded.replay_verified)
                self.assertEqual(loaded.outcome, built.result.outcome)
                self.assertEqual(loaded.receipt_canonical, built.receipt.canonical)

    def test_reload_through_a_freshly_constructed_store_after_restart(self):
        built = self.build()
        built.put(self.store)
        reopened = store.LocalStore(self.root)
        loaded = reopened.get_record("r-1", receipt_keys=_receipt_keys(),
                                     registry=self.registry,
                                     authorization_keys=_auth_keys(),
                                     verification_time="2026-08-05T00:01:00Z")
        self.assertTrue(loaded.replay_verified)
        self.assertTrue(loaded.authorization_verified)

    def test_a_negative_decision_stores_no_authorization(self):
        built = self.build("accept_block_decision.json")
        built.put(self.store)
        self.assertFalse((self.root / "receipts" / "r-1.inputs" / "authorization.json").exists())
        self.assertIsNone(self.load("r-1").authorization_canonical)

    def test_local_bytes_are_not_trusted_without_verification(self):
        built = self.build()
        built.put(self.store)
        with self.assertRaises(VerifyError) as caught:
            self.store.get_record("r-1", receipt_keys={}, registry=self.registry)
        self.assertEqual(caught.exception.code, "signing_key_unknown")

    def test_a_tampered_body_is_caught_on_load(self):
        built = self.build()
        built.put(self.store)
        path = self.root / "receipts" / "r-1.inputs" / "candidate.json"
        value = load.load_json_bytes(path.read_bytes())
        value["candidate_id"] = "tampered"
        path.write_bytes(canon.canonical_bytes(value))
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "replay_body_mismatch")

    def test_a_noncanonical_stored_file_is_refused(self):
        built = self.build()
        built.put(self.store)
        path = self.root / "receipts" / "r-1.inputs" / "candidate.json"
        path.write_bytes(json.dumps(load.load_json_bytes(path.read_bytes()),
                                    indent=2).encode("utf-8"))
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "store_artifact_noncanonical")


class IdempotenceAndCollision(StoreTestCase):
    def test_writing_the_same_record_twice_is_idempotent(self):
        built = self.build()
        first = built.put(self.store)
        second = built.put(self.store)
        self.assertEqual(first.receipt_canonical, second.receipt_canonical)
        self.assertEqual(len(self.store.list_receipts()), 1)

    def test_the_same_id_with_different_receipt_bytes_is_a_conflict(self):
        self.build().put(self.store)
        other = self.build("accept_block_decision.json", receipt_id="r-1")
        with self.assertRaises(VerifyError) as caught:
            other.put(self.store)
        self.assertEqual(caught.exception.code, "store_record_conflict")

    def test_the_same_id_with_a_different_body_is_a_conflict(self):
        built = self.build()
        built.put(self.store)
        (self.root / "receipts" / "r-1.inputs" / "candidate.json").write_bytes(
            canon.canonical_bytes({"candidate_id": "other", "kind": "command",
                                   "action": {"summary": "x"}}))
        with self.assertRaises(VerifyError) as caught:
            built.put(self.store)
        self.assertEqual(caught.exception.code, "store_record_conflict")

    def test_an_incomplete_record_is_not_idempotent(self):
        built = self.build()
        built.put(self.store)
        (self.root / "receipts" / "r-1.inputs" / "snapshot.json").unlink()
        with self.assertRaises(VerifyError) as caught:
            built.put(self.store)
        self.assertEqual(caught.exception.code, "store_record_incomplete")

    def test_a_missing_record_is_distinct_from_an_incomplete_one(self):
        with self.assertRaises(VerifyError) as caught:
            self.load("absent")
        self.assertEqual(caught.exception.code, "store_record_missing")
        self.build().put(self.store)
        (self.root / "receipts" / "r-1.inputs" / "rulebook.json").unlink()
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "store_record_incomplete")


class Index(StoreTestCase):
    def _three(self):
        for index, fixture in enumerate(RoundTrip.FIXTURES):
            self.build(fixture, receipt_id="r-%d" % index).put(self.store)

    def test_listing_is_deterministic(self):
        self._three()
        first = self.store.list_receipts()
        self.assertEqual(len(first), 3)
        self.assertEqual([s.receipt_id for s in first], sorted(s.receipt_id for s in first))
        for _ in range(3):
            self.assertEqual(self.store.list_receipts(), first)

    def test_the_index_is_rebuildable_and_subordinate(self):
        self._three()
        expected = self.store.list_receipts()
        (self.root / "index.json").unlink()
        self.assertEqual(self.store.list_receipts(), expected)
        self.assertEqual(self.store.rebuild_index(), expected)

    def test_a_malformed_index_is_refused_by_name_then_rebuilt(self):
        """The cache is never believed — and it never silences the records either.

        This asserted a raised `store_index_invalid` until the 0.1.x hardening pass. A damaged
        cache making every committed record unlistable is the same availability failure as a
        damaged record doing it, and the index is the artifact this store is most willing to
        throw away: rebuilding is the documented repair.
        """
        self._three()
        expected = self.store.rebuild_index()
        (self.root / "index.json").write_bytes(b'{"nope":1}')
        listing = self.store.listing()
        self.assertEqual(listing.summaries, expected)
        self.assertEqual([(r.filename, r.code) for r in listing.refused],
                         [("index.json", "store_index_invalid")])
        self.assertEqual(self.store.rebuild_index(), expected)
        self.assertEqual(self.store.listing().refused, ())

    def test_an_index_entry_with_unexpected_fields_is_refused_by_name(self):
        self._three()
        value = load.load_json_bytes((self.root / "index.json").read_bytes())
        value["receipts"][0]["extra"] = "field"
        (self.root / "index.json").write_bytes(canon.canonical_bytes(value))
        listing = self.store.listing()
        self.assertEqual(len(listing.summaries), 3)
        self.assertEqual([(r.filename, r.code) for r in listing.refused],
                         [("index.json", "store_index_invalid")])

    def test_records_govern_when_the_index_disagrees(self):
        self._three()
        stale = load.load_json_bytes((self.root / "index.json").read_bytes())
        stale["receipts"] = stale["receipts"][:1]
        (self.root / "index.json").write_bytes(canon.canonical_bytes(stale))
        # This asserted 1 until Unit 12's concurrency proof: it recorded what the code did rather
        # than what spec/local-store.md says. "If the index disagrees with the records, the
        # records govern" leaves no room for a listing to report a stale count it can see is wrong.
        self.assertEqual(len(self.store.list_receipts()), 3)     # the records, not the cache
        self.assertEqual(len(self.store.rebuild_index()), 3)
        self.assertEqual(len(self.store.list_receipts()), 3)

    def test_every_summary_field_comes_from_the_signed_receipt(self):
        built = self.build()
        built.put(self.store)
        summary = self.store.list_receipts()[0]
        value = built.receipt.value()
        self.assertEqual(summary.created_at, value["created_at"])
        self.assertEqual(summary.outcome, value["result"]["outcome"])
        self.assertEqual(summary.rulebook_id, value["rulebook"]["rulebook_id"])
        self.assertEqual(summary.authorization_id, value["authorization_id"])
        self.assertEqual(summary.key_id, value["signature"]["key_id"])


class Consumption(StoreTestCase):
    def test_first_consumption_succeeds_and_every_later_one_fails(self):
        built = self.build()
        self.assertFalse(self.store.is_consumed("n" * 16))
        record = self.store.consume_once(built.authorization)
        self.assertEqual(record.authorization_id, "auth-1")
        self.assertTrue(self.store.is_consumed("n" * 16))
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                with self.assertRaises(VerifyError) as caught:
                    self.store.consume_once(built.authorization)
                self.assertEqual(caught.exception.code, "authorization_nonce_reused")

    def test_an_identical_repeat_never_grants_a_second_right(self):
        built = self.build()
        self.store.consume_once(built.authorization)
        with self.assertRaises(VerifyError) as caught:
            self.store.consume_once(built.authorization)
        self.assertEqual(caught.exception.code, "authorization_nonce_reused")

    def test_a_different_authorization_reusing_a_nonce_is_a_conflict(self):
        built = self.build()
        self.store.consume_once(built.authorization)
        substitute = authorization.issue_authorization(
            built.pinned, built.candidate, built.snapshot, built.result, "auth-2",
            "n" * 16, "runtime-1", FROZEN_AT, "auth-key", 1, AUTH_SEED, self.registry)
        with self.assertRaises(VerifyError) as caught:
            self.store.consume_once(substitute)
        self.assertEqual(caught.exception.code, "store_consumption_conflict")

    def test_distinct_authorizations_consume_independently(self):
        built = self.build()
        for index in range(3):
            other = authorization.issue_authorization(
                built.pinned, built.candidate, built.snapshot, built.result,
                "auth-%d" % index, "nonce-%d" % index + "x" * 12, "runtime-1", FROZEN_AT,
                "auth-key", 1, AUTH_SEED, self.registry)
            with self.subTest(index=index):
                self.assertIsNotNone(self.store.consume_once(other))

    def test_consumption_survives_a_new_store_object(self):
        built = self.build()
        self.store.consume_once(built.authorization)
        self.assertTrue(store.LocalStore(self.root).is_consumed("n" * 16))

    def test_a_nonce_never_reaches_the_filesystem_as_a_path(self):
        built = self.build()
        self.store.consume_once(built.authorization)
        names = [p.name for p in (self.root / "consumed").iterdir()]
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"\A[0-9a-f]{64}\.json\Z")

    def test_consumption_records_no_invented_timestamp(self):
        built = self.build()
        self.store.consume_once(built.authorization)
        path = next((self.root / "consumed").iterdir())
        value = load.load_json_bytes(path.read_bytes())
        self.assertEqual(set(value), {"nonce", "authorization_id", "action_digest",
                                      "rulebook_digest", "evidence_digest"})
        self.assertNotIn("consumed_at", value)

    def test_consumption_does_not_prove_execution(self):
        # The record binds what was spent, not what happened. Nothing here observes the world.
        source = (REPO_ROOT / "vfy" / "store.py").read_text(encoding="utf-8")
        for banned in ("subprocess", "acknowledg", "exit_status"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)


class CrashRecovery(StoreTestCase):
    def test_an_orphaned_inputs_directory_is_not_committed(self):
        built = self.build()
        built.put(self.store)
        (self.root / "receipts" / "r-1.json").unlink()          # commit point removed
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "store_record_missing")
        self.assertEqual(self.store.scan().orphaned_inputs, ("r-1",))
        self.assertEqual(self.store.rebuild_index(), ())

    def test_abandoned_staging_is_reported_and_never_auto_deleted(self):
        staging = self.root / "tmp" / "r-1.staging"
        staging.mkdir()
        (staging / "candidate.json").write_bytes(b"{}")
        self.assertIn("r-1.staging", self.store.scan().abandoned_staging)
        built = self.build()
        with self.assertRaises(VerifyError) as caught:
            built.put(self.store)
        self.assertEqual(caught.exception.code, "store_commit_conflict")
        self.assertTrue(staging.exists())          # evidence preserved

    def test_partial_body_writes_never_become_committed(self):
        built = self.build()
        staging = self.root / "tmp" / "r-1.staging"
        staging.mkdir()
        (staging / "rulebook.json").write_bytes(built.pinned.canonical.encode("utf-8"))
        # Interruption after the first body write: no receipt file, so nothing is committed.
        self.assertFalse((self.root / "receipts" / "r-1.json").exists())
        with self.assertRaises(VerifyError):
            self.load("r-1")
        self.assertEqual(self.store.list_receipts(), ())

    def test_an_index_entry_without_a_record_is_never_believed(self):
        self.build().put(self.store)
        value = load.load_json_bytes((self.root / "index.json").read_bytes())
        value["receipts"].append(dict(value["receipts"][0], receipt_id="ghost"))
        (self.root / "index.json").write_bytes(canon.canonical_bytes(value))
        # This asserted 2 until Unit 12's concurrency proof — a listing naming a receipt that
        # does not exist. An index entry may never substitute for a committed record.
        self.assertEqual([s.receipt_id for s in self.store.list_receipts()], ["r-1"])
        self.assertEqual([s.receipt_id for s in self.store.rebuild_index()], ["r-1"])


class FilesystemAttacks(StoreTestCase):
    def test_path_traversal_identifiers_are_refused(self):
        for receipt_id in ("../escape", "..", ".", "a/b", "/absolute", "a\\b", "",
                           "x" * 200, ".hidden", "a b"):
            with self.subTest(receipt_id=receipt_id):
                with self.assertRaises(VerifyError) as caught:
                    self.store.get_record(receipt_id, receipt_keys=_receipt_keys(),
                                          registry=self.registry)
                self.assertEqual(caught.exception.code, "store_path_invalid")

    def test_a_symlinked_record_is_refused(self):
        built = self.build()
        built.put(self.store)
        target = self.root / "receipts" / "r-1.json"
        stolen = self.parent / "elsewhere.json"
        shutil.move(str(target), str(stolen))
        target.symlink_to(stolen)
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "store_path_invalid")

    def test_a_symlinked_body_is_refused(self):
        built = self.build()
        built.put(self.store)
        body = self.root / "receipts" / "r-1.inputs" / "candidate.json"
        stolen = self.parent / "candidate.json"
        shutil.move(str(body), str(stolen))
        body.symlink_to(stolen)
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "store_path_invalid")

    def test_a_symlinked_inputs_directory_is_refused(self):
        built = self.build()
        built.put(self.store)
        inputs = self.root / "receipts" / "r-1.inputs"
        stolen = self.parent / "inputs"
        shutil.move(str(inputs), str(stolen))
        inputs.symlink_to(stolen, target_is_directory=True)
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "store_path_invalid")

    def test_a_symlinked_index_is_refused(self):
        self.build().put(self.store)
        index = self.root / "index.json"
        stolen = self.parent / "index.json"
        shutil.move(str(index), str(stolen))
        index.symlink_to(stolen)

        # A listing names it and still answers from the records: a symlinked cache is one
        # unusable artifact, not a reason to make every committed record unreachable.
        listing = self.store.listing()
        self.assertEqual([s.receipt_id for s in listing.summaries], ["r-1"])
        self.assertEqual([(r.filename, r.code) for r in listing.refused],
                         [("index.json", "store_path_invalid")])
        # Writing is where a symlink is dangerous, and writing still refuses: a rename over this
        # name would remove the link and put the store's bytes wherever it pointed.
        with self.assertRaises(VerifyError) as caught:
            self.store.rebuild_index()
        self.assertEqual(caught.exception.code, "store_path_invalid")
        self.assertTrue(index.is_symlink(), "the link was followed or removed")

    def test_the_root_must_be_a_path_object(self):
        for root in ("/tmp/x", None, 5, b"/tmp/x"):
            with self.subTest(root=repr(root)):
                with self.assertRaises(TypeError):
                    store.LocalStore(root)

    def test_a_smuggled_authorization_on_a_negative_record_is_refused(self):
        built = self.build("accept_block_decision.json")
        built.put(self.store)
        allow = self.build(receipt_id="r-allow")
        (self.root / "receipts" / "r-1.inputs" / "authorization.json").write_bytes(
            allow.authorization.canonical.encode("utf-8"))
        with self.assertRaises(VerifyError) as caught:
            self.load("r-1")
        self.assertEqual(caught.exception.code, "store_record_conflict")


class PurityAndImmutability(StoreTestCase):
    def test_no_input_is_mutated(self):
        built = self.build()
        before = (copy.deepcopy(built.candidate), built.pinned.digest,
                  built.snapshot.digest, built.receipt.canonical)
        built.put(self.store)
        self.load("r-1")
        self.assertEqual(built.candidate, before[0])
        self.assertEqual(built.pinned.digest, before[1])
        self.assertEqual(built.snapshot.digest, before[2])
        self.assertEqual(built.receipt.canonical, before[3])

    def test_stored_records_and_summaries_are_immutable(self):
        built = self.build()
        record = built.put(self.store)
        self.assertTrue(dataclasses.is_dataclass(record))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            record.receipt_id = "tampered"
        summary = self.store.list_receipts()[0]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            summary.outcome = "ALLOW"
        borrowed = record.receipt()
        borrowed["receipt_id"] = "tampered"
        self.assertNotEqual(record.receipt(), borrowed)

    def test_the_store_reads_no_clock_environment_randomness_or_network(self):
        source = (REPO_ROOT / "vfy" / "store.py").read_text(encoding="utf-8")
        for banned in ("import time", "import datetime", "import random", "import secrets",
                       "urandom", "import socket", "urllib", "requests", "getenv(",
                       "os.environ", "expanduser", "home()", "float("):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)

    def test_the_store_cannot_change_a_decision(self):
        source = (REPO_ROOT / "vfy" / "store.py").read_text(encoding="utf-8")
        for banned in ("gate.evaluate", "issue_receipt", "issue_authorization",
                       "build_snapshot"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)


class ExceptionContainment(StoreTestCase):
    def test_malformed_trees_stay_typed(self):
        built = self.build()
        built.put(self.store)
        corruptions = [b"", b"{", b"not json", b"[]", b'{"a":1}', b"\xff\xfe",
                       b'{"receipt_id":"r-1"}']
        for payload in corruptions:
            (self.root / "receipts" / "r-1.json").write_bytes(payload)
            with self.subTest(payload=payload[:12]):
                try:
                    self.load("r-1")
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                    self.assertIsNotNone(typed.code)
                except Exception as untyped:
                    self.fail("%s crossed the boundary" % type(untyped).__name__)
                else:
                    self.fail("accepted corrupt receipt %r" % payload[:20])

    def test_a_corrupt_consumption_record_is_typed(self):
        built = self.build()
        path = self.store._consumption_path("n" * 16)
        path.write_bytes(b"not json")
        try:
            self.store.consume_once(built.authorization)
        except VerifyError as typed:
            self.assertIsNotNone(typed.code)
        except Exception as untyped:
            self.fail("%s crossed the boundary" % type(untyped).__name__)


if __name__ == "__main__":
    unittest.main()


class FrozenTrees(StoreTestCase):
    """The committed layout itself is a frozen contract."""

    STORE_DIR = REPO_ROOT / "fixtures" / "store"

    def test_every_frozen_tree_is_reproduced_exactly(self):
        import hashlib
        paths = sorted(self.STORE_DIR.glob("accept_tree_*.json"))
        self.assertEqual(len(paths), 3)
        for path in paths:
            case = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(fixture=path.name):
                parent = pathlib.Path(tempfile.mkdtemp())
                try:
                    root = parent / "s"
                    local = store.LocalStore(root)
                    Built(case["receipt_fixture"], self.registry,
                          receipt_id=case["receipt_id"]).put(local)
                    tree = {}
                    for entry in sorted(root.rglob("*")):
                        rel = str(entry.relative_to(root))
                        tree[rel] = ("dir" if entry.is_dir() else
                                     "sha256:" + hashlib.sha256(entry.read_bytes()).hexdigest())
                    self.assertEqual(tree, case["tree"])
                    self.assertEqual(
                        load.load_json_bytes((root / "index.json").read_bytes()), case["index"])
                finally:
                    shutil.rmtree(parent, ignore_errors=True)

    def test_the_frozen_consumption_record_is_reproduced(self):
        case = json.loads((self.STORE_DIR / "accept_consumption_record.json")
                          .read_text(encoding="utf-8"))
        built = self.build()
        self.store.consume_once(built.authorization)
        path = next((self.root / "consumed").iterdir())
        self.assertEqual(path.name, case["filename"])
        self.assertEqual(load.load_json_bytes(path.read_bytes()), case["record"])
        self.assertNotIn("consumed_at", case["record"])


class ConsumptionPublishAtomicity(StoreTestCase):
    """A consumption record's existence and its content must become visible together.

    Regression for the defect Unit 12's concurrency proof exposed: `consume_once` created the
    record's directory entry and wrote its bytes as two steps, so a second caller arriving in
    between read a zero-byte file and reported `source_syntax_invalid` instead of the
    `authorization_nonce_reused` spec/local-store.md declares. The exclusive creation was atomic;
    the *publication* was not.
    """

    # What a second caller may legitimately observe. Anything else means it read a record that
    # was not fully published.
    PERMITTED = {"CONSUMED", "authorization_nonce_reused", "store_consumption_conflict"}

    def _paused_writer(self, built, reached, release):
        """Run one consumption with a seam that holds it at its single payload write.

        Both the defective and the repaired implementations write the record's bytes through
        exactly one `os.fdopen`, so the same seam catches both — under the old code it pauses
        after the final entry exists, under the new one after only a staging file does.
        """
        import threading

        real_os = store.os
        holder = {}

        class Seam:
            def __getattr__(self, name):
                return getattr(real_os, name)

            def fdopen(self, *a, **k):
                if threading.get_ident() == holder.get("ident"):
                    reached.set()
                    release.wait(20)
                return real_os.fdopen(*a, **k)

        def writer():
            holder["ident"] = threading.get_ident()
            store.os = Seam()
            try:
                self.store.consume_once(built.authorization)
            finally:
                store.os = real_os

        return threading.Thread(target=writer, daemon=True)

    def test_no_caller_ever_observes_a_partially_published_record(self):
        import threading

        built = self.build()
        path = self.store._consumption_path("n" * 16)
        reached, release = threading.Event(), threading.Event()
        writer = self._paused_writer(built, reached, release)
        writer.start()
        try:
            self.assertTrue(reached.wait(20), "the seam never engaged")

            # 1. The direct invariant, checked at the paused instant.
            if path.exists():
                raw = path.read_bytes()
                self.assertNotEqual(raw, b"", "the record's entry exists with no content")
                self.assertEqual(load.load_json_bytes(raw),
                                 load.load_json_bytes(canon.canonical_bytes(
                                     load.load_json_bytes(raw))),
                                 "the record's entry exists with partial content")

            # 2. The public contract, checked by a real second caller in that same instant.
            try:
                self.store.consume_once(built.authorization)
                observed = "CONSUMED"
            except VerifyError as failure:
                observed = failure.code
            self.assertIn(observed, self.PERMITTED,
                          "a second caller read a record that was not fully published")
        finally:
            release.set()
            writer.join(20)

        # Whatever happened above, the nonce is spent exactly once from here on.
        with self.assertRaises(VerifyError) as caught:
            self.store.consume_once(built.authorization)
        self.assertEqual(caught.exception.code, "authorization_nonce_reused")

    def test_racing_threads_all_report_the_declared_reason(self):
        """Corroborating stress. The deterministic test above is what proves the invariant."""
        import concurrent.futures
        import threading

        built = self.build()
        for workers in (8, 32):
            with self.subTest(workers=workers):
                codes, winners = {}, []
                for round_index in range(15):
                    root = pathlib.Path(tempfile.mkdtemp(prefix="vfy-consume-race-"))
                    self.addCleanup(shutil.rmtree, root, ignore_errors=True)
                    racing = store.LocalStore(root)
                    # A fresh nonce per round, issued from the same governed computation, so
                    # each round is a clean race rather than a reuse of the previous one.
                    spent = authorization.issue_authorization(
                        built.pinned, built.candidate, built.snapshot, built.result, "auth-1",
                        "race-nonce-%09d" % round_index, "runtime-1", FROZEN_AT, "auth-key", 1,
                        AUTH_SEED, self.registry)
                    start = threading.Barrier(workers)

                    def attempt(_):
                        start.wait()
                        try:
                            racing.consume_once(spent)
                            return "CONSUMED"
                        except VerifyError as failure:
                            return failure.code

                    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
                        outcomes = list(pool.map(attempt, range(workers)))
                    winners.append(outcomes.count("CONSUMED"))
                    for code in outcomes:
                        if code != "CONSUMED":
                            codes[code] = codes.get(code, 0) + 1

                self.assertEqual(set(winners), {1}, "exactly one caller may consume")
                self.assertEqual(set(codes), {"authorization_nonce_reused"},
                                 "a loser reported something other than the declared reason")


class IndexIsSubordinate(StoreTestCase):
    """A committed record is authoritative. The index is a rebuildable cache and must never
    make a committed record look absent, look failed, or appear where no record exists.

    Regression for the defect found while proving the first repair: `_write_index` staged every
    index write at one shared path, so two callers committing different records collided there
    and one received a raw FileNotFoundError out of `put_record` — after its record was already
    committed.
    """

    def _distinct(self, count):
        return [self.build("accept_allow_with_authorization_and_execution.json",
                           receipt_id="r-%02d" % i) for i in range(count)]

    def _committed(self):
        return sorted(p.stem for p in (self.root / "receipts").glob("*.json"))

    def test_a_racing_index_write_never_fails_a_committed_record(self):
        """Controlled interleaving, not timing luck: one writer is held between staging its
        index and publishing it, while another writer stages and publishes over the same path."""
        import threading

        first, second = self._distinct(2)
        staged, release = threading.Event(), threading.Event()
        real_write_exact = store._write_exact
        holder = {}

        def seam(path, payload):
            real_write_exact(path, payload)
            if threading.get_ident() == holder.get("ident") and path.name.startswith("index"):
                staged.set()
                release.wait(20)

        outcome = {}

        def held_writer():
            holder["ident"] = threading.get_ident()
            try:
                first.put(self.store)
                outcome["first"] = "OK"
            except VerifyError as typed:
                outcome["first"] = "TYPED:" + typed.code
            except Exception as raw:
                outcome["first"] = "RAW:" + type(raw).__name__

        store._write_exact = seam
        try:
            worker = threading.Thread(target=held_writer, daemon=True)
            worker.start()
            self.assertTrue(staged.wait(20), "the seam never engaged")
            second.put(self.store)          # publishes its own index over the shared staging path
            release.set()
            worker.join(20)
        finally:
            store._write_exact = real_write_exact

        self.assertEqual(outcome["first"], "OK",
                         "a committed record was reported as failed by index maintenance")
        self.assertEqual(self._committed(), ["r-00", "r-01"])
        self.assertEqual(sorted(s.receipt_id for s in self.store.list_receipts()),
                         ["r-00", "r-01"])
        self.assertEqual(sorted(s.receipt_id for s in self.store.rebuild_index()),
                         ["r-00", "r-01"])

    def test_concurrent_distinct_records_all_commit_and_all_report_success(self):
        import concurrent.futures
        import threading

        builts = self._distinct(8)
        start = threading.Barrier(len(builts))
        raw = []

        def commit(built):
            start.wait()
            try:
                built.put(self.store)
                return "OK"
            except VerifyError as typed:
                return "TYPED:" + typed.code
            except Exception as untyped:
                raw.append(type(untyped).__name__)
                return "RAW:" + type(untyped).__name__

        with concurrent.futures.ThreadPoolExecutor(len(builts)) as pool:
            outcomes = list(pool.map(commit, builts))

        expected = ["r-%02d" % i for i in range(8)]
        self.assertEqual(raw, [], "a raw exception crossed the store boundary")
        self.assertEqual(set(outcomes), {"OK"},
                         "a caller was told persistence failed for a committed record")
        self.assertEqual(self._committed(), expected)
        for receipt_id in expected:
            for body in ("rulebook", "candidate", "snapshot", "authorization"):
                self.assertTrue((self.root / "receipts" / (receipt_id + ".inputs")
                                 / (body + ".json")).is_file(), receipt_id + "/" + body)
        listed = [s.receipt_id for s in self.store.list_receipts()]
        self.assertEqual(sorted(listed), expected)
        self.assertEqual(len(listed), len(set(listed)), "duplicate index entries")

    def test_an_index_write_failure_after_commit_leaves_the_record_committed(self):
        built = self.build()

        def broken(_summaries):
            raise OSError("the index could not be written")

        self.store._write_index = broken
        try:
            built.put(self.store)                      # must not raise: the record is committed
        finally:
            del self.store._write_index

        self.assertEqual(self._committed(), ["r-1"])
        loaded = self.store.get_record("r-1", receipt_keys=_receipt_keys(),
                                       registry=self.registry,
                                       authorization_keys=_auth_keys(),
                                       verification_time=FROZEN_AT)
        self.assertTrue(loaded.replay_verified)
        self.assertEqual([s.receipt_id for s in self.store.list_receipts()], ["r-1"])
        self.assertEqual([s.receipt_id for s in self.store.rebuild_index()], ["r-1"])

    def test_a_failure_before_the_commit_point_leaves_nothing_committed(self):
        built = self.build()
        real_write_exact = store._write_exact

        def fails_on_the_receipt(path, payload):
            if path.name == "receipt.json":
                raise OSError("the disk is gone")
            return real_write_exact(path, payload)

        store._write_exact = fails_on_the_receipt
        try:
            with self.assertRaises(VerifyError) as caught:
                built.put(self.store)
        finally:
            store._write_exact = real_write_exact

        self.assertEqual(caught.exception.code, "store_commit_conflict")
        self.assertEqual(self._committed(), [], "an uncommitted record became visible")
        with self.assertRaises(VerifyError) as missing:
            self.store.get_record("r-1", verify=False)
        self.assertEqual(missing.exception.code, "store_record_missing")
        self.assertEqual(self.store.list_receipts(), (),
                         "the index made an uncommitted record look stored")
        # The interrupted write is reported, never silently removed.
        self.assertIn("r-1.staging", self.store.scan().abandoned_staging)

    def test_a_listing_taken_during_commits_never_invents_a_record(self):
        import concurrent.futures
        import threading

        builts = self._distinct(6)
        start = threading.Barrier(len(builts) + 1)
        seen = []

        def commit(built):
            start.wait()
            built.put(self.store)

        def lister():
            start.wait()
            for _ in range(60):
                try:
                    seen.append(tuple(s.receipt_id for s in self.store.list_receipts()))
                except VerifyError as typed:
                    seen.append(("TYPED", typed.code))

        with concurrent.futures.ThreadPoolExecutor(len(builts) + 1) as pool:
            futures = [pool.submit(commit, b) for b in builts]
            futures.append(pool.submit(lister))
            for future in futures:
                future.result()

        committed = set(self._committed())
        for listing in seen:
            self.assertNotEqual(listing[:1], ("TYPED",), "listing failed: %r" % (listing,))
            for receipt_id in listing:
                self.assertIn(receipt_id, committed,
                              "a listing named a record that was never committed")
            self.assertEqual(len(listing), len(set(listing)), "duplicate entries: %r" % (listing,))

    def test_one_receipt_id_still_yields_one_identity_under_contention(self):
        import concurrent.futures
        import threading

        built = self.build(receipt_id="r-same")
        start = threading.Barrier(8)

        def commit(_):
            start.wait()
            try:
                built.put(self.store)
                return "OK"
            except VerifyError as typed:
                return typed.code
            except Exception as untyped:
                return "RAW:" + type(untyped).__name__

        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            outcomes = list(pool.map(commit, range(8)))

        self.assertEqual(self._committed(), ["r-same"], "one id must mean one record")
        self.assertIn("OK", outcomes)
        for outcome in outcomes:
            self.assertIn(outcome, ("OK", "store_commit_conflict", "store_record_conflict"),
                          "an untyped or wrong failure under same-id contention")

    def test_an_index_entry_never_substitutes_for_a_missing_record(self):
        self.build().put(self.store)
        value = load.load_json_bytes((self.root / "index.json").read_bytes())
        value["receipts"].append(dict(value["receipts"][0], receipt_id="ghost"))
        (self.root / "index.json").write_bytes(canon.canonical_bytes(value))
        self.assertEqual([s.receipt_id for s in self.store.list_receipts()], ["r-1"],
                         "the index named a record that does not exist")


class CorruptHistoryDoesNotRevokeACommit(StoreTestCase):
    """A corrupt historical record is a cache-maintenance problem, never a commit failure.

    spec/local-store.md: "Index maintenance may not revoke a commit ... `put_record` returns the
    committed record." The refresh scans every committed receipt, so one unreadable historical
    file must not travel back onto an unrelated record that has already been renamed into place.
    """

    def _corrupt_a_committed_receipt(self, receipt_id):
        path = self.root / "receipts" / (receipt_id + ".json")
        # Valid JSON, deliberately not the canonical bytes: exactly what `_load_canonical` refuses.
        path.write_bytes(b'{"receipt_id": "r-1",   "not": "canonical"}')

    def test_put_record_succeeds_when_an_unrelated_record_is_corrupt(self):
        self.build(receipt_id="r-1").put(self.store)
        self._corrupt_a_committed_receipt("r-1")
        second = self.build(fixture="accept_hold_decision.json", receipt_id="r-2")
        stored = second.put(self.store)                     # must not raise
        self.assertEqual(stored.receipt_id, "r-2")
        self.assertTrue((self.root / "receipts" / "r-2.json").exists())
        self.assertTrue((self.root / "receipts" / "r-2.inputs").is_dir())

    def test_the_corrupt_record_is_still_refused_and_still_present(self):
        self.build(receipt_id="r-1").put(self.store)
        self._corrupt_a_committed_receipt("r-1")
        self.build(fixture="accept_hold_decision.json", receipt_id="r-2").put(self.store)
        with self.assertRaises(VerifyError) as refusal:
            self.store.get_record("r-1", verify=False)
        self.assertEqual(refusal.exception.code, "store_artifact_noncanonical")
        self.assertTrue((self.root / "receipts" / "r-1.json").exists(),
                        "a corrupt artifact is never silently deleted")

    def test_a_listing_names_the_corrupt_record_and_still_answers_for_the_rest(self):
        """Once the index disagrees, the records govern — and one of them is unreadable.

        A listing must not present a corrupt artifact as a record, and it must not let that one
        file decide what can be said about every other record. It reports the refusal by
        filename, which names the repair, and lists the healthy records either way.

        This asserted a raised `store_artifact_noncanonical` until the 0.1.x hardening pass: one
        damaged file made `receipts list` useless for a whole store, which is an availability
        failure with no security benefit. Nothing here verifies anything, and `get_record` still
        refuses the damaged file — see the test above, which is unchanged.
        """
        self.build(receipt_id="r-1").put(self.store)
        self._corrupt_a_committed_receipt("r-1")
        self.build(fixture="accept_hold_decision.json", receipt_id="r-2").put(self.store)

        listing = self.store.listing()
        self.assertEqual([s.receipt_id for s in listing.summaries], ["r-2"])
        self.assertEqual([r.filename for r in listing.refused], ["r-1.json"])
        self.assertEqual([r.code for r in listing.refused], ["store_artifact_noncanonical"])
        self.assertIn("r-1.json", listing.refused[0].message)
        # The convenience accessor answers with what it could read, and never raises for a
        # damaged neighbour.
        self.assertEqual([s.receipt_id for s in self.store.list_receipts()], ["r-2"])

    def test_a_file_that_is_not_a_receipt_is_refused_by_name_not_by_traceback(self):
        """Canonical JSON that is structurally something else must not cross as a raw KeyError."""
        self.build(receipt_id="r-1").put(self.store)
        (self.root / "receipts" / "r-2.json").write_bytes(canon.canonical_bytes({"nope": 1}))
        listing = self.store.listing()
        self.assertEqual([s.receipt_id for s in listing.summaries], ["r-1"])
        self.assertEqual([(r.filename, r.code) for r in listing.refused],
                         [("r-2.json", "store_record_incomplete")])

    def test_a_receipt_whose_summary_fields_are_the_wrong_type_is_refused_by_name(self):
        """A listing sorts and prints these fields; a number where a string belongs is refused."""
        self.build(receipt_id="r-1").put(self.store)
        value = load.load_json_bytes((self.root / "receipts" / "r-1.json").read_bytes())
        value["created_at"] = 17
        (self.root / "receipts" / "r-2.json").write_bytes(canon.canonical_bytes(value))
        listing = self.store.listing()
        self.assertEqual([s.receipt_id for s in listing.summaries], ["r-1"])
        self.assertEqual([(r.filename, r.code) for r in listing.refused],
                         [("r-2.json", "store_record_incomplete")])

    def test_every_healthy_record_is_still_listed_when_most_of_the_store_is_damaged(self):
        for index in range(5):
            self.build(receipt_id="r-%d" % index).put(self.store)
        for index in (0, 2, 4):
            self._corrupt_a_committed_receipt("r-%d" % index)
        listing = self.store.listing()
        self.assertEqual([s.receipt_id for s in listing.summaries], ["r-1", "r-3"])
        self.assertEqual([r.filename for r in listing.refused],
                         ["r-0.json", "r-2.json", "r-4.json"])

    def test_a_rebuilt_index_holds_the_healthy_records_and_never_the_refused_ones(self):
        self.build(receipt_id="r-1").put(self.store)
        self.build(fixture="accept_hold_decision.json", receipt_id="r-2").put(self.store)
        self._corrupt_a_committed_receipt("r-1")
        self.assertEqual([s.receipt_id for s in self.store.rebuild_index()], ["r-2"])
        written = load.load_json_bytes((self.root / "index.json").read_bytes())
        self.assertEqual([entry["receipt_id"] for entry in written["receipts"]], ["r-2"])
        # The damaged file is still there, still refused, and still named by the next listing.
        self.assertTrue((self.root / "receipts" / "r-1.json").exists())
        self.assertEqual([r.filename for r in self.store.listing().refused], ["r-1.json"])

    def test_a_record_damaged_after_it_was_indexed_is_still_named(self):
        """The case the old reconciliation could not see: the cache is current and the file is not.

        Identities still agree — nothing was added or removed — so a listing that answered from
        the cache reported a receipt it had no way of knowing was unreadable.
        """
        self.build(receipt_id="r-1").put(self.store)
        self.build(fixture="accept_hold_decision.json", receipt_id="r-2").put(self.store)
        indexed = load.load_json_bytes((self.root / "index.json").read_bytes())
        self.assertEqual(sorted(e["receipt_id"] for e in indexed["receipts"]), ["r-1", "r-2"])

        self._corrupt_a_committed_receipt("r-2")
        listing = self.store.listing()
        self.assertEqual([s.receipt_id for s in listing.summaries], ["r-1"])
        self.assertEqual([r.filename for r in listing.refused], ["r-2.json"])

    def test_a_listing_writes_nothing(self):
        self.build(receipt_id="r-1").put(self.store)
        before = (self.root / "index.json").read_bytes()
        self._corrupt_a_committed_receipt("r-1")
        self.store.listing()
        self.assertEqual((self.root / "index.json").read_bytes(), before,
                         "a read command repaired the cache behind the caller")
