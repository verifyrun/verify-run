"""Closure Unit 8 — action-bound authorization issuance, verification, and single use."""

import base64
import copy
import dataclasses
import itertools
import json
import pathlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from vfy import authorization, canon, gate, load, rulebook, schema, snapshot
from vfy.errors import VerifyError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"
AUTH_DIR = REPO_ROOT / "fixtures" / "authorization"

# TEST-ONLY published constants. They authorize nothing.
SEED_A = bytes(range(32))
SEED_B = bytes(range(32, 64))
PUB_A = Ed25519PrivateKey.from_private_bytes(SEED_A).public_key().public_bytes_raw()
PUB_B = Ed25519PrivateKey.from_private_bytes(SEED_B).public_key().public_bytes_raw()


def _registry():
    return schema.build_registry([load.load_json_bytes(p.read_bytes())
                                  for p in sorted(SPEC_DIR.glob("*.schema.json"))])


def _case(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _keys(status="active", key_id="test-key", key_version=1, public_key=None):
    return authorization.build_key_registry([
        {"key_id": key_id, "key_version": key_version,
         "public_key": PUB_A if public_key is None else public_key, "status": status}])


def _forge(scenario, case):
    """Sign an authorization over inputs that do not produce ALLOW.

    Issuance refuses to build one, so the only way to reach the verification-side eligibility
    check is to forge exactly what an attacker would: a genuinely signed authorization whose
    bound inputs settle to something other than ALLOW.
    """
    payload = {"authorization_id": case["authorization_id"], "nonce": case["nonce"],
               "issued_at": case["issued_at"], "expires_at": case["expected_expires_at"],
               "runtime_id": case["runtime_id"],
               "action_digest": canon.digest(scenario.candidate),
               "rulebook_digest": scenario.pinned.digest,
               "evidence_digest": scenario.snapshot.digest}
    signature = Ed25519PrivateKey.from_private_bytes(SEED_A).sign(
        canon.canonicalize(payload).encode("utf-8"))
    value = dict(payload)
    value["signature"] = {"alg": "ed25519", "key_id": "test-key", "key_version": 1,
                          "value": base64.b64encode(signature).decode("ascii")}
    return value


class Scenario:
    """The minimum valid fixture, assembled once and mutated per test."""

    def __init__(self, registry, ttl=None, outcome_allow=True):
        case = _case(AUTH_DIR / "accept_minimum_valid.json")
        value = copy.deepcopy(case["rulebook"])
        if ttl is not None:
            value["authorization"] = {"ttl_seconds": ttl, "single_use": True}
        if not outcome_allow:
            value["rules"][0]["outcome"] = "HOLD"
        self.registry = registry
        self.case = case
        self.pinned = rulebook.load_rulebook_bytes(
            canon.canonicalize(value).encode("utf-8"), registry)
        self.candidate = case["candidate"]
        self.snapshot = snapshot.build_snapshot(self.pinned, case["snapshot_id"],
                                                case["frozen_at"], case["acquisitions"],
                                                registry)
        self.result = gate.evaluate(self.pinned, self.candidate, self.snapshot.value(),
                                    registry)

    def issue(self, seed=SEED_A, key_id="test-key", key_version=1, issued_at=None):
        return authorization.issue_authorization(
            self.pinned, self.candidate, self.snapshot, self.result,
            self.case["authorization_id"], self.case["nonce"], self.case["runtime_id"],
            issued_at or self.case["issued_at"], key_id, key_version, seed, self.registry)

    def verify(self, value, keys=None, verification_time=None, candidate=None, pinned=None,
               snap=None, result=None, runtime_id=None, consumed=None):
        return authorization.verify_authorization(
            value, pinned or self.pinned, candidate or self.candidate, snap or self.snapshot,
            result or self.result, runtime_id or self.case["runtime_id"],
            verification_time or self.case["verification_time"],
            _keys() if keys is None else keys,
            self.registry, consumed_nonces=consumed)


class AcceptedVectors(unittest.TestCase):
    def test_every_accepted_fixture_is_reproduced_byte_for_byte(self):
        registry = _registry()
        paths = sorted(AUTH_DIR.glob("accept_*.json"))
        self.assertGreaterEqual(len(paths), 6)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                pinned = rulebook.load_rulebook_bytes(
                    canon.canonicalize(case["rulebook"]).encode("utf-8"), registry)
                snap = snapshot.build_snapshot(pinned, case["snapshot_id"], case["frozen_at"],
                                               case["acquisitions"], registry)
                result = gate.evaluate(pinned, case["candidate"], snap.value(), registry)
                auth = authorization.issue_authorization(
                    pinned, case["candidate"], snap, result, case["authorization_id"],
                    case["nonce"], case["runtime_id"], case["issued_at"], case["key_id"],
                    case["key_version"], bytes.fromhex(case["private_key_hex"]), registry)
                self.assertEqual(auth.canonical, case["authorization_canonical"])
                self.assertEqual(auth.value()["signature"]["value"], case["signature"])
                self.assertEqual(auth.expires_at, case["expected_expires_at"])
                self.assertEqual(canon.canonicalize(case["unsigned_payload"]),
                                 case["unsigned_canonical"])

    def test_every_accepted_fixture_verifies(self):
        registry = _registry()
        for path in sorted(AUTH_DIR.glob("accept_*.json")):
            case = _case(path)
            with self.subTest(fixture=path.name):
                scenario = Scenario(registry, ttl=case.get("ttl_seconds")
                                    if case["ttl_seconds"] != 300 else None)
                auth = scenario.issue()
                verified = scenario.verify(auth.value(),
                                           verification_time=case["verification_time"])
                self.assertEqual(verified.canonical, auth.canonical)

    def test_signing_is_deterministic(self):
        registry = _registry()
        scenario = Scenario(registry)
        first, second = scenario.issue(), scenario.issue()
        self.assertEqual(first.canonical, second.canonical)

    def test_the_signature_verifies_with_the_library_directly(self):
        registry = _registry()
        auth = Scenario(registry).issue()
        value = auth.value()
        payload = {k: v for k, v in value.items() if k != "signature"}
        signing_bytes = canon.canonicalize(payload).encode("utf-8")
        signature = base64.b64decode(value["signature"]["value"])
        Ed25519PublicKey.from_public_bytes(PUB_A).verify(signature, signing_bytes)
        self.assertEqual(len(signature), 64)


class RejectedVectors(unittest.TestCase):
    def _apply(self, scenario, auth, mutation):
        """Return (value, keys, verification_time, overrides, consumed) after one mutation."""
        value = auth.value()
        keys, when, overrides, consumed = _keys(), None, {}, None
        kind = mutation["kind"]
        if kind == "field":
            value[mutation["field"]] = mutation["value"]
        elif kind == "drop":
            value.pop(mutation["field"])
        elif kind == "signature_field":
            value["signature"][mutation["field"]] = mutation["value"]
        elif kind == "key_absent":
            keys = authorization.build_key_registry([])
        elif kind == "key_retired":
            keys = _keys(status="retired")
        elif kind == "signed_by_other":
            value = scenario.issue(seed=SEED_B).value()
        elif kind == "signature_copy":
            other = Scenario(scenario.registry, ttl=60).issue()
            value["signature"] = other.value()["signature"]
        elif kind == "verification_time":
            when = mutation["value"]
        elif kind == "consumed":
            consumed = {scenario.case["nonce"]}
        elif kind == "supply":
            overrides = {mutation["object"]: True}
        elif kind == "outcome":
            overrides = {"outcome": True}
        return value, keys, when, overrides, consumed

    def test_every_verification_reject_carries_its_code(self):
        registry = _registry()
        paths = sorted(AUTH_DIR.glob("reject_*.json"))
        paths = [p for p in paths if not p.stem.startswith("reject_issue_")]
        self.assertGreaterEqual(len(paths), 25)
        for path in paths:
            case = _case(path)
            with self.subTest(fixture=path.name):
                scenario = Scenario(registry)
                auth = scenario.issue()
                value, keys, when, overrides, consumed = self._apply(
                    scenario, auth, case["mutation"])

                candidate = pinned = snap = result = runtime = None
                if overrides.get("candidate"):
                    candidate = dict(scenario.candidate, candidate_id="different")
                if overrides.get("rulebook"):
                    other = Scenario(registry, ttl=60)
                    pinned, snap, result = other.pinned, other.snapshot, other.result
                if overrides.get("snapshot"):
                    snap = snapshot.build_snapshot(
                        scenario.pinned, "s-2", scenario.case["frozen_at"],
                        [{"id": "tests", "status": "ok", "value": "passed",
                          "acquired_at": "2026-08-04T23:59:31Z"}], registry)
                    result = gate.evaluate(scenario.pinned, scenario.candidate,
                                           snap.value(), registry)
                if overrides.get("runtime"):
                    runtime = "some-other-runtime"
                if overrides.get("outcome"):
                    other = Scenario(registry, outcome_allow=False)
                    pinned, snap, result = other.pinned, other.snapshot, other.result
                    candidate = other.candidate
                    value = _forge(other, scenario.case)

                with self.assertRaises(VerifyError) as caught:
                    scenario.verify(value, keys=keys, verification_time=when,
                                    candidate=candidate, pinned=pinned, snap=snap,
                                    result=result, runtime_id=runtime, consumed=consumed)
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])
                self.assertEqual(caught.exception.outcome, "ERROR")

    def test_issuance_rejects(self):
        registry = _registry()
        for path in sorted(AUTH_DIR.glob("reject_issue_*.json")):
            case = _case(path)
            kind = case["mutation"]["kind"]
            with self.subTest(fixture=path.name):
                with self.assertRaises(VerifyError) as caught:
                    if kind == "hold":
                        Scenario(registry, outcome_allow=False).issue()
                    elif kind == "bad_private_key":
                        Scenario(registry).issue(seed=b"too short")
                    elif kind == "early_issue":
                        Scenario(registry).issue(issued_at="2026-08-04T00:00:00Z")
                self.assertEqual(caught.exception.code, case["expected"]["reason_code"])


class NoSelfCertification(unittest.TestCase):
    def test_a_valid_signature_cannot_substitute_for_a_correct_binding(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        # The signature is genuine and verifies; the supplied candidate is not the bound one.
        other_candidate = dict(scenario.candidate, candidate_id="c-2")
        with self.assertRaises(VerifyError) as caught:
            scenario.verify(auth.value(), candidate=other_candidate)
        self.assertEqual(caught.exception.code, "authorization_binding_mismatch")

    def test_each_binding_is_recomputed_not_read(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        value = auth.value()
        self.assertEqual(value["action_digest"], canon.digest(scenario.candidate))
        self.assertEqual(value["rulebook_digest"], scenario.pinned.digest)
        self.assertEqual(value["evidence_digest"], scenario.snapshot.digest)

    def test_the_result_is_bound_transitively_and_recomputed(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        self.assertNotIn("result_digest", auth.value())
        self.assertNotIn("outcome", auth.value())
        # A result that is not what the bound inputs produce is refused, even though the
        # signature is genuine and every digest binding matches.
        blocking = Scenario(registry, outcome_allow=False)
        with self.assertRaises(VerifyError) as caught:
            scenario.verify(auth.value(), result=blocking.result)
        self.assertEqual(caught.exception.code, "authorization_binding_mismatch")


class TimeBoundaries(unittest.TestCase):
    def test_expiry_is_exclusive(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        scenario.verify(auth.value(), verification_time="2026-08-05T00:04:59Z")
        with self.assertRaises(VerifyError) as caught:
            scenario.verify(auth.value(), verification_time=auth.expires_at)
        self.assertEqual(caught.exception.code, "authorization_expired")

    def test_valid_at_the_issuance_instant(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        self.assertIsNotNone(scenario.verify(auth.value(), verification_time=auth.issued_at))

    def test_offset_equivalent_instants_agree(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        for equivalent in ("2026-08-05T00:04:59Z", "2026-08-05T01:04:59+01:00",
                           "2026-08-04T19:04:59-05:00"):
            with self.subTest(instant=equivalent):
                self.assertIsNotNone(scenario.verify(auth.value(),
                                                     verification_time=equivalent))
        for expired in ("2026-08-05T00:05:00Z", "2026-08-05T01:05:00+01:00"):
            with self.subTest(expired=expired):
                with self.assertRaises(VerifyError):
                    scenario.verify(auth.value(), verification_time=expired)

    def test_ttl_default_is_three_hundred_seconds(self):
        registry = _registry()
        auth = Scenario(registry).issue()
        self.assertEqual(auth.issued_at, "2026-08-05T00:00:00Z")
        self.assertEqual(auth.expires_at, "2026-08-05T00:05:00Z")

    def test_explicit_ttl_overrides_the_default(self):
        registry = _registry()
        auth = Scenario(registry, ttl=60).issue()
        self.assertEqual(auth.expires_at, "2026-08-05T00:01:00Z")


class KeyStates(unittest.TestCase):
    def test_unknown_retired_and_wrong_keys_are_distinct_failures(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        cases = [(authorization.build_key_registry([]), "signing_key_unknown"),
                 (_keys(status="retired"), "signing_key_retired"),
                 (_keys(public_key=PUB_B), "signature_invalid")]
        for keys, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(VerifyError) as caught:
                    scenario.verify(auth.value(), keys=keys)
                self.assertEqual(caught.exception.code, code)

    def test_malformed_key_material_is_refused_at_registry_build(self):
        for public_key in (b"short", "not bytes", None, bytes(31), bytes(33)):
            with self.subTest(key=repr(public_key)[:20]):
                with self.assertRaises(VerifyError) as caught:
                    authorization.build_key_registry(
                        [{"key_id": "k", "key_version": 1, "public_key": public_key}])
                self.assertEqual(caught.exception.code, "signing_key_invalid")

    def test_duplicate_key_identity_is_refused(self):
        with self.assertRaises(VerifyError):
            authorization.build_key_registry([
                {"key_id": "k", "key_version": 1, "public_key": PUB_A},
                {"key_id": "k", "key_version": 1, "public_key": PUB_B}])

    def test_the_same_key_id_at_a_different_version_is_a_different_key(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue(key_version=1)
        keys = _keys(key_version=2)
        with self.assertRaises(VerifyError) as caught:
            scenario.verify(auth.value(), keys=keys)
        self.assertEqual(caught.exception.code, "signing_key_unknown")


class NonceState(unittest.TestCase):
    def test_a_consumed_nonce_is_refused_when_state_is_supplied(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        with self.assertRaises(VerifyError) as caught:
            scenario.verify(auth.value(), consumed={auth.nonce})
        self.assertEqual(caught.exception.code, "authorization_nonce_reused")

    def test_an_unconsumed_nonce_verifies(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        self.assertIsNotNone(scenario.verify(auth.value(), consumed=set()))

    def test_stateless_verification_makes_no_single_use_claim(self):
        # Without a view, verification succeeds twice. That is not one-time use, and the
        # specification says so rather than pretending otherwise.
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        self.assertIsNotNone(scenario.verify(auth.value()))
        self.assertIsNotNone(scenario.verify(auth.value()))

    def test_verification_never_mutates_the_consumed_view(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        consumed = set()
        scenario.verify(auth.value(), consumed=consumed)
        self.assertEqual(consumed, set())

    def test_single_use_is_const_true_so_a_reusable_authorization_is_not_expressible(self):
        registry = _registry()
        rulebook_schema = registry["https://verifyrun.com/spec/v1/rulebook.schema.json"]
        single_use = (rulebook_schema["properties"]["authorization"]["properties"]["single_use"])
        self.assertEqual(single_use.get("const"), True)


class SignatureSubstitution(unittest.TestCase):
    def test_a_signature_from_another_payload_does_not_verify(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        other = Scenario(registry, ttl=60).issue()
        value = auth.value()
        value["signature"] = other.value()["signature"]
        with self.assertRaises(VerifyError) as caught:
            scenario.verify(value)
        self.assertEqual(caught.exception.code, "signature_invalid")

    def test_field_order_cannot_change_the_signed_bytes(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        value = auth.value()
        # Bounded sample: the full 8! is 40320 verifications and proves nothing more, since
        # canonicalization sorts keys before any of them is signed.
        orders = list(itertools.islice(itertools.permutations(sorted(value)), 24))
        self.assertEqual(len(orders), 24)
        for order in orders:
            shuffled = {key: value[key] for key in order}
            with self.subTest(first=order[0]):
                verified = scenario.verify(shuffled)
                self.assertEqual(verified.canonical, auth.canonical)

    def test_every_payload_field_is_covered_by_the_signature(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        replacements = {"authorization_id": "other", "nonce": "z" * 16,
                        "issued_at": "2026-08-05T00:00:01Z",
                        "expires_at": "2026-08-05T00:06:00Z", "runtime_id": "other",
                        "action_digest": "sha256:" + "1" * 64,
                        "rulebook_digest": "sha256:" + "2" * 64,
                        "evidence_digest": "sha256:" + "3" * 64}
        for field, replacement in replacements.items():
            value = auth.value()
            value[field] = replacement
            with self.subTest(field=field):
                with self.assertRaises(VerifyError) as caught:
                    scenario.verify(value)
                self.assertEqual(caught.exception.code, "signature_invalid")


class ImmutabilityAndPurity(unittest.TestCase):
    def test_the_authorization_is_immutable(self):
        registry = _registry()
        auth = Scenario(registry).issue()
        self.assertTrue(dataclasses.is_dataclass(auth))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            auth.canonical = "tampered"
        borrowed = auth.value()
        borrowed["runtime_id"] = "tampered"
        borrowed["signature"]["key_id"] = "tampered"
        self.assertNotEqual(auth.value(), borrowed)
        self.assertIsNot(auth.value(), auth.value())

    def test_no_input_is_mutated(self):
        registry = _registry()
        scenario = Scenario(registry)
        before = (copy.deepcopy(scenario.candidate), scenario.pinned.digest,
                  scenario.snapshot.digest, scenario.result.canonical)
        auth = scenario.issue()
        scenario.verify(auth.value())
        self.assertEqual(scenario.candidate, before[0])
        self.assertEqual(scenario.pinned.digest, before[1])
        self.assertEqual(scenario.snapshot.digest, before[2])
        self.assertEqual(scenario.result.canonical, before[3])

    def test_the_module_reads_no_clock_randomness_or_external_source(self):
        source = (REPO_ROOT / "vfy" / "authorization.py").read_text(encoding="utf-8")
        for banned in ("import time", "import datetime", "import random", "import os",
                       "import secrets", "urandom", "import socket", "open(", "float(",
                       "urllib", "requests"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, source)


class ExceptionContainment(unittest.TestCase):
    def test_malformed_signatures_and_keys_stay_typed(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        values = ["", "!!!!", "AAAA", "A" * 87 + "=", base64.b64encode(b"short").decode(),
                  base64.b64encode(bytes(64)).decode(), "====", " "]
        for signature_value in values:
            value = auth.value()
            value["signature"]["value"] = signature_value
            with self.subTest(signature=signature_value[:16]):
                try:
                    scenario.verify(value)
                except VerifyError as typed:
                    self.assertEqual(typed.outcome, "ERROR")
                    self.assertIn(typed.code, ("signature_malformed", "signature_invalid",
                                               "authorization_schema_invalid"))
                except Exception as untyped:
                    self.fail("%s crossed the boundary" % type(untyped).__name__)

    def test_programmer_defects_raise_type_errors(self):
        registry = _registry()
        scenario = Scenario(registry)
        auth = scenario.issue()
        for value in (None, "text", 5, []):
            with self.subTest(value=repr(value)):
                with self.assertRaises(TypeError):
                    scenario.verify(value)
        with self.assertRaises(TypeError):
            scenario.issue(key_id=None) if False else authorization.issue_authorization(
                scenario.pinned, scenario.candidate, scenario.snapshot, scenario.result,
                None, "n" * 16, "r", "2026-08-05T00:00:00Z", "k", 1, SEED_A, registry)


if __name__ == "__main__":
    unittest.main()


class OnePublicKeyIsOneIdentity(unittest.TestCase):
    """`alg`, `key_id`, and `key_version` sit outside the signed bytes.

    spec/authorization.md argues that is safe because "substituting a different `key_id` makes
    verification look up a different key, under which the signature does not verify". That holds
    only while one public key carries one identity. Registering the same key twice makes the
    substitution look up the *same* key, so the relabelled artifact verifies under an identity
    that never signed it — and per-identity retirement stops meaning anything.
    """

    def test_the_same_public_key_under_two_identities_is_refused(self):
        public = Ed25519PrivateKey.from_private_bytes(SEED_A).public_key().public_bytes_raw()
        with self.assertRaises(VerifyError) as refusal:
            authorization.build_key_registry([
                {"key_id": "signing-identity", "key_version": 1, "public_key": public},
                {"key_id": "another-identity", "key_version": 1, "public_key": public},
            ])
        self.assertEqual(refusal.exception.code, "signing_key_invalid")

    def test_retirement_cannot_be_escaped_by_relabelling(self):
        public = Ed25519PrivateKey.from_private_bytes(SEED_A).public_key().public_bytes_raw()
        with self.assertRaises(VerifyError):
            authorization.build_key_registry([
                {"key_id": "retired-identity", "key_version": 1,
                 "public_key": public, "status": "retired"},
                {"key_id": "active-identity", "key_version": 1,
                 "public_key": public, "status": "active"},
            ])

    def test_distinct_keys_and_distinct_versions_are_still_accepted(self):
        first = Ed25519PrivateKey.from_private_bytes(SEED_A).public_key().public_bytes_raw()
        second = Ed25519PrivateKey.from_private_bytes(SEED_B).public_key().public_bytes_raw()
        registry = authorization.build_key_registry([
            {"key_id": "k", "key_version": 1, "public_key": first},
            {"key_id": "k", "key_version": 2, "public_key": second},
        ])
        self.assertEqual(sorted(registry), [("k", 1), ("k", 2)])
