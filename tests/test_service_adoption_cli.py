"""Disposable synthetic authority and copies; no retained customer effects."""
import json
import types
import unittest
from vfy.workflow import FixedClock
from vfy.errors import AuthorizationExpired
from unittest.mock import patch
from vfy import service_adoption as a, service_adoption_cli as cli, child_ledger as m
from tests.test_service_adoption import AdoptionTests
from tests.test_service_accounting_cli import SessionTests

class EntryTests(unittest.TestCase):
    def setUp(self):
        self.f = AdoptionTests()
        # Reuse preparation/authorization fixture without its old convenience
        # attach/reserve: the public entry must perform those transitions itself.
        with patch.object(a.AdoptionPool, 'attach', return_value=types.SimpleNamespace(reserve=lambda *a, **k: None)):
            self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.request=dict(schema='vfy.service-adoption-entry-request/1',root=str(self.f.root),
            plan=self.f.plan,rulebook=self.f.pinned.value(),snapshot=self.f.snap.value(),
            result=self.f.result.value(),authorization=self.f.auth.value())
        service_profile=SessionTests.make_profile(types.SimpleNamespace(f=self.f.f))
        self.service_path=self.f.f.base/'service-profile.json'
        self.service_path.write_bytes(m.raw(service_profile))
        self.profile=dict(schema='vfy.service-adoption-entry-profile/1',scope='DISPOSABLE_DEVELOPMENT_ONLY',
            service_profile=str(self.service_path),service_profile_sha256=m.sha(self.service_path.read_bytes()),
            adoption_policy=self.f.policy,action_key=dict(**self.f.policy['action_key'],status='active'))
        self.path=self.f.f.base/'entry-profile.json'

    def run_entry(self, clock=None):
        raw=m.raw(self.request);profile=m.raw(self.profile);self.path.write_bytes(profile)
        return cli.adopt_selected(raw,m.sha(raw),self.path,m.sha(profile),
                                  clock=FixedClock('2026-08-05T00:01:00Z') if clock is None else clock)

    def test_real_transition_and_duplicate_refusal(self):
        result=self.run_entry()
        self.assertEqual(result['receipt']['body']['state'],'OBSERVED_CANDIDATE')
        self.assertEqual((self.f.original/'app/a.py').read_bytes(),b'base a')
        self.assertEqual((self.f.root/'copy/app/a.py').read_bytes(),b'candidate a')
        with self.assertRaises(Exception):self.run_entry()

    def test_changed_result_refuses_before_pool_transition(self):
        before=(self.f.f.pool.root/'state.json').read_bytes()
        self.request['result']['outcome']='HOLD'
        with self.assertRaises(Exception):self.run_entry()
        self.assertEqual(before,(self.f.f.pool.root/'state.json').read_bytes())

    def test_revoked_key_refuses_before_pool_transition(self):
        before=(self.f.f.pool.root/'state.json').read_bytes()
        self.profile['action_key']['status']='revoked'
        with self.assertRaises(Exception):self.run_entry()
        self.assertEqual(before,(self.f.f.pool.root/'state.json').read_bytes())

    def test_wrong_runtime_refuses_before_pool_transition(self):
        before=(self.f.f.pool.root/'state.json').read_bytes()
        self.profile['adoption_policy']['runtime_id']='other-runtime'
        with self.assertRaises(Exception):self.run_entry()
        self.assertEqual(before,(self.f.f.pool.root/'state.json').read_bytes())

    def test_interrupted_adoption_retains_no_retry(self):
        with patch.object(a, '_fault', side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):self.run_entry()
        self.assertTrue((self.f.root/'INTENT.json').exists())
        before=(self.f.f.pool.root/'state.json').read_bytes()
        with self.assertRaises(Exception):self.run_entry()
        self.assertEqual(before,(self.f.f.pool.root/'state.json').read_bytes())
        self.assertFalse((self.f.root/'COMPLETE.json').exists())

    def test_expired_second_clock_read_refuses_adoption(self):
        instants = iter(['2026-08-05T00:01:00Z', '2099-01-01T00:00:00Z'])
        clock = types.SimpleNamespace(now_utc=lambda: next(instants))
        with self.assertRaises(AuthorizationExpired):
            self.run_entry(clock=clock)
        self.assertFalse((self.f.root/'COMPLETE.json').exists())
        self.assertEqual((self.f.original/'app/a.py').read_bytes(), b'base a')
