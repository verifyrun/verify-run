"""Disposable synthetic lifecycle; imported source setup is not customer acceptance."""
import base64
import json
import unittest
from unittest.mock import patch
from tests import test_service_adoption_cli as entry
from tests.test_service_adoption import manifest, SEED
from vfy import service_lifecycle as lifecycle, child_ledger as m, gate, authorization, service_adoption as a

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.f=entry.EntryTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f.f
        encode=lambda b:base64.b64encode(b).decode()
        payload=dict(base_manifest=manifest(f.base),base_files={k:encode(v) for k,v in f.base.items()},
            candidate_manifest=manifest(f.candidate),candidate_files={k:encode(v) for k,v in f.candidate.items()},
            original_root=str(f.original),check_inputs={k:(v if k=='request_sha256' else encode(v)) for k,v in f.o.args.items()})
        self.payload=f.f.base/'paid-payload.json';self.payload.write_bytes(m.raw(payload))
        self.profile=dict(schema=lifecycle.FORMAT,scope='DISPOSABLE_DEVELOPMENT_ONLY',
            service_profile=str(self.f.service_path),service_profile_sha256=m.sha(self.f.service_path.read_bytes()),
            task_id='TEST-REQUIREMENTS',attempt_id='fresh-paid-attempt',payload_sha256=m.sha(self.payload.read_bytes()),
            preparation_limits=dict(payload_bytes=1000000,copy_bytes=1000,staged_bytes=1000,checked_bytes=1000000,files=10,artifact_bytes=2000000),
            adoption_limits=f.limits,recovery_bytes=1000000,
            checker=dict(inputs={k:encode(v) for k,v in f.o.checker.selected.items()},limits=f.o.limits),
            action_key=dict(**f.policy['action_key'],status='active'),runtime_id='runtime-1',authorization_store_root=str(f.nonces.root))
        self.path=f.f.base/'paid-profile.json';self.path.write_bytes(m.raw(self.profile))
        self.initial=m.sha(f.f.pool.snapshot())

    def ledger(self,head):return lifecycle.Ledger(self.path,m.sha(self.path.read_bytes()),head)
    def current(self):return m.sha((self.f.f.f.pool.root/'state.json').read_bytes())
    def authorization_request(self,plan):
        f=self.f.f;result=gate.evaluate(f.pinned,a.action_for(plan),f.snap.value(),f.registry)
        auth=authorization.issue_authorization(f.pinned,a.action_for(plan),f.snap,result,'synthetic-paid-adoption',
            'fresh-paid-nonce','runtime-1',lifecycle.now(),'test-key',1,SEED,f.registry)
        return dict(rulebook=f.pinned.value(),snapshot=f.snap.value(),result=result.value(),authorization=auth.value())

    def test_prepare_adopt_recover(self):
        prepared=lifecycle.prepare(self.ledger(self.initial),self.payload)
        done=lifecycle.adopt(self.ledger(prepared['head_sha256']),self.authorization_request(prepared['plan']))
        self.assertEqual(done['state'],'COMPLETE')
        self.assertEqual((self.f.f.original/'app/a.py').read_bytes(),b'base a')
        recovered=lifecycle.recover(self.ledger(done['head_sha256']))
        self.assertEqual(recovered['state'],'COMPLETE')
        self.assertFalse(recovered['construction_resumed'])
        with self.assertRaises(Exception):lifecycle.prepare(self.ledger(self.current()),self.payload)
        with self.assertRaises(Exception):lifecycle.recover(self.ledger(self.current()))

    def test_failed_payload_holds_budget(self):
        self.payload.write_bytes(b'changed')
        with self.assertRaises(Exception):lifecycle.prepare(self.ledger(self.initial),self.payload)
        recovered=lifecycle.recover(self.ledger(self.current()))
        self.assertEqual(recovered['state'],'UNKNOWN')
        with self.assertRaises(Exception):lifecycle.prepare(self.ledger(self.current()),self.payload)

    def test_interrupt_before_payload(self):
        with patch.object(lifecycle,'fault',side_effect=RuntimeError('stop')):
            with self.assertRaises(RuntimeError):lifecycle.prepare(self.ledger(self.initial),self.payload)
        recovered=lifecycle.recover(self.ledger(self.current()))
        self.assertEqual(recovered['state'],'PREPARING')
        self.assertFalse(recovered['construction_resumed'])

    def test_changed_head_refuses_before_payload(self):
        before=(self.f.f.f.pool.root/'state.json').read_bytes()
        with patch.object(lifecycle,'bounded_file',wraps=lifecycle.bounded_file) as read:
            with self.assertRaises(Exception):lifecycle.prepare(self.ledger('0'*64),self.payload)
            self.assertFalse(any(str(call.args[0])==str(self.payload) for call in read.call_args_list))
        self.assertEqual(before,(self.f.f.f.pool.root/'state.json').read_bytes())

    def test_limit_failure_retains_whole_hold(self):
        self.profile['preparation_limits']['copy_bytes']=1
        self.path.write_bytes(m.raw(self.profile))
        with self.assertRaises(Exception):lifecycle.prepare(self.ledger(self.initial),self.payload)
        record=m.load.load_json_bytes((self.f.f.f.pool.root/'state.json').read_bytes())['body']
        self.assertEqual(record['phase'],'UNKNOWN')
        self.assertEqual(record['reserved']['dispatch_slots'],2)
        self.assertIsNone(record['managed_root'])

    def test_fault_after_copy_never_adopts(self):
        def stop(stage):
            if stage=='after_copy':raise RuntimeError('stop after copy')
        with patch.object(lifecycle,'fault',side_effect=stop):
            with self.assertRaises(RuntimeError):lifecycle.prepare(self.ledger(self.initial),self.payload)
        record=m.load.load_json_bytes((self.f.f.f.pool.root/'state.json').read_bytes())['body']
        self.assertEqual(record['phase'],'UNKNOWN')
        self.assertIsNotNone(record['managed_root'])
        self.assertEqual((self.f.f.original/'app/a.py').read_bytes(),b'base a')
        with self.assertRaises(Exception):lifecycle.adopt(self.ledger(self.current()),{})
