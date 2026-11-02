"""Fresh synthetic adoption vectors: published test keys, no service execution."""
import concurrent.futures
import json
import os
import shutil
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
SEED=bytes(range(96,128))
PUB=Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw()
from unittest.mock import patch
from tests import test_service_tests as observations, test_common_capacity as common_fixture
from tests import test_authorization as auth_fixture
from vfy import child_ledger as m, authorization, rulebook, snapshot, gate, store
from vfy import service_adoption as a


def manifest(files):
    return {p:dict(sha256=m.sha(b),bytes=len(b),executable=0) for p,b in files.items()}


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.o=observations.ObservationTests();self.o.setUp()
        self.addCleanup(self.o.doCleanups)
        self.f=self.o.f
        old=common_fixture.owner(self.f.base/'large-pool',self.f.job[0],slots=1 if getattr(self,'axis',None)=='dispatch_slots' else 4,
            byte_limit=800 if getattr(self,'axis',None)=='retained_output_bytes' else 8000000)
        self.f.bind(old)
        self.base={'app/a.py':b'base a','app/b.py':b'base b'}
        self.candidate={'app/a.py':b'candidate a','app/b.py':b'candidate b'}
        original_action=self.f.action
        def action():
            q,raw=original_action();p=json.loads(raw);p['source']=manifest(self.candidate)
            return q,m.raw(p)
        self.f.action=action
        self.assertEqual(self.o.observed()['state'],'OBSERVED_SELECTED_CASES_SUCCESS')
        self.limits=dict(files=10,source_bytes=1000,read_bytes=2000000,write_bytes=1000,
                         file_mutations=2,journal_bytes=1000000)
        self.original=self.f.base/'original';self.original.mkdir()
        for p,b in self.base.items():
            path=self.original/p;path.parent.mkdir(exist_ok=True);path.write_bytes(b)
        self.root=a.provision_managed_copy(base_manifest_bytes=m.raw(manifest(self.base)),
            base_files=self.base,original_root=self.original,limits=self.limits)
        self.addCleanup(shutil.rmtree,self.root)
        self.plan=self.prepare()
        self.nonces=store.LocalStore(self.f.base/'nonce-store')
        self.head=self.f.pool.snapshot()
        self.policy=dict(schema='vfy.service-adoption-policy/1',pool_root=str(self.f.pool.root),
            predecessor_sha256=m.sha(self.head),producer_identity=a.identity(),
            resource_capacities={k:3000000 for k in a.RESOURCES},runtime_id='runtime-1',
            authorization_store_root=str(self.nonces.root),
            action_key=dict(key_id='test-key',key_version=1,public_key_hex=PUB.hex()),
            authority_granted=False,automatic_retry=False)
        if getattr(self,'axis',None) in a.RESOURCES:self.policy['resource_capacities'][self.axis]=0
        self.pool=a.AdoptionPool.attach(self.f.pool,expected_snapshot_bytes=self.head,policy_bytes=m.raw(self.policy))
        self.ticket=None if getattr(self,'axis',None) else self.pool.reserve(self.plan,recorded_at='SYNTHETIC')
        self.registry=auth_fixture._registry()
        rb=dict(rulebook_id='explicit-isolated-approval',version='1.0.0',adopted_at='2026-08-05T00:00:00Z',
            evidence=[dict(id='approval',source='file',max_age_seconds=900)],
            rules=[dict(id='approved',when='fresh(approval) and evidence.approval == "APPROVE_ISOLATED_COPY"',
                        outcome='ALLOW',reason='Explicit selected test action approval')],default_outcome='HOLD')
        self.pinned=rulebook.load_rulebook_bytes(m.raw(rb),self.registry)
        self.snap=snapshot.build_snapshot(self.pinned,'synthetic','2026-08-05T00:00:00Z',
            [dict(id='approval',status='ok',value='APPROVE_ISOLATED_COPY',acquired_at='2026-08-05T00:00:00Z')],self.registry)
        action=a.action_for(self.plan)
        self.result=gate.evaluate(self.pinned,action,self.snap.value(),self.registry)
        self.auth=authorization.issue_authorization(self.pinned,action,self.snap,self.result,'synthetic-adopt',
            'adoption-nonce-0001','runtime-1','2026-08-05T00:00:00Z','test-key',1,SEED,self.registry)
        self.kw=dict(pool=self.pool,ticket=self.ticket,pinned=self.pinned,snapshot=self.snap,result=self.result,
            authorization=self.auth.value(),runtime_id='runtime-1',verification_time='2026-08-05T00:01:00Z',
            authorization_keys=auth_fixture._keys(public_key=PUB),registry=self.registry,authorization_store=self.nonces)

    def prepare(self):
        return a.prepare_adoption(self.root,candidate_manifest_bytes=m.raw(manifest(self.candidate)),
            candidate_files=self.candidate,task_id='TEST-REQUIREMENTS',checker=self.o.checker,
            check_inputs=self.o.args,limits=self.limits)

    def run_adopt(self,**changes):return a.adopt(self.root,self.plan,**dict(self.kw,**changes))
    def status(self):return a.reconcile(self.root,self.plan,owner_trust=self.f.old.trust)

    def test_actual_replacement_preserves_original_and_binds_evidence(self):
        receipt=self.run_adopt()
        self.assertEqual(receipt['body']['state'],'OBSERVED_CANDIDATE')
        self.assertEqual(self.status()['state'],'OBSERVED_CANDIDATE')
        self.assertEqual(self.status()['content_state'],'CANDIDATE')
        for p in self.base:
            self.assertEqual((self.original/p).read_bytes(),self.base[p])
            self.assertEqual((self.root/'copy'/p).read_bytes(),self.candidate[p])
        self.assertTrue(self.nonces.is_consumed(self.auth.nonce))
        self.assertEqual(self.plan['requirements_sha256'],m.sha(self.o.requirements))
        self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['used']['dispatch_slots'],2)
        with self.assertRaises(Exception):self.run_adopt()
        with self.assertRaises(Exception):self.f.pool.snapshot()

    def test_changed_base_refuses_before_intent(self):
        (self.root/'copy/app/a.py').write_bytes(b'changed')
        with self.assertRaises(Exception):self.run_adopt()
        self.assertFalse((self.root/'INTENT.json').exists())
        self.assertEqual(self.status()['content_state'],'UNKNOWN')

    def test_wrong_destination_and_action_refused(self):
        for field,value in [('destination',str(self.original)),('task_id','other-task')]:
            with self.assertRaises(Exception):a.adopt(self.root,dict(self.plan,**{field:value}),**self.kw)
        self.assertFalse((self.root/'INTENT.json').exists())

    def test_current_authority_controls(self):
        for changes in [dict(runtime_id='wrong'),dict(verification_time=None),
                        dict(verification_time='2026-08-05T00:05:00Z'),
                        dict(authorization_keys=auth_fixture._keys(status='revoked',public_key=PUB)),
                        dict(authorization_keys=auth_fixture._keys(status='retired',public_key=PUB)),
                        dict(authorization_store=store.LocalStore(self.f.base/'replacement-store'))]:
            with self.subTest(changes=changes):
                with self.assertRaises(Exception):self.run_adopt(**changes)
        self.assertFalse((self.root/'INTENT.json').exists())

    def test_frozen_evidence_tamper_refused(self):
        p=self.root/'evidence'/'stdout_bytes';p.write_bytes(b'{}')
        with self.assertRaises(Exception):self.run_adopt()
        self.assertFalse((self.root/'INTENT.json').exists())

    def test_concurrent_intent_exactly_one(self):
        def call(_):
            try:self.run_adopt();return True
            except Exception:return False
        with concurrent.futures.ThreadPoolExecutor(2) as ex:self.assertEqual(sum(ex.map(call,range(2))),1)
        self.assertEqual(self.status()['state'],'OBSERVED_CANDIDATE')

    def test_interrupt_before_mutation_no_retry(self):
        def stop(stage):
            if stage=='after_intent':raise RuntimeError('synthetic interruption')
        with patch.object(a,'_fault',side_effect=stop):
            with self.assertRaises(RuntimeError):self.run_adopt()
        self.assertEqual(self.status()['content_state'],'BASE')
        self.assertEqual(self.status()['state'],'UNKNOWN')
        with self.assertRaises(Exception):self.run_adopt()
        reopened=a.AdoptionPool(self.f.pool,expected_snapshot_bytes=self.head,policy_bytes=m.raw(self.policy))
        with self.assertRaises(Exception):self.run_adopt(pool=reopened)

    def test_interrupt_mid_replacement_mixed_no_retry(self):
        def stop(stage):
            if stage=='after_replace':raise RuntimeError('synthetic interruption')
        with patch.object(a,'_fault',side_effect=stop):
            with self.assertRaises(RuntimeError):self.run_adopt()
        self.assertEqual(self.status()['content_state'],'MIXED')
        self.assertEqual(self.status()['state'],'UNKNOWN')
        with self.assertRaises(Exception):self.run_adopt()

    def test_candidate_without_receipt_unknown(self):
        def stop(stage):
            if stage=='before_complete':raise RuntimeError('synthetic interruption')
        with patch.object(a,'_fault',side_effect=stop):
            with self.assertRaises(RuntimeError):self.run_adopt()
        self.assertEqual(self.status()['content_state'],'CANDIDATE')
        self.assertEqual(self.status()['state'],'UNKNOWN')

    def test_reconcile_read_only_and_requires_selected_trust(self):
        self.run_adopt()
        before={str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(m,'fresh',side_effect=AssertionError('write forbidden')):
            self.assertEqual(self.status()['state'],'OBSERVED_CANDIDATE')
            self.assertEqual(a.reconcile(self.root,self.plan)['state'],'UNKNOWN')
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_extra_and_alias_source_refuse(self):
        p=self.root/'copy/extra';p.symlink_to(self.original/'app/a.py')
        with self.assertRaises(Exception):self.run_adopt()
        self.assertEqual(self.status()['content_state'],'UNKNOWN')

    def test_duplicate_reservation_no_budget_reset(self):
        with self.assertRaises(Exception):self.pool.reserve(self.plan,recorded_at='AGAIN')
        with self.assertRaises(Exception):a.AdoptionPool.attach(self.f.pool,expected_snapshot_bytes=self.head,policy_bytes=m.raw(self.policy))
        self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['adoption_used']['journal_bytes'],self.limits['journal_bytes'])

    def test_wrong_candidate_manifest_not_tested_refused(self):
        other=dict(self.candidate);other['app/a.py']=b'untested'
        root=a.provision_managed_copy(base_manifest_bytes=m.raw(manifest(self.base)),base_files=self.base,
            original_root=self.original,limits=self.limits);self.addCleanup(shutil.rmtree,root)
        with self.assertRaises(Exception):a.prepare_adoption(root,candidate_manifest_bytes=m.raw(manifest(other)),
            candidate_files=other,task_id='TEST',checker=self.o.checker,check_inputs=self.o.args,limits=self.limits)


if __name__=='__main__':unittest.main()

class ExtendedControls(unittest.TestCase):
    setUp=AdoptionTests.setUp
    prepare=AdoptionTests.prepare
    run_adopt=AdoptionTests.run_adopt
    status=AdoptionTests.status
    def test_process_death_retains_intent_and_fresh_reader_no_retry(self):
        pid=os.fork()
        if pid==0:
            a._fault=lambda stage: os._exit(23) if stage=='after_intent' else None
            try:self.run_adopt()
            except Exception:os._exit(24)
            os._exit(25)
        _,status=os.waitpid(pid,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),23)
        self.assertEqual(self.status()['content_state'],'BASE')
        self.assertEqual(self.status()['state'],'UNKNOWN')
        # Parent inherited a live token, but shared durable intent also refuses it.
        with self.assertRaises(Exception):self.run_adopt()
        read_fd,write_fd=os.pipe();pid=os.fork()
        if pid==0:
            os.close(read_fd)
            raw=m.raw(a.reconcile(self.root,self.plan,owner_trust=self.f.old.trust))
            os.write(write_fd,raw);os._exit(0)
        os.close(write_fd);raw=os.read(read_fd,65536);os.close(read_fd);os.waitpid(pid,0)
        self.assertEqual(json.loads(raw)['state'],'UNKNOWN')
        self.assertEqual(json.loads(raw)['content_state'],'BASE')

    def test_all_resource_axes_and_shared_exhaustion(self):
        for axis in (*a.RESOURCES,'dispatch_slots','retained_output_bytes'):
            case=AdoptionTests();case.axis=axis
            try:
                case.setUp()
                with self.subTest(axis=axis):
                    with self.assertRaises(m.Refused):case.pool.reserve(case.plan,recorded_at='LIMIT')
                    self.assertEqual(case.pool.verify_snapshot(case.pool.snapshot())['adoption_used'],dict.fromkeys(a.RESOURCES,0))
            finally:case.doCleanups()

    def test_unrelated_pool_cannot_inherit_observation(self):
        old=common_fixture.owner(self.f.base/'unrelated',self.f.job[0],slots=4,byte_limit=8000000)
        self.f.bind(old);head=self.f.pool.snapshot()
        policy=dict(self.policy,pool_root=str(old.root),predecessor_sha256=m.sha(head))
        pool=a.AdoptionPool.attach(self.f.pool,expected_snapshot_bytes=head,policy_bytes=m.raw(policy))
        with self.assertRaises(m.Refused):pool.reserve(self.plan,recorded_at='WRONG_POOL')

    def test_bad_authority_reads_no_selected_payloads(self):
        with patch.object(a._Meter,'read',side_effect=AssertionError('selected read before approval')):
            with self.assertRaises(m.Refused):self.run_adopt(runtime_id='wrong')
        self.assertIsNone(json.loads(self.pool.snapshot())['body']['entries'][0]['intent'])

    def test_failed_validation_cannot_repeat_payload_reads(self):
        (self.root/'copy/app/a.py').write_bytes(b'changed')
        with self.assertRaises(m.Refused):self.run_adopt()
        with patch.object(a._Meter,'read',side_effect=AssertionError('repeat selected read')):
            with self.assertRaises(m.Refused):self.run_adopt()
        self.assertIsNotNone(json.loads(self.pool.snapshot())['body']['entries'][0]['intent'])

    def test_existing_nonce_prevents_intent(self):
        self.nonces.consume_once(self.auth)
        with self.assertRaises(Exception):self.run_adopt()
        self.assertFalse((self.root/'INTENT.json').exists())

    def test_hardlink_and_mode_change_refuse(self):
        p=self.root/'copy/app/a.py';p.unlink();os.link(self.original/'app/a.py',p)
        with self.assertRaises(Exception):self.run_adopt()
        p.unlink();p.write_bytes(self.base['app/a.py']);p.chmod(0o700)
        with self.assertRaises(Exception):self.run_adopt()

    def test_completion_tamper_never_known(self):
        self.run_adopt();p=self.root/'COMPLETE.json';receipt=json.loads(p.read_bytes())
        receipt['body']['destination']=str(self.original);p.write_bytes(m.raw(receipt))
        self.assertEqual(self.status()['state'],'UNKNOWN')
        self.assertEqual(self.status()['content_state'],'CANDIDATE')

    def test_path_population_and_traversal_refuse(self):
        for name in ('../escape','/absolute','.git/config','a/../b','a//b'):
            files={name:b'x'}
            with self.assertRaises(Exception):a.provision_managed_copy(base_manifest_bytes=m.raw(manifest(files)),
                base_files=files,original_root=self.original,limits=self.limits)

    def test_reopened_reservation_before_consume_refused(self):
        pool=a.AdoptionPool(self.f.pool,expected_snapshot_bytes=self.head,policy_bytes=m.raw(self.policy))
        with self.assertRaises(Exception):self.run_adopt(pool=pool)
        self.assertFalse((self.root/'INTENT.json').exists())

    def test_declared_read_bound_prevents_mutation(self):
        with patch.object(a._Meter,'charge',side_effect=m.Refused('synthetic resource exhaustion')):
            with self.assertRaises(m.Refused):self.run_adopt()
        self.assertFalse((self.root/'INTENT.json').exists())
