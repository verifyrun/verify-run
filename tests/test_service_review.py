"""Explicit fresh paid reviews of disposable synthetic retained operations only."""
import concurrent.futures
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch
from tests import test_service_adoption as adoption_fixtures, test_common_capacity as common_fixtures
from vfy import child_ledger as m, service_adoption as adoption, service_review as r

class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.f=adoption_fixtures.AdoptionTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.run_adopt()
        self.trust=self.f.f.base/'selected-trust.json';m.fresh(self.trust,m.raw(self.f.f.old.trust))
        self.owner=common_fixtures.owner(self.f.f.base/'review-pool',self.f.f.job[0],slots=3,byte_limit=3000000)
        self.head=self.owner.snapshot()
        self.policy=dict(schema='vfy.service-review-policy/1',pool_root=str(self.owner.root),
            predecessor_sha256=m.sha(self.head),review_identity=r.identity(),
            adoption_sha256=r.ADOPTION_SHA256,resource_capacities=dict(read_bytes=3000000,read_calls=1000,retained_bytes=3000000),
            accounting_scope='EXPLICIT_DEVELOPMENT_REVIEW_ONLY',authority_granted=False,automatic_retry=False)
        self.pool=r.PaidReviewPool.attach(self.owner,expected_snapshot_bytes=self.head,policy_bytes=m.raw(self.policy))
        self.request=dict(schema='vfy.service-review-request/1',review_id='review-one',pool_root=str(self.pool.root),
            policy_sha256=m.sha(m.raw(self.policy)),operation_root=str(self.f.root),
            plan_path=str(self.f.root/'PLAN.json'),plan_sha256=m.sha((self.f.root/'PLAN.json').read_bytes()),
            trust_path=str(self.trust),trust_sha256=m.sha(self.trust.read_bytes()),
            adoption_module_path=str(Path(adoption.__file__).resolve()),adoption_sha256=r.ADOPTION_SHA256,
            expected_source_sha256=m.digest(self.f.plan['candidate_manifest']),
            resources=dict(read_bytes=1000000,read_calls=200,retained_bytes=1000000),
            authority_granted=False,automatic_retry=False)

    def reserve(self):
        self.raw=m.raw(self.request);self.ticket=self.pool.reserve(request_bytes=self.raw,recorded_at='SYNTHETIC');return self.ticket
    def review(self):return r.paid_review(self.pool,self.ticket,request_bytes=self.raw,recorded_at='SYNTHETIC')
    def body(self,receipt):return m.authenticate(receipt,self.owner.trust)

    def test_paid_candidate_exact_bindings_no_old_mutation(self):
        before={str(p):p.read_bytes() for p in self.f.root.rglob('*') if p.is_file()};old=self.f.pool.snapshot()
        self.reserve();receipt=self.review();b=self.body(receipt)
        self.assertEqual(b['state'],'REVIEW_RECORDED');self.assertEqual(b['run_result']['state'],'OBSERVED_CANDIDATE')
        self.assertEqual(b['observed_source_sha256'],self.request['expected_source_sha256'])
        self.assertEqual(b['request'],self.request);self.assertGreater(b['charged']['read_bytes'],0)
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.f.root.rglob('*') if p.is_file()})
        self.assertEqual(old,self.f.pool.snapshot())
        with self.assertRaises(m.Refused):self.review()
        self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['used']['dispatch_slots'],1)

    def test_unknown_source_is_recorded_not_acceptance(self):
        (self.f.root/'copy/app/a.py').write_bytes(b'later change')
        self.reserve();b=self.body(self.review())
        self.assertEqual(b['run_result']['state'],'UNKNOWN');self.assertEqual(b['source_relation'],'MISMATCH')
        self.assertEqual(b['state'],'REVIEW_RECORDED')

    def test_wrong_hashes_paid_unknown(self):
        self.request['trust_sha256']='f'*64
        self.reserve();b=self.body(self.review())
        self.assertEqual(b['state'],'UNKNOWN_HOLD_RETAINED');self.assertEqual(b['run_result']['state'],'UNKNOWN')
        with self.assertRaises(m.Refused):self.review()

    def test_reserve_reads_no_subject_files(self):
        before=m.read_file
        def guarded(p):
            if str(p).startswith(str(self.f.root)):raise AssertionError('subject read before reservation')
            return before(p)
        with patch.object(m,'read_file',side_effect=guarded):self.reserve()

    def test_each_declared_read_limit_refuses_and_holds(self):
        self.request['resources']['read_bytes']=1;self.reserve();b=self.body(self.review())
        self.assertEqual(b['state'],'UNKNOWN_HOLD_RETAINED')
        self.assertLessEqual(b['charged']['read_bytes'],1)
        self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['review_used']['retained_bytes'],1000000)

    def test_read_calls_exhaustion_cannot_promote_run_caught_exception(self):
        self.request['resources']['read_calls']=5;self.reserve();b=self.body(self.review())
        self.assertEqual(b['state'],'UNKNOWN_HOLD_RETAINED')
        self.assertEqual(b['run_result']['state'],'UNKNOWN');self.assertLessEqual(b['charged']['read_calls'],5)

    def test_concurrent_consumption_only_one(self):
        self.reserve()
        def call(_):
            try:self.review();return True
            except m.Refused:return False
        with concurrent.futures.ThreadPoolExecutor(2) as ex:self.assertEqual(sum(ex.map(call,range(2))),1)

    def test_interrupt_after_consume_retains_and_reopen_refuses(self):
        self.reserve()
        with patch.object(r,'_fault',side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):self.review()
        self.assertEqual(self.pool.inspect(self.ticket)['state'],'UNKNOWN_HOLD_RETAINED')
        with self.assertRaises(m.Refused):self.review()
        reopened=r.PaidReviewPool(self.owner,expected_snapshot_bytes=self.head,policy_bytes=m.raw(self.policy))
        with self.assertRaises(m.Refused):r.paid_review(reopened,self.ticket,request_bytes=self.raw,recorded_at='REOPEN')

    def test_process_death_before_selected_reads(self):
        self.reserve();pid=os.fork()
        if pid==0:
            r._fault=lambda stage:os._exit(23)
            self.review();os._exit(24)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),23)
        with self.assertRaises(m.Refused):self.review()
        self.assertEqual(self.pool.inspect(self.ticket)['state'],'UNKNOWN_HOLD_RETAINED')

    def test_duplicate_and_exhaustion_preserve_budget(self):
        self.reserve()
        with self.assertRaises(m.Refused):self.reserve()
        for n in (2,3):
            self.request['review_id']='review-'+str(n);self.reserve()
        self.request['review_id']='review-4'
        with self.assertRaises(m.Refused):self.reserve()
        self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['used']['dispatch_slots'],3)

    def test_same_module_globals_unmodified(self):
        original=adoption.m.read_file;scan=adoption._scan
        self.reserve();self.review()
        self.assertIs(adoption.m.read_file,original);self.assertIs(adoption._scan,scan)
        self.assertEqual(adoption.identity()['source_sha256'],r.ADOPTION_SHA256)

    def test_different_module_refused_at_admission(self):
        self.request['adoption_sha256']='f'*64
        with self.assertRaises(m.Refused):self.reserve()

    def test_wrong_expected_source_cannot_pass(self):
        self.request['expected_source_sha256']='f'*64;self.reserve();b=self.body(self.review())
        self.assertEqual(b['run_result']['state'],'UNKNOWN');self.assertEqual(b['source_relation'],'MISMATCH')

if __name__=='__main__':unittest.main()

class AdditionalControls(unittest.TestCase):
    setUp=ReviewTests.setUp
    reserve=ReviewTests.reserve
    review=ReviewTests.review
    body=ReviewTests.body
    def test_exact_successful_payload_meter_matches_trace(self):
        self.reserve();b=self.body(self.review())
        trace=json.loads((self.pool.root/'reviews'/m.sha(self.raw)/'TRACE.json').read_bytes())
        self.assertEqual(b['charged']['read_bytes'],sum(e['bytes'] for e in trace))
        self.assertEqual(b['charged']['read_calls'],len(trace))
        self.assertEqual(b['trace_sha256'],m.sha(m.raw(trace)))
        self.assertTrue(any(e['path']==self.request['adoption_module_path'] for e in trace))
        self.assertTrue(any(e['path']==str(self.f.root/'FIXTURE.json') for e in trace))

    def test_read_failure_inside_old_reconcile_is_outer_unknown(self):
        # Three selected reads succeed, then the first old reader payload cannot.
        self.request['resources']['read_calls']=3;self.reserve();b=self.body(self.review())
        self.assertEqual(b['reason'],'BOUNDED_READ_FAILED')
        self.assertEqual(b['state'],'UNKNOWN_HOLD_RETAINED')
        self.assertEqual(b['charged']['read_calls'],3)

    def test_independent_parallel_reviews_do_not_patch_original_reader(self):
        self.reserve();first=(self.ticket,self.raw)
        self.request['review_id']='parallel-review';self.reserve();second=(self.ticket,self.raw)
        original=m.read_file
        def run(item):return r.paid_review(self.pool,item[0],request_bytes=item[1],recorded_at='SYNTHETIC')
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            receipts=list(ex.map(run,[first,second]))
        self.assertIs(m.read_file,original)
        for receipt in receipts:self.assertEqual(self.body(receipt)['run_result']['state'],'OBSERVED_CANDIDATE')

    def test_exhausted_predecessor_refuses_without_subject_read(self):
        old=common_fixtures.owner(self.f.f.base/'empty-review',self.f.f.job[0],slots=0,byte_limit=0)
        head=old.snapshot();policy=dict(self.policy,pool_root=str(old.root),predecessor_sha256=m.sha(head))
        pool=r.PaidReviewPool.attach(old,expected_snapshot_bytes=head,policy_bytes=m.raw(policy))
        req=dict(self.request,pool_root=str(pool.root),policy_sha256=m.sha(m.raw(policy)))
        with self.assertRaises(m.Refused):pool.reserve(request_bytes=m.raw(req),recorded_at='EMPTY')
        self.assertEqual(pool.verify_snapshot(pool.snapshot())['used']['dispatch_slots'],0)

    def test_low_retention_stops_reads_and_holds(self):
        self.request['resources']['retained_bytes']=65536
        self.reserve();b=self.body(self.review())
        root=self.pool.root/'reviews'/m.sha(self.raw)
        self.assertLessEqual(sum(p.stat().st_size for p in root.iterdir()),65536)
        self.assertEqual(b['reserved']['retained_bytes'],65536)

    def test_existing_adoption_pool_usage_is_preserved_on_explicit_transition(self):
        head=self.f.pool.snapshot();before=self.f.pool.verify_snapshot(head)['used']
        policy=dict(self.policy,pool_root=str(self.f.pool.root),predecessor_sha256=m.sha(head))
        pool=r.PaidReviewPool.attach(self.f.pool,expected_snapshot_bytes=head,policy_bytes=m.raw(policy))
        self.assertEqual(pool.verify_snapshot(pool.snapshot())['used'],before)
        req=dict(self.request,pool_root=str(pool.root),policy_sha256=m.sha(m.raw(policy)))
        pool.reserve(request_bytes=m.raw(req),recorded_at='SYNTHETIC')
        self.assertEqual(pool.verify_snapshot(pool.snapshot())['used']['dispatch_slots'],before['dispatch_slots']+1)

    def test_uncharged_historical_reader_unchanged(self):
        before=self.pool.snapshot()
        result=adoption.reconcile(self.f.root,self.f.plan,owner_trust=self.f.f.old.trust)
        self.assertEqual(result['state'],'OBSERVED_CANDIDATE');self.assertEqual(before,self.pool.snapshot())

class ReviewFixControls(unittest.TestCase):
    setUp=ReviewTests.setUp
    reserve=ReviewTests.reserve
    review=ReviewTests.review
    body=ReviewTests.body

    def test_unreadable_source_root_cannot_observe_complete_manifest(self):
        self.reserve();original=os.scandir
        def fail(path):
            if Path(path)==self.f.root/'copy':raise PermissionError('synthetic unreadable source root')
            return original(path)
        with patch.object(os,'scandir',side_effect=fail):b=self.body(self.review())
        self.assertEqual(b['state'],'UNKNOWN_HOLD_RETAINED')
        self.assertIsNone(b['observed_source_sha256']);self.assertEqual(b['run_result']['state'],'UNKNOWN')

    def test_unreadable_extra_subtree_cannot_false_accept_candidate(self):
        hidden=self.f.root/'copy/unreadable';hidden.mkdir();(hidden/'extra').write_bytes(b'extra')
        self.reserve();original=os.scandir
        def fail(path):
            if Path(path)==hidden:raise PermissionError('synthetic unreadable extra subtree')
            return original(path)
        with patch.object(os,'scandir',side_effect=fail):b=self.body(self.review())
        self.assertEqual(b['state'],'UNKNOWN_HOLD_RETAINED')
        self.assertIsNone(b['observed_source_sha256']);self.assertEqual(b['run_result']['state'],'UNKNOWN')

    def test_control_character_trace_charged_before_payload_read(self):
        folder=self.f.f.base
        for _ in range(4):folder=folder/('\x01'*200);folder.mkdir()
        p=folder/'data';p.write_bytes(b'x')
        reader=r._Reader(dict(read_calls=100,read_bytes=1000,retained_bytes=65536))
        succeeded=0
        with self.assertRaises(m.Refused):
            for _ in range(28):reader.read(p);succeeded+=1
        self.assertLess(succeeded,28)
        self.assertLessEqual(len(m.raw(reader.trace)),65536-32768)
        self.assertEqual(reader.used['read_bytes'],succeeded)
