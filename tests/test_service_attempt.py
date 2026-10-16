"""Fresh synthetic accounting fixtures; never execute or rewrite historical attempts."""
import concurrent.futures
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tests.child_observer_fixture import install_profile, setup
from tests.test_common_capacity import owner
from tests.test_managed_capacity import fixture as managed_fixture
from vfy import child_ledger as m, service_attempt as s


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        install_profile(self, self.base)
        self.job = setup(self.base/'child')
        self.old = owner(self.base/'pool', self.job[0], slots=3, byte_limit=1000)
        self.approver = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
        self.trust = {'APPROVER': {'public_key_hex': self.approver.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex(), 'producer_identity': m.producer()}}
        self.bind(self.old)

    def tearDown(self):
        self.tmp.cleanup()

    def bind(self, old):
        self.head = old.snapshot()
        self.policy = dict(schema='vfy.service-policy/1', pool_root=str(old.root),
            config_sha256=m.sha(old.config_bytes), predecessor_sha256=m.sha(self.head),
            service_identity=s.identity(), approval_trust=self.trust,
            adapter_sha256='a'*64, capture_sha256='b'*64,
            resource_capacities={k:100000 for k in s.RESOURCES}, **s.FLAGS)
        self.kw = dict(predecessor_snapshot_bytes=self.head, policy_bytes=m.raw(self.policy))
        self.pool = s.ServicePool.attach(old, **self.kw)
        self.old = old

    def action(self, name='one'):
        root = self.base/name; root.mkdir()
        limits = dict(wall_seconds=60, cpu_seconds=40, output_bytes=100, file_bytes=200, descriptors=128)
        p = dict(schema='engineer.service-observation/1', root=str(root), limits=limits,
            adapter_sha256='a'*64, capture_sha256='b'*64, source={'tree':'source'},
            examiner={'tree':'examiner'}, environment={'python':'synthetic'}, labels=['synthetic'],
            policy='synthetic no-execution fixture', scope='synthetic')
        preview = m.raw(p); m.fresh(root/'PREVIEW.json', preview)
        q = dict(schema=s.PROFILE, attempt_id=name, attempt_root=str(root),
            pool_root=str(self.old.root), policy_sha256=m.sha(self.kw['policy_bytes']),
            preview_sha256=m.sha(preview), resources=limits, **s.FLAGS)
        return q, preview

    def approval(self, q, p):
        return m.raw(m.envelope(dict(schema='vfy.service-approval/1', request_sha256=m.sha(m.raw(q)),
            preview_sha256=m.sha(p), policy_sha256=m.sha(self.kw['policy_bytes']), **s.FLAGS),
            self.approver, 'APPROVER'))

    def admit(self, a):
        q, p = a
        return self.pool.admit(request_bytes=m.raw(q), preview_bytes=p,
            approval_bytes=self.approval(q, p), recorded_at='SYNTHETIC')

    def start(self, a):
        raw = m.raw({'preview':m.sha(a[1])})
        m.fresh(Path(a[0]['attempt_root'])/'START.json', raw)
        return raw

    def consume(self, t, a, start):
        return self.pool.consume(t, request_bytes=m.raw(a[0]), preview_bytes=a[1],
            start_bytes=start, recorded_at='SYNTHETIC')

    def result(self, a, exit=0, **extra):
        out, err = b'OK', b''
        result = dict(preview=m.sha(a[1]), state='PROCESS_OBSERVED', exit=exit,
            limit_failure=None, wall_seconds=0.01, stdout_sha256=m.sha(out), stderr_sha256=m.sha(err), **extra)
        if exit is None: result.pop('exit')
        raw = json.dumps(result, sort_keys=True).encode()
        for name, data in [('RESULT.json',raw),('stdout.bin',out),('stderr.bin',err)]:
            m.fresh(Path(a[0]['attempt_root'])/name, data)
        return dict(result_bytes=raw, stdout_bytes=out, stderr_bytes=err, recorded_at='SYNTHETIC')

    def state(self):
        return json.loads(self.pool.snapshot())['body']

    def test_positive_raw_bindings_all_charges_and_old_handle_refusal(self):
        a=self.action(); t=self.admit(a); start=self.start(a); receipt=self.consume(t,a,start)
        self.assertEqual(receipt['body']['entries'][0]['start_sha256'],m.sha(start))
        self.pool.settle(t, **self.result(a))
        b=self.state(); e=b['entries'][0]
        self.assertEqual(e['state'],'OBSERVED_EXIT_ZERO')
        self.assertEqual(e['request_sha256'],m.sha(m.raw(a[0])))
        self.assertEqual(b['predecessor_raw_hex'],self.head.hex())
        v=self.pool.verify_snapshot(self.pool.snapshot())
        self.assertEqual(v['used']['dispatch_slots'],1)
        self.assertEqual(v['used']['retained_output_bytes'],100)
        self.assertEqual(v['service_used'],a[0]['resources'])
        with self.assertRaises(m.Refused): self.old.snapshot()
        with self.assertRaises(m.Refused): self.old.reserve(*self.job[:2])
        with self.assertRaises(m.Refused): self.consume(t,a,start)

    def test_failed_consume_burns_and_unknown_no_launch(self):
        a=self.action(); t=self.admit(a); self.start(a)
        with self.assertRaises(m.Refused): self.consume(t,a,b'{}')
        self.assertEqual(self.state()['entries'][0]['state'],'UNKNOWN')
        with self.assertRaises(m.Refused): self.consume(t,a,m.raw({'preview':m.sha(a[1])}))

    def test_reopened_admission_cannot_launch(self):
        a=self.action(); t=self.admit(a); start=self.start(a)
        self.pool=s.ServicePool(self.old,**self.kw)
        with self.assertRaises(m.Refused): self.consume(t,a,start)
        self.pool.mark_unknown(t,reason='lost live capability',recorded_at='SYNTHETIC')
        self.assertEqual(self.state()['entries'][0]['state'],'UNKNOWN')

    def test_result_states_and_retained_charges(self):
        for i, (code, expected) in enumerate([(1,'OBSERVED_EXIT_NONZERO'),(-9,'OBSERVED_SIGNAL'),(None,'UNKNOWN')]):
            a=self.action(str(i)); t=self.admit(a); self.consume(t,a,self.start(a))
            self.pool.settle(t,**self.result(a,code))
            self.assertEqual(self.state()['entries'][-1]['state'],expected)
        self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['used']['retained_output_bytes'],300)

    def test_unknown_stays_unknown_with_late_evidence(self):
        a=self.action(); t=self.admit(a); self.consume(t,a,self.start(a))
        self.pool.mark_unknown(t,reason='caller interrupted',recorded_at='SYNTHETIC')
        self.pool.settle(t,**self.result(a))
        self.assertEqual(self.state()['entries'][0]['state'],'UNKNOWN')

    def test_tampered_output_refuses_settlement(self):
        a=self.action(); t=self.admit(a); self.consume(t,a,self.start(a)); args=self.result(a)
        (Path(a[0]['attempt_root'])/'stdout.bin').write_bytes(b'changed')
        with self.assertRaises(m.Refused): self.pool.settle(t,**args)
        self.assertEqual(self.state()['entries'][0]['state'],'CONSUMED')

    def test_wrong_version_approval_and_resources_refused(self):
        a=self.action(); q,p=a
        for change in ({'schema':'vfy.service-attempt/2'}, {'preview_sha256':'f'*64},
                       {'resources':dict(q['resources'],cpu_seconds=41)}, {'pool_root':'/wrong'}):
            with self.subTest(change=change):
                with self.assertRaises(m.Refused): self.admit((dict(q,**change),p))
        sig=json.loads(self.approval(q,p)); sig['signature']='0'*128
        with self.assertRaises(m.Refused): self.pool.admit(request_bytes=m.raw(q),preview_bytes=p,
            approval_bytes=m.raw(sig),recorded_at='SYNTHETIC')
        self.assertEqual(len(self.state()['entries']),0)

    def test_preview_change_at_consume(self):
        a=self.action(); t=self.admit(a); start=self.start(a)
        (Path(a[0]['attempt_root'])/'PREVIEW.json').write_bytes(b'{}')
        with self.assertRaises(m.Refused): self.consume(t,a,start)
        self.assertEqual(self.state()['entries'][0]['state'],'UNKNOWN')

    def test_duplicate_concurrent_consume_one_only(self):
        a=self.action(); t=self.admit(a); start=self.start(a)
        def call(_):
            try: self.consume(t,a,start); return True
            except m.Refused: return False
        with concurrent.futures.ThreadPoolExecutor(2) as ex:
            self.assertEqual(sum(ex.map(call,range(2))),1)

    def test_shared_slot_exhaustion_not_new_store(self):
        for i in range(3): self.admit(self.action(str(i)))
        with self.assertRaises(m.Refused): self.admit(self.action('four'))
        self.assertFalse(hasattr(s.ServicePool,'create'))

    def test_exhausted_predecessor_preserved(self):
        old=owner(self.base/'empty',self.job[0],slots=0,byte_limit=0)
        self.bind(old)
        with self.assertRaises(m.Refused): self.admit(self.action())
        self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['capacities']['dispatch_slots'],0)

    def test_shared_bytes_exhaustion(self):
        old=owner(self.base/'small',self.job[0],slots=10,byte_limit=99); self.bind(old)
        with self.assertRaises(m.Refused): self.admit(self.action())

    def test_managed_predecessor_preserves_existing_usage(self):
        base=self.base/'managed';base.mkdir()
        old,managed,grant,_=managed_fixture(base)
        managed.apply_grant(m.raw(grant),recorded_at='SYNTHETIC'); self.bind(managed)
        self.admit(self.action())
        view=self.pool.verify_snapshot(self.pool.snapshot())
        self.assertEqual(view['used'],{'dispatch_slots':2,'retained_output_bytes':262244,'managed_receipt_bytes':0})
        with self.assertRaises(m.Refused): managed.snapshot()

    def test_pending_publication_blocks_everything(self):
        a=self.action();t=self.admit(a);start=self.start(a)
        m.fresh(self.old.root/'pending.json',b'interrupted')
        with self.assertRaises(m.Refused): self.consume(t,a,start)
        with self.assertRaises(m.Refused): self.pool.snapshot()

    def test_attach_replay_and_unselected_policy_refuse(self):
        with self.assertRaises(m.Refused): s.ServicePool.attach(self.old,**self.kw)
        policy=dict(self.policy,approval_trust=self.old.trust)
        with self.assertRaises(m.Refused): s.ServicePool(self.old,
            predecessor_snapshot_bytes=self.head,policy_bytes=m.raw(policy))

    def test_signed_state_tamper_refused(self):
        b=json.loads(self.pool.snapshot());b['body']['revision']+=1
        with self.assertRaises(m.Refused): self.pool.verify_snapshot(m.raw(b))

    def test_every_resource_coordinate_exhaustion(self):
        for k in s.RESOURCES:
            with self.subTest(coordinate=k):
                old=owner(self.base/('pool-'+k),self.job[0],slots=10,byte_limit=10000)
                head=old.snapshot(); p=dict(self.policy,pool_root=str(old.root),
                    config_sha256=m.sha(old.config_bytes),predecessor_sha256=m.sha(head),
                    resource_capacities=dict(self.policy['resource_capacities'],**{k:0}))
                self.old=old;self.kw=dict(predecessor_snapshot_bytes=head,policy_bytes=m.raw(p))
                self.pool=s.ServicePool.attach(old,**self.kw)
                with self.assertRaises(m.Refused): self.admit(self.action(k))
                self.assertEqual(self.state()['entries'],[])

    def test_engineer_limit_vector_requires_full_shared_output_capacity(self):
        limits=dict(wall_seconds=60,cpu_seconds=40,output_bytes=1048576,file_bytes=67108864,descriptors=128)
        for size in (786432,1048576):
            old=owner(self.base/('pool-'+str(size)),self.job[0],slots=1,byte_limit=size)
            head=old.snapshot();p=dict(self.policy,pool_root=str(old.root),
                config_sha256=m.sha(old.config_bytes),predecessor_sha256=m.sha(head),resource_capacities=limits)
            self.old=old;self.kw=dict(predecessor_snapshot_bytes=head,policy_bytes=m.raw(p))
            self.pool=s.ServicePool.attach(old,**self.kw)
            q,preview=self.action(str(size));v=json.loads(preview);v['limits']=limits;preview=m.raw(v)
            (Path(q['attempt_root'])/'PREVIEW.json').write_bytes(preview)
            q.update(resources=limits,preview_sha256=m.sha(preview))
            if size < limits['output_bytes']:
                with self.assertRaises(m.Refused): self.admit((q,preview))
            else:
                self.admit((q,preview))
                self.assertEqual(self.pool.verify_snapshot(self.pool.snapshot())['service_used'],limits)

    def test_actual_signed_unselected_issuer_refused(self):
        a=self.action(); q,p=a
        approval=m.envelope(self.pool._approval_body(m.raw(q),m.sha(p)),self.old.key,self.old.issuer)
        with self.assertRaises(m.Refused): self.pool.admit(request_bytes=m.raw(q),preview_bytes=p,
            approval_bytes=m.raw(approval),recorded_at='SYNTHETIC')

    def test_start_wrong_preview_and_version_refuse(self):
        for i,wrong in enumerate(({'preview':'f'*64}, {'preview':'f'*64,'schema':'future/2'})):
            a=self.action(str(i));t=self.admit(a);start=m.raw(wrong)
            m.fresh(Path(a[0]['attempt_root'])/'START.json',start)
            with self.assertRaises(m.Refused): self.consume(t,a,start)
            self.assertEqual(self.state()['entries'][-1]['state'],'UNKNOWN')

    def test_limit_failure_and_launch_failure_are_unknown(self):
        for i,patch in enumerate(({'limit_failure':'wall'}, {'state':'LAUNCH_FAILED','exit':None})):
            a=self.action(str(i));t=self.admit(a);self.consume(t,a,self.start(a))
            args=self.result(a);r=json.loads(args['result_bytes']);r.update(patch)
            args['result_bytes']=json.dumps(r).encode()
            (Path(a[0]['attempt_root'])/'RESULT.json').write_bytes(args['result_bytes'])
            self.pool.settle(t,**args)
            self.assertEqual(self.state()['entries'][-1]['state'],'UNKNOWN')

    def test_duplicate_admission_and_existing_start_refused(self):
        a=self.action();self.admit(a)
        with self.assertRaises(m.Refused): self.admit(a)
        b=self.action('two');self.start(b)
        with self.assertRaises(m.Refused): self.admit(b)

    def test_wrong_result_preview_and_changed_start_refused(self):
        a=self.action();t=self.admit(a);self.consume(t,a,self.start(a));args=self.result(a)
        r=json.loads(args['result_bytes']);r['preview']='f'*64
        wrong=dict(args,result_bytes=json.dumps(r).encode())
        (Path(a[0]['attempt_root'])/'RESULT.json').write_bytes(wrong['result_bytes'])
        with self.assertRaises(m.Refused): self.pool.settle(t,**wrong)
        (Path(a[0]['attempt_root'])/'RESULT.json').write_bytes(args['result_bytes'])
        (Path(a[0]['attempt_root'])/'START.json').write_bytes(b'{}')
        with self.assertRaises(m.Refused): self.pool.settle(t,**args)

    def test_duplicate_and_nonfinite_evidence_refuse(self):
        for raw, error in ((b'{"a":1,"a":2}',m.load.CanonicalFormInvalid),
                           (b'{"wall_seconds":NaN}',m.load.SourceSyntaxInvalid),
                           (b'{"wall_seconds":1e999}',m.Refused)):
            with self.subTest(raw=raw):
                with self.assertRaises(error): s.evidence(raw)


if __name__=='__main__': unittest.main()
