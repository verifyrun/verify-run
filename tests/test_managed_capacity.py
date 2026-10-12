"""Run-owned no-authority fixture; never writes Engineer pending operations."""
import concurrent.futures
import multiprocessing
import os
import json
import tempfile
import unittest
from pathlib import Path
from test_common_capacity import owner
from test_child_observer import setup
from vfy import managed_capacity as mc, child_ledger as m, common_capacity as cap


def seal(value):
    value = dict(value)
    value['identity_sha256'] = m.sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
    return (json.dumps(value, sort_keys=True, indent=1)+'\n').encode()


def file_ref(p, data):
    p.write_bytes(data)
    return {'path':str(p), 'sha256':m.sha(data)}


def fixture(base, slots=9):
    job = setup(base/'legacy-job')
    old = owner(base/'pool', job[0], slots=slots)
    # Positive prior UNKNOWN-sized reservation, not a fake Engineer history.
    old.reserve(job[0], job[1])
    oldbytes = old.snapshot()
    callback = {'id':mc.EFFECT, 'code_sha256':'1'*64, 'adapter_source_sha256':m.sha(b'fixed-test-writer'), 'python':'TEST_ONLY'}
    kw = dict(expected_config_bytes=old.config_bytes, child_trust=old.child_trust, selected_observer=old.observer,
              legacy_snapshot_bytes=oldbytes, expected_child_trusts={json.loads(job[1])['identity_sha256']:old.child_trust},
              selected_callback_identity=callback)
    new = mc.ManagedCapacityOwner(old.root, bytes(range(32,64)), old.issuer, old.trust, **kw)
    grant = dict(schema='vfy.local-capacity-grant-request/1', grant_id='TEST_NONFINANCIAL',pool_root=str(old.root),
        config_sha256=m.sha(old.config_bytes),owner_issuer=old.issuer,
        expected_head={'raw_sha256':m.sha(oldbytes),'envelope_sha256':json.loads(oldbytes)['sha256'],'revision':1},
        additions={'dispatch_slots':3,'managed_receipt_bytes':12288},profile_extension=mc.EFFECT,
        retained_byte_dimension='managed_receipt_bytes',scope='EXPLICIT_NONFINANCIAL_LOCAL_DEVELOPMENT_GRANT_NOT_ACTION_AUTHORITY',**mc.FLAGS)
    return old,new,grant,kw


def action(base, o, name='0001'):
    state = base/'managed-state'; state.mkdir(exist_ok=True)
    attempt = state/name; attempt.mkdir()
    task = {'repository':str(base/'subject'), 'subject_sha256':'a'*64, 'task_id':'RUN_TEST'}
    basis = file_ref(base/('basis-'+name), m.raw({'repository':task['repository'], 'task_source_binding':{'task_id':task['task_id'],'task_subject_identity_sha256':task['subject_sha256']}}))
    config = file_ref(base/'config.json', o.config_bytes)
    binding = dict(schema='engineer.managed-task-capacity-binding/1',state_root=str(state),pool_root=str(o.root),
        config=config,owner={'owner_issuer':o.issuer,'public_key_hex':o.trust[o.issuer]['public_key_hex']},
        task={'inspection_sha256':basis['sha256'],'task_id':task['task_id'],'task_subject_identity_sha256':task['subject_sha256']},
        effect_profile=mc.EFFECT,**mc.FLAGS)
    bindingref = file_ref(state/'CAPACITY.json', m.raw(binding))
    adapter = file_ref(base/'adapter.py', b'fixed-test-writer')
    capture = dict(schema='engineer.managed-local-execution/1',kind='CAPTURE',callback=o.callback,common_capacity_binding=bindingref,
        repository=task['repository'],contract={'task_id':task['task_id'],'destination':'test/local'},
        snapshot={'payload':{'message':name},'values':{'ready':True},'observation':{'task':binding['task'],'observed_at_ns':2**60}},
        criterion={'parameters':['ready']},refs={'inspection':basis})
    cb = seal(capture); cid=json.loads(cb)['identity_sha256']
    cref = file_ref(attempt/'CAPTURE.json', cb)
    receipt = seal(dict(schema=capture['schema'],kind='LOCAL_CALLBACK_RECEIPT',capture_id=cid,callback_id=mc.EFFECT,
                        destination_label='test/local',payload=capture['snapshot']['payload']))
    complete = seal(dict(schema=capture['schema'],kind='COMPLETE',capture_id=cid,callback=o.callback,
        receipt_sha256=json.loads(receipt)['identity_sha256'],observed_guard_arguments=[True],observed_guard_result=True,
        callback_calls=1,local_effect='MANAGED_JSON_RECEIPT_ONLY',external_effects='UNKNOWN'))
    start = m.raw(dict(state='STARTED',automatic_retry=False,task_key='b'*64,task_identity=task,operation_id='op-'+name,
        attempt_id='attempt-'+name,input_artifacts=[basis],native_child_population={'state':'DECLARED_BEFORE_DISPATCH','expected_child_ids':['managed-json-callback']}))
    sref = file_ref(base/('parent-'+name+'.json'),start)
    q = dict(schema='vfy.managed-dispatch-request/1',task_key='b'*64,task_identity=task,operation_id='op-'+name,attempt_id='attempt-'+name,
        parent_start=sref,basis=basis,child_id='managed-json-callback',capture=cref,capture_identity=cid,managed_state=str(state),managed_attempt=str(attempt),
        destination=str(attempt/'CALLBACK.json'),callback_identity=o.callback,receipt_sha256=m.sha(receipt),receipt_bytes=len(receipt),
        complete_sha256=m.sha(complete),complete_bytes=len(complete),source_refs=[basis,adapter],binding_ref=bindingref,binding_basis=basis,**mc.FLAGS)
    return q,start,cb,receipt,complete


def prepare(o,a): return o.prepare_managed(m.raw(a[0]),*a[1:],recorded_at='TEST')
def local_start(a):
    q=a[0]; p=Path(q['managed_attempt'])/'START.json'
    p.write_bytes(seal(dict(schema='engineer.managed-local-execution/1',kind='START',capture_id=q['capture_identity'])))
def consume(g,a):
    return g.before_callback(capture_bytes=a[2],callback_identity=a[0]['callback_identity'],destination=a[0]['destination'],receipt_bytes=a[3])


class ManagedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.base=Path(self.temp.name).resolve()
        self.old,self.o,self.grant,self.kw=fixture(self.base)
        self.o.apply_grant(m.raw(self.grant),recorded_at='TEST')
    def tearDown(self):self.temp.cleanup()
    def state(self):return json.loads(self.o.snapshot())['body']
    def test_positive_exact_fixed_write_settle_preserves_legacy(self):
        a=action(self.base,self.o);g=prepare(self.o,a);local_start(a);consume(g,a)
        Path(a[0]['destination']).write_bytes(a[3]);(Path(a[0]['managed_attempt'])/'COMPLETE.json').write_bytes(a[4])
        g.settle(callback_bytes=a[3],complete_bytes=a[4],recorded_at='TEST')
        b=self.state();self.assertEqual(b['legacy_raw_hex'],self.o.legacy_bytes.hex())
        self.assertEqual(self.o.usage(b),{'dispatch_slots':2,'retained_output_bytes':262144,'managed_receipt_bytes':len(a[3])})
        v=mc.verify_managed_snapshot(self.o.snapshot(),self.o.trust,self.o.config_bytes,expected_pool_root=str(self.o.root),
            legacy_snapshot_bytes=self.o.legacy_bytes,expected_child_trusts=self.kw['expected_child_trusts'],selected_observer=self.o.observer,
            selected_callback_identity=self.o.callback,selected_managed_identity=mc.identity())
        self.assertEqual(v['used'],self.o.usage(b))
    def test_grant_replay_and_legacy_api_refused(self):
        before=self.o.snapshot()
        with self.assertRaises(m.Refused):self.o.apply_grant(m.raw(self.grant),recorded_at='TEST')
        with self.assertRaises(m.Refused):self.old.snapshot()
        self.assertEqual(before,self.o.snapshot())
    def test_reserved_crash_new_parent_and_recovery_cannot_dispatch(self):
        a=action(self.base,self.o);g=prepare(self.o,a)
        fresh=mc.ManagedCapacityOwner(self.o.root,bytes(range(32,64)),self.o.issuer,self.o.trust,**self.kw)
        local_start(a)
        with self.assertRaises(m.Refused):consume(fresh.guard(g.key),a)
        with self.assertRaises(m.Refused):consume(mc.ManagedGuard(fresh,g.key),a)
        (Path(a[0]['managed_attempt'])/'START.json').unlink() # local fixture only to isolate stable identity test
        start=json.loads(a[1]);start['attempt_id']='NEW';a[0]['attempt_id']='NEW';changed=m.raw(start)
        Path(a[0]['parent_start']['path']).write_bytes(changed);a[0]['parent_start']['sha256']=m.sha(changed)
        with self.assertRaises(m.Refused):prepare(fresh,(a[0],changed,*a[2:]))
        self.assertEqual(self.o.usage(self.state())['managed_receipt_bytes'],4096)
    def test_byte_change_and_double_use_refused(self):
        a=action(self.base,self.o);g=prepare(self.o,a);local_start(a)
        bad=list(a);bad[3]+=b' '
        with self.assertRaises(m.Refused):consume(g,bad)
        with self.assertRaises(m.Refused):consume(g,a)
        self.assertFalse(Path(a[0]['destination']).exists())
    def test_after_write_missing_complete_retains_unknown(self):
        a=action(self.base,self.o);g=prepare(self.o,a);local_start(a);consume(g,a)
        Path(a[0]['destination']).write_bytes(a[3])
        with self.assertRaises(OSError):g.settle(callback_bytes=a[3],complete_bytes=a[4],recorded_at='TEST')
        self.assertEqual(self.o.usage(self.state())['managed_receipt_bytes'],4096)
        g.mark_unknown(reason='COMPLETE absent',recorded_at='TEST')
        with self.assertRaises(m.Refused):consume(g,a)
    def test_source_and_complete_arguments_refused_before_admission(self):
        a=action(self.base,self.o);a[0]['source_refs']=[]
        with self.assertRaises(m.Refused):prepare(self.o,a)
        self.assertEqual(len(self.state()['managed_entries']),0)
    def test_concurrent_same_capture_one_claim(self):
        a=action(self.base,self.o)
        def attempt(_):
            try:return prepare(self.o,a)
            except m.Refused:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:results=list(ex.map(attempt,range(2)))
        self.assertEqual(sum(x is not None for x in results),1)
    def test_actual_process_death_before_managed_start(self):
        a=action(self.base,self.o)
        def child():
            prepare(self.o,a)
            os._exit(73)
        proc=multiprocessing.get_context('fork').Process(target=child);proc.start();proc.join(5)
        self.assertFalse(proc.is_alive());self.assertEqual(proc.exitcode,73)
        self.assertFalse((Path(a[0]['managed_attempt'])/'START.json').exists())
        with self.assertRaises(m.Refused):prepare(self.o,a)
        self.assertEqual(self.o.usage(self.state())['managed_receipt_bytes'],4096)
    def test_actual_process_death_after_write_before_complete(self):
        a=action(self.base,self.o)
        def child():
            g=prepare(self.o,a);local_start(a);consume(g,a)
            m.fresh(Path(a[0]['destination']),a[3])
            os._exit(74)
        proc=multiprocessing.get_context('fork').Process(target=child);proc.start();proc.join(5)
        self.assertFalse(proc.is_alive());self.assertEqual(proc.exitcode,74)
        self.assertTrue(Path(a[0]['destination']).exists())
        self.assertFalse((Path(a[0]['managed_attempt'])/'COMPLETE.json').exists())
        with self.assertRaises(m.Refused):prepare(self.o,a)
        self.assertEqual(self.o.usage(self.state())['managed_receipt_bytes'],4096)
    def test_pending_quarantines(self):
        a=action(self.base,self.o);(self.o.root/'pending.json').write_bytes(b'INTERRUPTED_FIXTURE')
        with self.assertRaises(m.Refused):prepare(self.o,a)

if __name__=='__main__':unittest.main()
