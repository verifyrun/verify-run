"""New Run-owned actual no-effect verifier controls, never Engineer pending operations."""
import concurrent.futures,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from tests.child_observer_fixture import setup, install_profile
from vfy import common_capacity as cap,child_observer as obs,child_ledger as m,runner

def owner(root,ledger,slots=9,byte_limit=786432):
    seed=bytes(range(32,64));key=Ed25519PrivateKey.from_private_bytes(seed)
    trust={'CAPACITY_OWNER':{'public_key_hex':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),'producer_identity':m.producer()}}
    config=m.raw({'schema':'vfy.common-capacity/1','pool_id':'RUN_DEVELOPMENT_CAPACITY','owner_issuer':'CAPACITY_OWNER','capacities':{'dispatch_slots':slots,'retained_output_bytes':byte_limit},'scope':'REVIEWED_LOCAL_VERIFIER_ONLY'})
    return cap.CapacityOwner.create(root,config,seed,'CAPACITY_OWNER',trust,child_trust=ledger.trust,selected_observer=obs.identity())

class CommonTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name).resolve();install_profile(self,self.base);self.a=setup(self.base/'a');self.b=setup(self.base/'b')
    def tearDown(self):self.tmp.cleanup()
    def dispatch(self,o,job,**kw):return cap.dispatch_common(*[job[0],o,job[1],job[2]],selected_observer=obs.identity(),recorded_at='2026-10-08T00:00:00Z',**kw)
    def test_real_common_known_then_exhausted_slot(self):
        o=owner(self.base/'pool',self.a[0],slots=1);original=runner._launch
        def checked(*args,**kwargs):
            state=json.loads(o.snapshot())['body'];self.assertEqual(len(state['entries']),1);self.assertIsNotNone(state['entries'][0]['dispatch']);return original(*args,**kwargs)
        with patch.object(runner,'_launch',checked):r=self.dispatch(o,self.a)
        self.assertEqual(r['common_settlement']['body']['state'],'KNOWN_LOCAL_RETAINED_OUTPUT')
        used=o.usage(json.loads(o.snapshot())['body']);self.assertEqual(used['dispatch_slots'],1);self.assertEqual(used['retained_output_bytes'],len(r['stdout'])+len(r['stderr']))
        with patch.object(runner,'_launch',side_effect=AssertionError('must not launch')):
            with self.assertRaises(m.Refused):self.dispatch(o,self.b)
            with self.assertRaises(m.Refused):self.dispatch(o,self.a)
    def test_overlap_different_parents_no_double_allocation(self):
        o=owner(self.base/'pool',self.a[0],slots=9,byte_limit=cap.OUTPUT_HOLD)
        def reserve(job):
            other=cap.CapacityOwner(o.root,bytes(range(32,64)),o.issuer,o.trust,expected_config_bytes=o.config_bytes,child_trust=o.child_trust,selected_observer=o.observer)
            try:return other.reserve(job[0],job[1])
            except m.Refused:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:out=list(ex.map(reserve,[self.a,self.b]))
        self.assertEqual(sum(x is not None for x in out),1);self.assertEqual(o.usage(json.loads(o.snapshot())['body'])['retained_output_bytes'],cap.OUTPUT_HOLD)
    def test_real_interruption_retains_capacity(self):
        o=owner(self.base/'pool',self.a[0]);r=self.dispatch(o,self.a,interrupt=True,timeout_seconds=1)
        self.assertEqual(r['common_settlement']['body']['state'],'UNKNOWN_HOLD_RETAINED')
        self.assertEqual(o.usage(json.loads(o.snapshot())['body']),{'dispatch_slots':1,'retained_output_bytes':262144})
    def test_pool_binding_blocks_legacy(self):
        o=owner(self.base/'pool',self.a[0]);o.reserve(self.a[0],self.a[1]);before=self.a[0].snapshot()
        with self.assertRaises(m.Refused):obs.dispatch_development(*self.a,selected_observer=obs.identity(),recorded_at='time')
        self.assertEqual(before,self.a[0].snapshot())
    def test_forged_result_and_double_settlement_refused(self):
        o=owner(self.base/'pool',self.a[0]);r=self.dispatch(o,self.a);before=o.snapshot()
        with self.assertRaises(m.Refused):o.settle(r['common_reservation'],r)
        self.assertEqual(before,o.snapshot())
    def test_public_snapshot_verifier_selection_and_revision(self):
        o=owner(self.base/'pool',self.a[0]);o.reserve(self.a[0],self.a[1]);data=o.snapshot()
        kw=dict(expected_pool_root=str(o.root),expected_child_trusts={json.loads(self.a[1])['identity_sha256']:o.child_trust},selected_observer=o.observer)
        result=cap.verify_capacity_snapshot(data,o.trust,o.config_bytes,**kw)
        self.assertEqual(result['used'],{'dispatch_slots':1,'retained_output_bytes':262144})
        with self.assertRaises(m.Refused):cap.verify_capacity_snapshot(data,o.trust,o.config_bytes,minimum_revision=2,**kw)
        kw['expected_pool_root']=str(o.root)+'-other'
        with self.assertRaises(m.Refused):cap.verify_capacity_snapshot(data,o.trust,o.config_bytes,**kw)
    def test_reserialized_same_logical_parent_refuses(self):
        o=owner(self.base/'pool',self.a[0]);o.reserve(self.a[0],self.a[1]);l,q,_=self.a
        sb,basis,bb=l.expected;changed=sb+b' ';budget=json.loads(bb);budget['parent_start_sha256']=m.sha(changed)
        other=m.Ledger.create(self.base/'other',changed,basis,m.raw(budget),bytes(range(32)),'PUBLIC_LOCAL_DEVELOPMENT_ONLY',l.trust)
        req=json.loads(q);req['parent_start']['sha256']=m.sha(changed);req.pop('identity_sha256');req['identity_sha256']=m.sha(json.dumps(req,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode())
        with self.assertRaises(m.Refused):o.reserve(other,m.raw(req))
    def test_scoped_distinct_parent_issuer_in_one_pool(self):
        o=owner(self.base/'pool',self.a[0]);o.reserve(self.a[0],self.a[1])
        other=setup(self.base/'different-issuer',seed=bytes(range(1,33)))
        reopened=cap.CapacityOwner(o.root,bytes(range(32,64)),o.issuer,o.trust,expected_config_bytes=o.config_bytes,child_trust=other[0].trust,selected_observer=o.observer)
        reopened.reserve(other[0],other[1])
        trusts={json.loads(self.a[1])['identity_sha256']:self.a[0].trust,json.loads(other[1])['identity_sha256']:other[0].trust}
        result=cap.verify_capacity_snapshot(o.snapshot(),o.trust,o.config_bytes,expected_pool_root=str(o.root),expected_child_trusts=trusts,selected_observer=o.observer)
        self.assertEqual(result['used'],{'dispatch_slots':2,'retained_output_bytes':524288})
        trusts.pop(json.loads(other[1])['identity_sha256'])
        with self.assertRaises(m.Refused):cap.verify_capacity_snapshot(o.snapshot(),o.trust,o.config_bytes,expected_pool_root=str(o.root),expected_child_trusts=trusts,selected_observer=o.observer)
    def test_pending_quarantines(self):
        o=owner(self.base/'pool',self.a[0]);o.reserve(self.a[0],self.a[1]);(o.root/'pending.json').write_bytes(b'interrupted local fixture')
        with self.assertRaises(m.Refused):o.reserve(self.b[0],self.b[1])
    def test_wrong_config_or_child_key_refuses(self):
        o=owner(self.base/'pool',self.a[0]);c=json.loads(o.config_bytes);c['capacities']['dispatch_slots']=99
        changed=cap.CapacityOwner(o.root,bytes(range(32,64)),o.issuer,o.trust,expected_config_bytes=m.raw(c),child_trust=o.child_trust,selected_observer=o.observer)
        with self.assertRaises(m.Refused):changed.snapshot()

if __name__=='__main__':unittest.main()
