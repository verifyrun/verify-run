"""Focused local fixture tests: no launcher, provider, credential or real service."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from vfy import child_ledger as m

class ChildLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.seed = bytes(range(32))  # public fixture seed, NEVER a production credential
        self.key = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.trust = {'fixture': {'public_key_hex': self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(), 'producer_identity':m.producer()}}
        self.basis = {'path':'fixture-only-input','sha256':'1'*64}
        self.start = json.dumps({'state':'STARTED','automatic_retry':False,'task_key':'task','task_identity':{'subject_sha256':'2'*64},'operation_id':'op','attempt_id':'parent-attempt','input_artifacts':[self.basis],'native_child_population':{'state':'DECLARED_BEFORE_DISPATCH','expected_child_ids':['a','b','c']}},indent=2).encode()
        self.budget = m.raw({'schema':'vfy.child-resource-budget/1','budget_id':'dedicated-fixture-partition','task_key':'task','task_identity':{'subject_sha256':'2'*64},'parent_start_sha256':m.sha(self.start),'resource_rows':self.row('10','limit')})
        self.l = m.Ledger.create(self.base/'ledger',self.start,self.basis,self.budget,self.seed,'fixture',self.trust)
    def tearDown(self): self.temp.cleanup()
    def row(self,n,field='reserved_amount'):
        return [{'axis_id':'captured_console_bytes','unit':'byte','aggregation':'SUM','scope':'DIRECT_CHILD_CAPTURED_OUTPUT',field:n}]
    def verify(self, data=None, minimum_revision=0):
        return m.verify_report(self.l.snapshot() if data is None else data,self.trust,self.start,self.basis,self.budget,minimum_revision)
    def reserve(self,n='7',child='a',attempt='attempt-a'):
        return self.l.reserve(child,attempt,self.row(n),'2026-10-06T00:00:00Z')['body']['reservation_id']
    def complete(self,rid,n='4',service='PERFORMED'):
        rows=self.row(n,'measured_amount'); p=self.base/(rid+'.observation.json')
        p.write_bytes(m.raw({'schema':'vfy.child-observation/1','reservation_id':rid,'service_performed':service,'resource_rows':rows}))
        return self.l.complete(rid,service,rows,{'path':str(p),'sha256':m.sha(p.read_bytes())},'2026-10-06T00:00:01Z')
    def settle(self,rid,n='4',service='PERFORMED'):
        self.l.dispatch_record(rid,'2026-10-06T00:00:00Z'); c=self.complete(rid,n,service)
        self.l.settle(rid,c['sha256'],'2026-10-06T00:00:02Z')
    def test_reserve_and_known_settlement(self):
        rid=self.reserve(); self.settle(rid)
        result=self.verify(); self.assertEqual(result['committed_exposure'],{'captured_console_bytes':'4'})
        self.assertFalse(result['authority_granted']); self.assertEqual(result['financial_or_external_settlement'],'UNKNOWN')
        self.reserve('6','b','attempt-b')
        with self.assertRaises(m.Refused): self.reserve('1','c','attempt-c')
    def test_unknown_service_retains_hold(self):
        rid=self.reserve(); self.settle(rid,'0','UNKNOWN')
        self.assertEqual(self.verify()['committed_exposure']['captured_console_bytes'],'7')
        self.assertIn('a',self.verify()['unknown_children'])
    def test_unknown_measurement_retains_hold(self):
        rid=self.reserve(); self.settle(rid,'UNKNOWN')
        self.assertEqual(self.verify()['committed_exposure']['captured_console_bytes'],'7')
    def test_overrun_not_hidden(self):
        rid=self.reserve(); self.settle(rid,'12')
        self.assertTrue(self.verify()['limit_exceeded'])
        self.assertEqual(self.verify()['committed_exposure']['captured_console_bytes'],'12')
        with self.assertRaises(m.Refused): self.reserve('0','b','attempt-b')
    def test_incomplete_not_zero(self):
        rid=self.reserve(); self.l.dispatch_record(rid,'time'); self.complete(rid)
        self.assertEqual(self.verify()['committed_exposure']['captured_console_bytes'],'7')
        self.assertEqual(self.verify()['unknown_children'],['a','b','c'])
    def test_same_receipt_readback_no_retry(self):
        rid=self.reserve(); before=self.l.snapshot()
        with self.assertRaises(m.Refused): self.reserve()
        reopened=m.Ledger(self.l.root,self.seed,'fixture',self.trust,expected_start_bytes=self.start,expected_basis=self.basis,expected_budget_bytes=self.budget)
        self.assertEqual(reopened.snapshot(),before)
    def test_missing_dispatch_or_completion(self):
        rid=self.reserve()
        with self.assertRaises(m.Refused): self.complete(rid)
        with self.assertRaises(m.Refused): self.l.settle(rid,'0'*64,'time')
    def test_unlisted_child_duplicate_attempt(self):
        self.reserve()
        with self.assertRaises(m.Refused): self.reserve('1','b','attempt-a')
        with self.assertRaises(m.Refused): self.reserve('1','absent','attempt-x')
    def test_wrong_observation_binding(self):
        rid=self.reserve(); self.l.dispatch_record(rid,'time'); p=self.base/'bad.json'; p.write_bytes(b'{}')
        with self.assertRaises(m.Refused): self.l.complete(rid,'PERFORMED',self.row('1','measured_amount'),{'path':str(p),'sha256':m.sha(p.read_bytes())},'time')
    def test_stale_snapshot_revision(self):
        old=self.l.snapshot(); self.reserve()
        with self.assertRaises(m.Refused): self.verify(old,1)
    def test_parent_and_budget_exact_bytes(self):
        report=self.l.snapshot()
        with self.assertRaises(m.Refused): m.verify_report(report,self.trust,self.start+b' ',self.basis,self.budget)
        with self.assertRaises(m.Refused): m.verify_report(report,self.trust,self.start,self.basis,self.budget+b' ')
    def test_signed_semantic_conflicts(self):
        rid=self.reserve(); self.settle(rid)
        for path,value in [('budget_id','other'),('automatic_retry',True),('schema','wrong')]:
            report=json.loads(self.l.snapshot()); child=report['body']['children'][0]
            child['settlement']['body'][path]=value
            child['settlement']=m.envelope(child['settlement']['body'],self.key,'fixture')
            with self.assertRaises(m.Refused): self.verify(m.raw(m.envelope(report['body'],self.key,'fixture')))
    def test_signature_and_origin_pin(self):
        report=json.loads(self.l.snapshot()); report['signature']='00'*64
        report['sha256']=m.digest({k:v for k,v in report.items() if k!='sha256'})
        with self.assertRaises(m.Refused): self.verify(m.raw(report))
        trust=copy.deepcopy(self.trust); trust['fixture']['producer_identity']['source_sha256']='0'*64
        with self.assertRaises(m.Refused): m.verify_report(self.l.snapshot(),trust,self.start,self.basis,self.budget)
    def test_partial_transaction_quarantine(self):
        self.reserve(); (self.l.root/'pending.json').write_bytes(b'interrupted fixture')
        with self.assertRaises(m.Refused): self.l.snapshot()
        with self.assertRaises(m.Refused): self.reserve('1','b','attempt-b')
    def test_axis_and_amount_refusal(self):
        for n in ['-1','2/2','1.0','UNKNOWN']:
            with self.assertRaises(m.Refused): self.reserve(n)
        rows=self.row('1'); rows[0]['scope']='ALL_DESCENDANTS'
        with self.assertRaises(m.Refused): self.l.reserve('a','attempt-a',rows,'time')

if __name__=='__main__': unittest.main()
