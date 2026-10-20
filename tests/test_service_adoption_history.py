import base64,copy,io,json,unittest
from pathlib import Path
from tests import test_service_lifecycle as fixture
from vfy import service_lifecycle as lifecycle,child_ledger as m,service_adoption_history as history
class HistoricalTests(unittest.TestCase):
 def setUp(self):
  f=fixture.LifecycleTests();f.setUp();self.addCleanup(f.doCleanups);self.f=f
  prepared=lifecycle.prepare(f.ledger(f.initial),f.payload)
  lifecycle.adopt(f.ledger(prepared['head_sha256']),f.authorization_request(prepared['plan']))
  root=Path(prepared['plan']['fixture']['root']['path'])
  self.root=root
  self.inputs=dict(plan=m.raw(prepared['plan']),preparation=m.raw(prepared['preparation_receipt']),intent=(root/'INTENT.json').read_bytes(),completion=(root/'COMPLETE.json').read_bytes())
  ledger=f.ledger(f.current())
  self.policy=dict(owner_trust=ledger.owner.trust,owner_issuer=ledger.owner.issuer,profile_sha256=m.sha(f.path.read_bytes()),runtime_id=f.profile['runtime_id'],action_key=f.profile['action_key'])
  self.expected=m.digest(prepared['plan'])
 def test_historical_verification_does_not_touch_effects_or_grant_authority(self):
  before={str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
  result=history.verify(self.inputs,self.policy,self.expected)
  self.assertEqual(result['final_plan_sha256'],self.expected)
  self.assertNotEqual(result['base_plan_sha256'],self.expected)
  for key in history.FLAGS:self.assertIs(result[key],False)
  self.assertEqual(before,{str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
 def test_cli_tamper_and_wrong_registry_refuse(self):
  q=dict(schema='vfy.verify-service-adoption-history-request/1',inputs={k:dict(base64=base64.b64encode(v).decode(),sha256=m.sha(v)) for k,v in self.inputs.items()},policy=self.policy,expected_final_plan_sha256=self.expected)
  for field in ('valid','completion','profile','plan'):
   request=copy.deepcopy(q)
   if field=='completion':request['inputs']['completion']['base64']=base64.b64encode(b'{}').decode();request['inputs']['completion']['sha256']=m.sha(b'{}')
   if field=='profile':request['policy']['profile_sha256']='0'*64
   if field=='plan':request['expected_final_plan_sha256']='0'*64
   raw=m.raw(request);out=io.StringIO();code=history.run(request_sha256=m.sha(raw),stdin=io.BytesIO(raw),out=out)
   self.assertEqual(code,0 if field=='valid' else 12)
   self.assertEqual(json.loads(out.getvalue())['state'],'HISTORICAL_ADOPTION_VERIFIED' if field=='valid' else 'REFUSED')
