import base64,copy,io,json,unittest
from tests import test_service_adoption_history as fixture
from vfy import service_adoption_accounting as accounting,child_ledger as m
class AccountingTests(unittest.TestCase):
 def setUp(self):
  self.f=fixture.HistoricalTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
 def test_exact_separate_counters_and_cli(self):
  f=self.f
  q=dict(schema='vfy.verify-service-adoption-accounting-request/1',inputs={k:dict(base64=base64.b64encode(v).decode(),sha256=m.sha(v)) for k,v in f.inputs.items()},policy=f.policy,expected_final_plan_sha256=f.expected)
  raw=m.raw(q);out=io.StringIO();self.assertEqual(accounting.run(request_sha256=m.sha(raw),stdin=io.BytesIO(raw),out=out),0)
  result=json.loads(out.getvalue())['result']['accounting']
  done=m.authenticate(json.loads(f.inputs['completion']),f.policy['owner_trust'])
  self.assertEqual(result['adoption']['measured'],done['measured'])
  self.assertEqual(result['aggregation'],'NOT_SUMMED');self.assertEqual(result['full_physical_cost'],'UNKNOWN')
  self.assertEqual(result['remaining_budget'],'NOT_ESTABLISHED')
 def test_invalid_counter_types_and_over_limit_refuse(self):
  for value in (-1,True,2**64):
   with self.assertRaises(m.Refused):accounting.vector({'read_bytes':value},('read_bytes',))
  f=self.f;inputs=copy.deepcopy(f.inputs);record=json.loads(inputs['completion']);body=record['body'];body['measured']['read_bytes']=body['resources_reserved']['read_bytes']+1
  ledger=f.f.ledger(f.f.current());inputs['completion']=m.raw(m.envelope(body,ledger.owner.key,ledger.owner.issuer))
  with self.assertRaisesRegex(m.Refused,'reservation mismatch'):accounting.accounting(inputs,f.policy)
