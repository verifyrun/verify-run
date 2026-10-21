import io,json,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from tests.test_service_proposal_cli import ProposalTests
from tests.test_service_accounting_cli import SessionTests
from vfy import child_ledger as m,check_execution as c

class ExecutionTests(unittest.TestCase):
 def setUp(self):
  self.f=ProposalTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
  fixture=self.f.f;h=SessionTests();h.f=fixture;sp=h.make_profile();sp['session_seconds']=90
  self.sp=fixture.base/'selected-profile.json';self.sp.write_bytes(m.raw(sp))
  self.data=m.raw(self.f.q);self.root=Path(json.loads(self.f.inputs['request'])['attempt_root'])
  (self.root/'PREVIEW.json').write_bytes(self.f.inputs['preview'])
  self.p=dict(schema=c.FORMAT,accounting_profile=str(self.sp),accounting_profile_sha256=m.sha(self.sp.read_bytes()),proposal_sha256=m.sha(self.data),platform_context_sha256=m.sha(self.f.inputs['platform_context']),engineer_package={})
  self.path=fixture.base/'check-profile.json';self.path.write_bytes(m.raw(self.p));self.count=0
  def execute(root,digest,*,_consume,_before_launch):
   start=m.raw({'preview':digest});(root/'START.json').write_bytes(start);_consume(start);_before_launch();self.count+=1
   result=fixture.result((json.loads(self.f.inputs['request']),self.f.inputs['preview']))
  self.adapter=SimpleNamespace(LIMITS=json.loads(self.f.inputs['request'])['resources'],_execute=execute)
 def call(self):
  out=io.StringIO()
  with patch.object(c,'load_adapter',return_value=self.adapter):
   code=c.run(profile=str(self.path),profile_sha256=m.sha(m.raw(self.p)),request_sha256=m.sha(self.data),stdin=io.BytesIO(self.data),out=out,now=lambda:'NOW')
  return code,json.loads(out.getvalue())
 def test_live_accounting_exact_once_and_readonly_status(self):
  code,result=self.call();self.assertEqual(code,0,result);self.assertEqual(self.count,1)
  self.assertEqual(self.call()[0],12);self.assertEqual(self.count,1)
  out=io.StringIO();self.assertEqual(c.status(profile=str(self.path),profile_sha256=m.sha(m.raw(self.p)),request_sha256=m.sha(self.data),stdin=io.BytesIO(self.data),out=out),0)
  self.assertEqual(json.loads(out.getvalue())['state'],'OBSERVED_EXIT_ZERO')
 def test_changed_head_refuses_before_execution(self):
  self.f.f.admit(self.f.f.action(name="other"));self.assertEqual(self.call()[0],12);self.assertEqual(self.count,0)
 def test_changed_host_profile_refuses(self):
  self.path.write_bytes(b'{}');self.assertEqual(self.call()[0],12);self.assertEqual(self.count,0)
 def test_wrong_context_refuses(self):
  self.p['platform_context_sha256']='f'*64;self.path.write_bytes(m.raw(self.p));self.assertEqual(self.call()[0],12);self.assertEqual(self.count,0)
 def test_boundary_revocation_burns_hold_no_execution(self):
  def revoke(root,digest,*,_consume,_before_launch):
   self.path.write_bytes(b'{}');start=m.raw({'preview':digest});(root/'START.json').write_bytes(start);_consume(start)
  self.adapter._execute=revoke
  code,result=self.call();self.assertEqual(code,12);self.assertEqual(result['state'],'UNKNOWN_NO_RETRY');self.assertEqual(self.count,0)
  self.assertEqual(self.f.f.state()['entries'][0]['state'],'UNKNOWN')
 def test_executor_limit_mismatch_refuses(self):
  self.adapter.LIMITS=dict(self.adapter.LIMITS,wall_seconds=999);self.assertEqual(self.call()[0],12);self.assertEqual(self.count,0)

 def test_hostile_supplier_manifest_refused_before_import(self):
  root=self.f.f.base/'engineer';root.mkdir();(root/'__init__.py').write_bytes(b'')
  with self.assertRaises(m.Refused):c.load_adapter({'root':str(root),'files':{'__init__.py':'f'*64}})
  (root/'escape.py').symlink_to(self.sp)
  with self.assertRaises(m.Refused):c.load_adapter({'root':str(root),'files':{'__init__.py':m.sha(b'')}})
 def test_pending_status_refuses(self):
  (self.f.f.old.root/'pending.json').write_bytes(b'pending')
  out=io.StringIO();self.assertEqual(c.status(profile=str(self.path),profile_sha256=m.sha(m.raw(self.p)),request_sha256=m.sha(self.data),stdin=io.BytesIO(self.data),out=out),12)
