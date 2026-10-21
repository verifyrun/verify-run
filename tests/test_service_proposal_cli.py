"""Fresh synthetic proposal bytes only; never execute a selected child."""
import base64,io,json,unittest
from unittest.mock import patch
from tests.test_service_attempt import ServiceTests
from vfy import child_ledger as m,service_proposal_cli as c,service_attempt,service_tests

def packed(raw):return dict(base64=base64.b64encode(raw).decode(),sha256=m.sha(raw))
class ProposalTests(unittest.TestCase):
 def setUp(self):
  self.f=ServiceTests();self.f.setUp();self.addCleanup(self.f.tearDown);self.addCleanup(self.f.doCleanups);f=self.f
  request,preview=f.action();p=json.loads(preview);runner=b'NOT_EXECUTED';task=b'bounded selected task'
  requirements=m.raw(dict(schema='vfy.service-requirements/1',requirements={'R':'selected example'}))
  selection=dict(schema='vfy.service-test-selection/1',labels=p['labels'],case_ids=['case1'],requirement_cases={'R':['case1']},requirements_sha256=m.sha(requirements),runner_sha256=m.sha(runner),adapter_sha256=p['adapter_sha256'],capture_sha256=p['capture_sha256'],authority_granted=False,automatic_retry=False,**{n+'_sha256':m.digest(p[n]) for n in ('source','examiner','environment')})
  selected=m.raw(selection);p.update(test_selection_sha256=m.sha(selected),test_runner_sha256=m.sha(runner),task_successor_binding=dict(schema='vfy.service-test-task-binding/1',task_sha256=m.sha(task),revision=1,predecessor_observation_sha256=None,authority_granted=False,automatic_retry=False));preview=m.raw(p);request['preview_sha256']=m.sha(preview)
  context=m.raw(dict(pool_root=str(f.old.root),config_hex=f.old.config_bytes.hex(),owner_trust=f.old.trust,child_trust=f.old.child_trust,observer=f.old.observer,head_hex=f.head.hex(),policy_hex=f.kw['policy_bytes'].hex()))
  self.inputs=dict(context=context,snapshot=f.pool.snapshot(),selection=selected,requirements=requirements,runner=runner,preview=preview,request=m.raw(request),approval=f.approval(request,preview),workflow=m.raw(dict(schema='vfy.service-workflow/1',scope='DISPOSABLE_DEVELOPMENT_ONLY',labels=p['labels'],observation_limits=request['resources'])),task=task,platform_context=m.raw({'caller':'selected reference only'}))
  self.q=dict(schema='vfy.service-proposal-preflight-request/1',module_sha256=c.CHECKER_SHA256,minimum_revision=1,inputs={k:packed(v) for k,v in self.inputs.items()},limits=dict(input_bytes=16777216,output_bytes=1048576,cases=20,requirements=10))
 def call(self,q=None):
  raw=m.raw(q or self.q);out=io.StringIO();code=c.run(request_sha256=m.sha(raw),stdin=io.BytesIO(raw),out=out);return code,json.loads(out.getvalue())
 def test_no_capability_or_live_read_and_explicit_limits(self):
  original=m.read_file
  def code_only(path):
   self.assertEqual(path.name,'service_tests.py');return original(path)
  before=self.f.pool.snapshot()
  with patch.object(m,'read_file',side_effect=code_only),patch.object(service_attempt.ServicePool,'attach',side_effect=AssertionError('attach')),patch.object(service_attempt.ServicePool,'_preview',side_effect=AssertionError('live preview')),patch.object(service_attempt.ServicePool,'admit',side_effect=AssertionError('admit')):
   code,r=self.call()
  self.assertEqual(code,0,r);self.assertEqual(before,self.f.pool.snapshot());self.assertFalse(r['result']['admission_granted']);self.assertEqual(r['result']['live_head_freshness'],'UNESTABLISHED')
 def test_each_raw_input_pin_refused(self):
  for name in c.NAMES:
   q=json.loads(m.raw(self.q));q['inputs'][name]['sha256']='f'*64;self.assertEqual(self.call(q)[0],12,name)
 def test_signed_wrong_request_approval_refused(self):
  q=json.loads(m.raw(self.q));request=json.loads(self.inputs['request']);request['attempt_id']='other';q['inputs']['approval']=packed(self.f.approval(request,self.inputs['preview']));self.assertEqual(self.call(q)[0],12)
 def test_changed_preview_task_workflow_or_selection_refused(self):
  for name,value in [('task',b'other'),('workflow',m.raw({'schema':'bad'})),('preview',m.raw({'schema':'bad'})),('runner',b'other')]:
   q=json.loads(m.raw(self.q));q['inputs'][name]=packed(value);self.assertEqual(self.call(q)[0],12,name)
 def test_consumed_selected_attempt_refused(self):
  request=json.loads(self.inputs['request']);p=self.inputs['preview'];from pathlib import Path
  (Path(request['attempt_root'])/'PREVIEW.json').write_bytes(p)
  self.f.admit((request,p));q=json.loads(m.raw(self.q));q['inputs']['snapshot']=packed(self.f.pool.snapshot());self.assertEqual(self.call(q)[0],12)
 def test_changed_trust_limits_and_checker_refused(self):
  for change in ({'module_sha256':'f'*64},{'minimum_revision':999},{'limits':dict(self.q['limits'],input_bytes=1)}):self.assertEqual(self.call(dict(self.q,**change))[0],12)
  q=json.loads(m.raw(self.q));ctx=json.loads(self.inputs['context']);ctx['owner_trust']={};q['inputs']['context']=packed(m.raw(ctx));self.assertEqual(self.call(q)[0],12)
