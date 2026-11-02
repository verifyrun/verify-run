"""Independent AST-only consumer review; no service or Run process invocation."""
import ast,base64,copy,hashlib,json,io,os,subprocess,tempfile,time,types
from pathlib import Path
root=Path('/private/tmp/verify-engineer-continuation-20261013')
view=root/'engineer/experience/service_test_view.py'
transport=root/'engineer/experience/service_read_cli.py'
cli=root/'engineer/cli.py'
def functions(path,names,ns):
 tree=ast.parse(path.read_bytes())
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
 exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns)
ns=dict(base64=base64,json=json);functions(transport,{'unique'},ns);functions(view,{'validate_response','render'},ns)
art=Path('/private/tmp/verify-run-service-tests-cli-artifacts-20261016')
q=json.loads((art/'S8KETD64_REQUEST.json').read_bytes())
r=json.loads((art/'S8KETD64_RESPONSE.json').read_bytes())
ns['validate_response'](r,q,r['request_sha256'],0)
unknown=copy.deepcopy(r)
unknown['result'].update(state='UNKNOWN',all_selected_cases_reported_success=False,reason_codes=['UNCERTAIN'],report=None,requirements={},refs={})
unknown['result']['costs'].update(input_bytes=None,case_events=None)
ns['validate_response'](unknown,q,r['request_sha256'],0)
assert 'do not establish success' in ns['render']({'verification':unknown['result']})
accepted={}
changes={
 'foreign_refs':lambda x:x['result'].update(refs={'stdout_bytes':'f'*64}),
 'incomplete_report':lambda x:x['result']['report'].update(completed=False),
 'failing_case':lambda x:x['result']['report']['events'][0].update(outcome='failure'),
 'missing_case':lambda x:x['result']['report']['events'].pop(),
 'duplicate_case':lambda x:x['result']['report']['events'].append(x['result']['report']['events'][0]),
 'empty_requirements':lambda x:x['result'].update(requirements={}),
 'arbitrary_limits':lambda x:x['result'].update(selected_limits={}),
 'invalid_costs':lambda x:x['result']['costs'].update(input_bytes=-1,case_events=True),
}
for name,change in changes.items():
 bad=copy.deepcopy(r);change(bad)
 try:ns['validate_response'](bad,q,r['request_sha256'],0)
 except ValueError:accepted[name]='REFUSED'
 else:raise AssertionError('Original mutation accepted: '+name)
class Stream(io.BytesIO):
 def fileno(self):return 99
class Proc:
 def __init__(self):self.stdout=Stream();self.stderr=Stream();self.calls=[]
 def wait(self,timeout=None):
  self.calls.append(timeout)
  if len(self.calls)==2:raise subprocess.TimeoutExpired('fake',timeout)
  return 0
 def poll(self):return 0
class Selector:
 closed=False
 def register(self,*args):pass
 def get_map(self):return {}
 def close(self):self.closed=True
proc=Proc();selector=Selector()
tn=dict(MAX_OUTPUT=65536,TIMEOUT=30,json=json,hashlib=hashlib,os=types.SimpleNamespace(set_blocking=lambda *a:None),
 tempfile=tempfile,time=time,_vfy_path=lambda:'/selected/vfy',
 selectors=types.SimpleNamespace(DefaultSelector=lambda:selector,EVENT_READ=1),
 subprocess=types.SimpleNamespace(PIPE=subprocess.PIPE,Popen=lambda *a,**k:proc,TimeoutExpired=subprocess.TimeoutExpired))
functions(transport,{'read'},tn)
try:tn['read']('check-service-tests',q)
except subprocess.TimeoutExpired:pass
else:raise AssertionError('Expected cleanup failure')
assert proc.calls[1]==1 and proc.stdout.closed and proc.stderr.closed and selector.closed
remaining={}
bad=copy.deepcopy(r);bad['result']['report']['schema']='foreign.report/99'
ns['validate_response'](bad,q,r['request_sha256'],0)
remaining['wrong_report_schema']='ACCEPTED_SUCCESS'
bad=copy.deepcopy(r);bad['result']['costs']['input_bytes']=0
ns['validate_response'](bad,q,r['request_sha256'],0)
remaining['wrong_input_byte_count']='ACCEPTED_SUCCESS'
# Select altered raw stdout and matching references, but leave claimed report as success.
qq=copy.deepcopy(q);rr=copy.deepcopy(r)
report=json.loads(base64.b64decode(qq['inputs']['stdout']['base64']))
report['events'][0]['outcome']='failure'
body=json.dumps(report).encode();digest=hashlib.sha256(body).hexdigest()
qq['inputs']['stdout']={'base64':base64.b64encode(body).decode(),'sha256':digest}
rr['result']['refs']['stdout_bytes']=digest
identity=hashlib.sha256(json.dumps(qq,sort_keys=True,separators=(',',':')).encode()).hexdigest()
rr['request_sha256']=identity
ns['validate_response'](rr,qq,identity,0)
assert ns['render']({'verification':rr['result']}).startswith('The saved selected tests reported success.')
remaining['selected_stdout_failure_claimed_report_success']='ACCEPTED_AND_RENDERED_SUCCESS'
proc=Proc();tn['subprocess'].Popen=lambda *a,**k:proc
def bad_selector():raise OSError('simulated selector setup error')
tn['selectors'].DefaultSelector=bad_selector
try:tn['read']('check-service-tests',q)
except OSError:pass
else:raise AssertionError('Expected setup refusal')
assert not proc.stdout.closed and not proc.stderr.closed and not proc.calls
remaining['selector_setup_error']='NO_REAP_AND_OPEN_PIPES'
print(json.dumps(dict(source_hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (view,transport,cli)},
 unknown_preserved=True,original_reproductions=accepted,corrected_cleanup=dict(final_wait_timeout=1,pipes_and_selector_closed_on_reap_error=True),remaining=remaining,
 service_executed=False,engineer_edited=False,scope='AST extracted validation/render and simulated cleanup only'),indent=2))
