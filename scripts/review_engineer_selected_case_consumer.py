"""Independent AST-only consumer review; no service or Run process invocation."""
import ast,copy,hashlib,json,io,os,subprocess,tempfile,time,types
from pathlib import Path
root=Path('/private/tmp/verify-engineer-continuation-20261013')
view=root/'engineer/experience/service_test_view.py'
transport=root/'engineer/experience/service_read_cli.py'
cli=root/'engineer/cli.py'
def functions(path,names,ns):
 tree=ast.parse(path.read_bytes())
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
 exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns)
ns={};functions(view,{'validate_response','render'},ns)
art=Path('/private/tmp/verify-run-service-tests-cli-artifacts-20261016')
q=json.loads((art/'S8KETD64_REQUEST.json').read_bytes())
r=json.loads((art/'S8KETD64_RESPONSE.json').read_bytes())
ns['validate_response'](r,q,r['request_sha256'],0)
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
 ns['validate_response'](bad,q,r['request_sha256'],0)
 text=ns['render']({'verification':bad['result']})
 assert text.startswith('The saved selected tests reported success.')
 accepted[name]='ACCEPTED_AND_RENDERED_SUCCESS'
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
assert proc.calls[1] is None and not proc.stdout.closed and not proc.stderr.closed and not selector.closed
print(json.dumps(dict(source_hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (view,transport,cli)},
 false_success_reproductions=accepted,cleanup=dict(unbounded_final_wait=True,cleanup_error_leaves_pipes_and_selector_open=True),
 service_executed=False,engineer_edited=False,scope='AST extracted validation/render and simulated cleanup only'),indent=2))
