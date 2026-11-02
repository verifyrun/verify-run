"""Extract p11 only; disposable Git fixtures, no Engineer imports or service actions."""
import ast,errno,hashlib,json,os,subprocess,tempfile,uuid
from pathlib import Path
from unittest.mock import patch
source=Path('/private/tmp/verify-engineer-continuation-20261013/scripts/audit_real_operational.py')
raw=source.read_bytes();tree=ast.parse(raw)
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='p11')
ns=dict(Path=Path,errno=errno,hashlib=hashlib,json=json,os=os,subprocess=subprocess,uuid=uuid)
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(source),'exec'),ns)
results={}
with tempfile.TemporaryDirectory(prefix='run-operational-review-') as tmp:
 root=Path(tmp)/'repo';root.mkdir()
 def git(*args):
  return subprocess.check_output(['/usr/bin/git','-C',str(root),'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',*args],text=True).strip()
 git('init','-q');(root/'source.txt').write_text('frozen\n');git('add','source.txt')
 git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
 frozen={'immutable_checkout':{'commit':git('rev-parse','HEAD'),'writable':False}}
 frozen['selection_digest']=hashlib.sha256(json.dumps(frozen,sort_keys=True).encode()).hexdigest()
 ns['DOGFOOD']=Path(tmp)/'selection.json';ns['load']=lambda p:frozen
 original=Path.open
 def deny(p,*a,**kw):
  if p.name.startswith('.verify-write-probe-'):raise PermissionError(errno.EACCES,'simulated root denial')
  return original(p,*a,**kw)
 for flag in ('assume-unchanged','skip-worktree'):
  git('update-index','--'+flag,'source.txt');(root/'source.txt').write_text('changed\n')
  assert git('status','--porcelain','--untracked-files=all','--ignored')==''
  with patch.object(Path,'open',deny):status,why=ns['p11'](root)
  assert status=='CHECKOUT_BOUND_ROOT_WRITE_REFUSED'
  results[flag]={'tracked_bytes_differ_from_HEAD':True,'status':status,'why':why}
  git('update-index','--no-'+flag,'source.txt');(root/'source.txt').write_text('frozen\n')
 class FailAfterCreation:
  def __init__(self,p):self.p=p
  def __enter__(self):
   self.f=original(self.p,'x');return self
  def write(self,s):raise PermissionError(errno.EACCES,'simulated post-open write denial')
  def __exit__(self,*args):self.f.close()
 def fail_write(p,*a,**kw):
  if p.name.startswith('.verify-write-probe-'):return FailAfterCreation(p)
  return original(p,*a,**kw)
 with patch.object(Path,'open',fail_write):status,why=ns['p11'](root)
 created=list(root.glob('.verify-write-probe-*'))
 assert status=='CHECKOUT_BOUND_ROOT_WRITE_REFUSED' and len(created)==1
 results['write_after_create_denied']={'status':status,'created_file_left_behind':True,'why':why}
 status,why=ns['p11'](None)
 assert status=='NOT_RUN'
 results['not_run_aggregation']={'status':status,'caught_by_current_status_is_not_None':status is not None}
print(json.dumps({'source_sha256':hashlib.sha256(raw).hexdigest(),'reproductions':results,
 'scope':'extracted p11 and disposable fixtures; no sealed subjects or service executions'},indent=2))
