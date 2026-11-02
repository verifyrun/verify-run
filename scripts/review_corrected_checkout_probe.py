"""Read-only source review; exercise extracted p11 only in disposable fixtures."""
import ast,errno,hashlib,json,os,subprocess,tempfile,uuid
from pathlib import Path
from unittest.mock import patch
source=Path('/private/tmp/verify-engineer-continuation-20261013/scripts/audit_real_operational.py')
raw=source.read_bytes();tree=ast.parse(raw)
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='p11')
ns=dict(Path=Path,errno=errno,hashlib=hashlib,json=json,os=os,subprocess=subprocess,uuid=uuid)
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(source),'exec'),ns)
checks={}
with tempfile.TemporaryDirectory(prefix='run-corrected-checkout-review-') as tmp:
 root=Path(tmp)/'repo';root.mkdir()
 def git(*args):
  return subprocess.check_output(['/usr/bin/git','-C',str(root),'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',*args],text=True).strip()
 git('init','-q');(root/'source.txt').write_text('frozen\n');git('add','source.txt')
 git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
 frozen={'immutable_checkout':{'commit':git('rev-parse','HEAD'),'writable':False}}
 frozen['selection_digest']=hashlib.sha256(json.dumps(frozen,sort_keys=True).encode()).hexdigest()
 ns['DOGFOOD']=Path(tmp)/'selection.json';ns['load']=lambda p:frozen
 opened=os.open;closed=os.close
 def deny(path,flags,*a,**kw):
  if Path(path).name.startswith('.verify-write-probe-'):
   assert flags & os.O_EXCL and flags & os.O_NOFOLLOW
   raise PermissionError(errno.EACCES,'simulated open denial')
  return opened(path,flags,*a,**kw)
 for flag in ('assume-unchanged','skip-worktree'):
  git('update-index','--'+flag,'source.txt');(root/'source.txt').write_text('changed\n')
  with patch.object(os,'open',deny):status,why=ns['p11'](root)
  assert status is None and 'index entries' in why
  checks[flag]='REFUSED'
  git('update-index','--no-'+flag,'source.txt');(root/'source.txt').write_text('frozen\n')
 with patch.object(os,'open',deny):status,why=ns['p11'](root)
 assert status=='CHECKOUT_BOUND_ROOT_WRITE_REFUSED' and 'Git-reported clean' in why
 checks['open_denied']='SCOPED_CURRENT_OBSERVATION'
 assert ns['p11'](root)[0] is None and not list(root.glob('.verify-write-probe-*'))
 checks['successful_create']='REFUSED_AND_CLEANED'
 fds=set()
 def tracked(path,flags,*a,**kw):
  fd=opened(path,flags,*a,**kw)
  if Path(path).name.startswith('.verify-write-probe-'):fds.add(fd)
  return fd
 def failing_close(fd):
  closed(fd)
  if fd in fds:raise PermissionError(errno.EACCES,'simulated post-close error')
 with patch.object(os,'open',tracked),patch.object(os,'close',failing_close):
  try:ns['p11'](root)
  except PermissionError:pass
  else:raise AssertionError('close error accepted')
 assert not list(root.glob('.verify-write-probe-*'))
 checks['post_create_close_error']='PROPAGATES_WITH_CLEANUP'
 assert ns['p11'](None)[0]=='NOT_RUN'
# Evaluate actual aggregate predicate and return expression without other audit plants.
main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
caught=next(n.value for n in ast.walk(main) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='caught' for t in n.targets))
ret=next(n.value for n in ast.walk(main) if isinstance(n,ast.Return))
assert eval(compile(ast.Expression(caught),str(source),'eval'),{'status':'NOT_RUN'}) is False
assert eval(compile(ast.Expression(ret),str(source),'eval'),{'ok':False,'rows':[{'status':'NOT_RUN'}]})==2
checks['not_run']='NOT_CAUGHT_EXIT_2'
print(json.dumps(dict(source_sha256=hashlib.sha256(raw).hexdigest(),checks=checks,
 disposition='ACCEPTED_CURRENT_GIT_REPORTED_ROOT_CREATE_OBSERVATION_ONLY',
 historical_checkout_probed=False,service_executed=False,engineer_edited=False),indent=2))
