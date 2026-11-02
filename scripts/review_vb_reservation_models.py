"""Read-only selected-source integrity and finite model witnesses; no Run actions."""
from pathlib import Path
import hashlib,json,subprocess
root=Path('/private/tmp/verify-vb-recovery-backup-20261016')
workspace=Path('/private/tmp/verify-vb-fork-credit-20261016')
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert commit=='d7046e2bad1bd15f14f7a13aabc140a5771f073c'
files={}
for folder in ('vb-fork-credit-20261016','vb-reservation-refinement-20261016','vb-keyed-settlement-20261016'):
 p=root/'docs/research'/folder
 for line in (p/'SHA256SUMS').read_text().splitlines():
  digest,name=line.split(None,1);f=p/name.lstrip('* ')
  assert hashlib.sha256(f.read_bytes()).hexdigest()==digest
  files[str(f.relative_to(root))]=digest
 for f in p.glob('*.lean'):assert f.read_bytes()==(workspace/f.name).read_bytes()
def reserve(l,cap,overhead):
 s,p,f=l
 return (s+overhead,p+cap,f-cap-overhead) if cap+overhead<=f else None
def settle(l,cap,actual,overhead):
 s,p,f=l
 return (s+actual+overhead,p-cap,f-overhead+cap-actual) if cap<=p and actual<=cap and overhead<=f else None
def issue(state,key,cap,overhead):
 l,entries=state
 if key in entries:return None
 n=reserve(l,cap,overhead)
 return None if n is None else (n,dict(entries,**{key:cap}))
def complete(state,key,actual,overhead):
 l,entries=state
 if key not in entries or entries[key] is None:return None
 n=settle(l,entries[key],actual,overhead)
 return None if n is None else (n,dict(entries,**{key:None}))
assert settle((0,12,0),6,0,0)==(0,6,6)
assert settle((0,6,6),6,0,0)==(0,0,12)
s=issue(((0,0,10),{}),'id',6,0);t=complete(s,'id',6,0)
assert complete(t,'id',6,0) is None and issue(t,'id',6,0) is None
assert sum(t[0])==sum(s[0])==10
# Reusing an old immutable input is possible in the mathematical function interface.
assert complete(s,'id',6,0)==t
# Two authentic branches on a cloned pre-issue input both locally fit.
a=issue(((0,0,10),{}),'left',6,0);b=issue(((0,0,10),{}),'right',6,0)
assert a and b and a[0][1]+b[0][1]==12
invalid=((0,6,0),{'left':6,'right':6})
assert sum(invalid[1].values())>invalid[0][1]
run=Path('/private/tmp/verify-run-service-session-cli-20261016')
modules={name:hashlib.sha256((run/'vfy'/name).read_bytes()).hexdigest() for name in
 ('common_capacity.py','service_attempt.py','service_accounting_cli.py','service_review.py','service_adoption.py','child_ledger.py')}
print(json.dumps(dict(selected_commit=commit,manifest_members=files,workspace_sources_equal=True,
 finite_model_witnesses=dict(aggregate_indistinguishable_double_settle=True,immediate_no_repeat=True,
 no_reissue=True,total_conserved=True,rollback_reuses_precompletion_state=True,
 cloned_issue_states_overallocate=True,arbitrary_state_lacks_pending_sum_invariant=True),
 runtime_module_hashes=modules,lean_compiler_rerun=False,
 scope='Source proof review and finite Python mirrors only; not Lean proof or runtime refinement',
 service_or_pool_actions=False),indent=2))
