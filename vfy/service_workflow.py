"""Single-attempt pre-observation hold on the existing allocator.

Nested service records retain original validation and authority. They never
replace the outer allocator head. No construction or admission resume exists.
"""
import contextlib
import fcntl
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from vfy import child_ledger as m,service_attempt as service,service_tests
from vfy.service_accounting_cli import bounded_file,MAX_STDIN
from vfy.service_read_cli import _inputs,MAX_INPUTS

FORMAT='vfy.service-workflow/1'
ACQUISITION={'read_bytes','read_files','write_bytes','write_files'}
FIELDS={'schema','scope','service_profile','service_profile_sha256','task_id','attempt_id','paths',
 'acquisition_limits','observation_limits','preparation_limits','adoption_limits','recovery_bytes',
 'action_key','runtime_id','authorization_store_root','labels'}
PATHS={'repository','candidate','tests','venv','parent','requirements'}

def positive(x):return type(x) is int and 0<x<=m.canon.MAX_SAFE_INTEGER
def identity():return {'schema':FORMAT,'source_sha256':m.sha(Path(__file__).read_bytes())}
def fault(stage):pass

class Ledger:
 def __init__(self,path,digest,expected_head):
  self.path=path;self.raw=bounded_file(path,MAX_STDIN)
  m.need(m.sha(self.raw)==digest and m.hex64(expected_head))
  self.profile=p=m.load.load_json_bytes(self.raw)
  m.need(type(p) is dict and set(p)==FIELDS and p['schema']==FORMAT and p['scope']=='DISPOSABLE_DEVELOPMENT_ONLY')
  m.need(m.text(p['task_id']) and m.text(p['attempt_id']) and set(p['paths'])==PATHS)
  m.need(type(p['labels']) is list and bool(p['labels']) and all(type(v) is str and v and all(c.isalnum() or c in '._' for c in v) for v in p['labels']))
  m.need(all(type(v) is str and Path(v).is_absolute() for v in p['paths'].values()))
  m.need(set(p['acquisition_limits'])==ACQUISITION and all(positive(v) for v in p['acquisition_limits'].values()))
  service.resources(p['observation_limits'],positive=True)
  from vfy import service_lifecycle as lifecycle,service_adoption as adoption
  m.need(set(p['preparation_limits'])==lifecycle.PREP_AXES and all(positive(v) for v in p['preparation_limits'].values()))
  adoption._limits(p['adoption_limits']);m.need(positive(p['recovery_bytes']))
  sr=bounded_file(p['service_profile'],MAX_STDIN);m.need(m.sha(sr)==p['service_profile_sha256'])
  self.service_profile=s=m.load.load_json_bytes(sr)
  m.need(s['schema']=='vfy.service-accounting-profile/1' and s['scope']=='DISPOSABLE_DEVELOPMENT_ONLY')
  d=_inputs(s['inputs'],('snapshot','config','predecessor','policy','managed_legacy'),MAX_INPUTS)
  self.data=d;self.legacy=d['snapshot']
  selected=service_tests.load_service_pool(**s['selection'],snapshot_bytes=d['snapshot'],expected_config_bytes=d['config'],
   predecessor_snapshot_bytes=d['predecessor'],policy_bytes=d['policy'],managed_legacy_snapshot_bytes=d['managed_legacy'] or None)
  self.selected=selected;self.owner=selected.owner;self.root=self.owner.root
  self.owner.key=Ed25519PrivateKey.from_private_bytes(bounded_file(s['key_file'],32,secret=True))
  pub=self.owner.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
  m.need(self.owner.trust[self.owner.issuer]=={'public_key_hex':pub,'producer_identity':m.producer()})
  action=p['action_key']
  m.need(type(action) is dict and set(action)=={'key_id','key_version','public_key_hex','status'} and m.hex64(action['public_key_hex']) and m.text(action['key_id']) and positive(action['key_version']) and action['status'] in {'active','revoked'})
  excluded={v['public_key_hex'] for v in self.owner.trust.values()} | {v['public_key_hex'] for v in self.owner.child_trust.values()}
  m.need(action['public_key_hex'] not in excluded and m.text(p['runtime_id']),'Independent final action identity required.')
  self.profile_sha=digest;self.expected=expected_head;self.held=False

 @contextlib.contextmanager
 def locked(self,inspect_pending=False):
  fd=os.open(self.root/'lock',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   m.need(inspect_pending or not os.path.lexists(self.root/'pending.json'),'Interrupted publication; UNKNOWN, no replay.')
   self.current=bounded_file(self.root/'state.json',m.MAX_BYTES)
   m.need(m.sha(self.current)==self.expected,'Workflow head changed.')
   self.check_profile();self.held=True
   yield self
  finally:self.held=False;os.close(fd)

 def check_profile(self):m.need(bounded_file(self.path,MAX_STDIN)==self.raw,'Workflow trust changed.')

 def publish(self,b):
  m.need(self.held,'Existing allocator fence required');self.check_profile()
  b=dict(b,revision=getattr(self,'body',{}).get('revision',0)+1,previous=m.sha(self.current))
  raw=m.raw(m.envelope(b,self.owner.key,self.owner.issuer));m.need(len(raw)<=m.MAX_BYTES)
  m.fresh(self.root/'pending.json',raw);os.replace(self.root/'pending.json',self.root/'state.json');m.sync_dir(self.root)
  self.current=raw;self.body=b;return m.sha(raw)

 def start(self):
  m.need(self.current==self.legacy,'Whole workflow must start at the selected original head.')
  p=self.profile;prior=self.selected.verify_snapshot(self.legacy)
  hold=p['acquisition_limits']['write_bytes']+p['observation_limits']['output_bytes']+p['preparation_limits']['artifact_bytes']+p['adoption_limits']['journal_bytes']+p['recovery_bytes']
  m.need(prior['used']['dispatch_slots']+3<=prior['capacities']['dispatch_slots'] and prior['used']['retained_output_bytes']+hold<=prior['capacities']['retained_output_bytes'],'Combined workflow capacity unavailable.')
  self.publish(dict(schema=FORMAT,identity=identity(),profile_sha256=self.profile_sha,legacy_sha256=m.sha(self.legacy),
   task_id=p['task_id'],attempt_id=p['attempt_id'],pool_root=str(self.root),phase='WORKFLOW_RESERVED',
   nested_raw_hex=self.legacy.hex(),nested_previous_sha256=None,nested_successor_sha256=m.sha(self.legacy),
   reservation=dict(dispatch_slots=3,retained_output_bytes=hold,acquisition=p['acquisition_limits'],observation=p['observation_limits'],preparation=p['preparation_limits'],adoption=p['adoption_limits'],recovery_bytes=p['recovery_bytes']),
   acquisition_used=dict.fromkeys(ACQUISITION,0),preview_sha256=None,attempt_root=None,plan=None,completion=None,
   preparation_transferred=False,recovery_used=False,automatic_retry=False,authority_granted=False,full_physical_cost='UNKNOWN'))
  fault('after_whole_reservation')

 def load(self):
  record=m.load.load_json_bytes(self.current);b=m.authenticate(record,self.owner.trust)
  m.need(record['issuer_identity']==self.owner.issuer and b['schema']==FORMAT and b['identity']==identity()
   and b['profile_sha256']==self.profile_sha and b['legacy_sha256']==m.sha(self.legacy)
   and b['pool_root']==str(self.root) and b['task_id']==self.profile['task_id'] and b['attempt_id']==self.profile['attempt_id']
   and type(b['revision']) is int and b['revision']>0 and m.hex64(b['previous']))
  nested=bytes.fromhex(b['nested_raw_hex']);m.need(m.sha(nested)==b['nested_successor_sha256'])
  self.selected.verify_snapshot(nested)
  self.body=b;return b

 def acquired(self,used,root,preview):
  m.need(self.body['phase']=='WORKFLOW_RESERVED' and set(used)==ACQUISITION)
  m.need(all(type(v) is int and self.body['acquisition_used'][k]<=v<=self.profile['acquisition_limits'][k] for k,v in used.items()))
  m.need(m.hex64(preview) and type(root) is str and Path(root).is_absolute())
  self.body.update(phase='OBSERVATION_PREPARED',acquisition_used=dict(used),attempt_root=root,preview_sha256=preview)
  self.publish(self.body)

 def abandon(self):
  if self.body['phase'] not in {'COMPLETE','UNKNOWN'}:
   self.body['phase']='UNKNOWN';self.publish(self.body)

class NestedServicePool(service.ServicePool):
 """Closed service state writer, held by exactly one existing workflow fence."""
 def __init__(self,ledger):
  super().__init__(ledger.owner,predecessor_snapshot_bytes=ledger.data['predecessor'],policy_bytes=ledger.data['policy'])
  self.workflow=ledger
  self.baseline=len(self._validate(m.load.load_json_bytes(ledger.legacy))['body']['entries'])

 def _publish(self,b):raise m.Refused('Nested workflow never publishes a standalone allocator head.')

 def snapshot(self):
  m.need(self.workflow.held)
  raw=bytes.fromhex(self.workflow.body['nested_raw_hex']);self.verify_snapshot(raw);return raw

 def _change(self,fn):
  w=self.workflow;m.need(w.held and w.body['phase'] in {'OBSERVATION_PREPARED','OBSERVATION_ADMITTED','OBSERVATION_CONSUMED'})
  old=self._validate(m.load.load_json_bytes(self.snapshot()));b=old['body'];fn(b)
  b['revision']+=1;b['previous']=old['sha256'];record=m.envelope(b,self.owner.key,self.owner.issuer)
  self._validate(record)
  added=b['entries'][self.baseline:];m.need(len(added)==1,'Exactly one held observation attempt.')
  e=added[0];q=self._request(bytes.fromhex(e['request_raw_hex']))
  m.need(q['attempt_id']==w.profile['attempt_id'] and q['attempt_root']==w.body['attempt_root']
   and q['preview_sha256']==w.body['preview_sha256'] and all(q['resources'][k]<=w.profile['observation_limits'][k] for k in service.RESOURCES))
  raw=m.raw(record);fault('nested_signed_before_outer_publish')
  state=e['state'];phase={'ADMITTED':'OBSERVATION_ADMITTED','CONSUMED':'OBSERVATION_CONSUMED'}.get(state,'OBSERVATION_SETTLED' if e['result'] is not None and e['unknown'] is None else 'UNKNOWN')
  w.body.update(nested_previous_sha256=w.body['nested_successor_sha256'],nested_successor_sha256=m.sha(raw),nested_raw_hex=raw.hex(),phase=phase)
  w.publish(w.body);return record

class Acquisition:
 def __init__(self,ledger):self.ledger=ledger
 def read(self,path):
  b=self.ledger.body;limit=self.ledger.profile['acquisition_limits'];u=b['acquisition_used']
  m.need(u['read_files']<limit['read_files'],'Acquisition file limit exhausted.')
  remaining=limit['read_bytes']-u['read_bytes'];m.need(remaining>=0)
  # Complete acquisition allowance was held before any reads. Counters retain
  # completed reads; interrupted acquisition retains the entire original hold.
  raw=bounded_file(path,remaining)
  u['read_files']+=1;u['read_bytes']+=len(raw)
  self.ledger.publish(b)
  return raw

def capture(root,meter,limits):
 import stat
 root=Path(root);m.need(root.is_absolute() and root==root.resolve() and root.is_dir())
 files={};manifest={};total=0
 for directory,dirs,names in os.walk(root,followlinks=False):
  dirs[:]=sorted(d for d in dirs if d not in {'.git','__pycache__','.venv','venv','.pytest_cache'})
  m.need(all(not (Path(directory)/d).is_symlink() for d in dirs))
  for name in sorted(names):
   if name in {'.DS_Store'}:continue
   p=Path(directory)/name;rel=p.relative_to(root).as_posix();s=p.lstat()
   m.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and len(files)<limits['files'] and total+s.st_size<=limits['source_bytes'])
   data=meter.read(p);total+=len(data);m.need(total<=limits['source_bytes'])
   files[rel]=data;manifest[rel]=dict(sha256=m.sha(data),bytes=len(data),executable=stat.S_IMODE(s.st_mode)&0o111)
 m.need(bool(files));return files,manifest

def prepare(ledger):
 from vfy import service_adoption as adoption
 b=ledger.body;p=ledger.profile
 m.need(b['phase']=='OBSERVATION_SETTLED' and not b['preparation_transferred'],'Fresh settled observation required; no repeated transfer.')
 b.update(phase='PREPARING',preparation_transferred=True);ledger.publish(b);fault('after_preparation_transfer')
 meter=Acquisition(ledger)
 try:
  base,base_manifest=capture(p['paths']['repository'],meter,p['adoption_limits'])
  candidate,candidate_manifest=capture(p['paths']['candidate'],meter,p['adoption_limits'])
  root=Path(b['attempt_root'])
  selected=dict(selection_bytes=meter.read(root/'TEST_SELECTION.json'),requirements_bytes=meter.read(p['paths']['requirements']),runner_bytes=meter.read(root/'runner/verify_service_runner.py'))
  inputs={k:meter.read(root/name) for k,name in [('preview_bytes','PREVIEW.json'),('start_bytes','START.json'),('result_bytes','RESULT.json'),('stdout_bytes','stdout.bin'),('stderr_bytes','stderr.bin')]}
  nested=bytes.fromhex(b['nested_raw_hex']);inputs['accounting_snapshot_bytes']=nested
  nested_body=ledger.selected._validate(m.load.load_json_bytes(nested))['body'];inputs['request_sha256']=nested_body['entries'][-1]['request_sha256']
  # Only the outer-authenticated exact nested successor is selected for checking.
  kwargs=dict(ledger.service_profile['selection']);kwargs['expected_snapshot_sha256']=m.sha(nested)
  readonly=service_tests.load_service_pool(**kwargs,snapshot_bytes=nested,expected_config_bytes=ledger.data['config'],predecessor_snapshot_bytes=ledger.data['predecessor'],policy_bytes=ledger.data['policy'],managed_legacy_snapshot_bytes=ledger.data['managed_legacy'] or None)
  checker=service_tests.TestObservationChecker(readonly,**selected,limits=dict(input_bytes=p['preparation_limits']['checked_bytes'],cases=64,requirements=64,retained_bytes=p['preparation_limits']['artifact_bytes']))
  counts=dict(copy_bytes=sum(map(len,base.values())),staged_bytes=sum(map(len,candidate.values())),files=len(base)+len(candidate),checked_bytes=sum(len(v) for k,v in inputs.items() if k!='request_sha256')+sum(map(len,selected.values())))
  m.need(all(v<=p['preparation_limits'][k] for k,v in counts.items()))
  managed=adoption.provision_managed_copy(base_manifest_bytes=m.raw(base_manifest),base_files=base,original_root=p['paths']['repository'],limits=p['adoption_limits'])
  b['managed_root']=str(managed);ledger.publish(b);fault('after_managed_copy')
  plan=adoption.prepare_adoption(managed,candidate_manifest_bytes=m.raw(candidate_manifest),candidate_files=candidate,task_id=p['task_id'],checker=checker,check_inputs=inputs,limits=p['adoption_limits'])
  receipt=m.envelope(dict(schema=FORMAT+'/prepared',profile_sha256=ledger.profile_sha,task_id=p['task_id'],attempt_id=p['attempt_id'],base_plan_sha256=m.digest(plan),input_inventory=counts,acquisition_used=b['acquisition_used'],nested_snapshot_sha256=m.sha(nested),predecessor_sha256=m.sha(ledger.current),full_physical_cost='UNKNOWN',authority_granted=False,automatic_retry=False),ledger.owner.key,ledger.owner.issuer)
  plan=dict(plan,preparation_receipt_sha256=m.digest(receipt))
  (managed/'PLAN.json').write_bytes(m.raw(plan))
  with (managed/'PLAN.json').open('rb') as stream:os.fsync(stream.fileno())
  m.sync_dir(managed)
  b.update(phase='PREPARED',plan=plan,preparation_receipt=receipt);head=ledger.publish(b)
  return dict(state='PREPARED',head_sha256=head,plan=plan,preparation_receipt=receipt,automatic_retry=False,full_physical_cost='UNKNOWN')
 except BaseException:
  ledger.abandon();raise

def session(*,profile,profile_sha256,expected_head,input_fd,output_fd,session_id,now,monotonic):
 from vfy.service_accounting_cli import Pipe,Session
 pipe=Pipe(input_fd,output_fd,300,monotonic);sequence=0;ledger=None;done=False
 def response(state,record=None,error=None,digest=None):
  return dict(schema='vfy.service-workflow-response/1',profile_sha256=profile_sha256,session_id=session_id,sequence=sequence,request_sha256=digest,state=state,record=record,error=error,authority_granted=False,automatic_retry=False,full_cost='UNKNOWN')
 try:
  ledger=Ledger(profile,profile_sha256,expected_head)
  with ledger.locked():
   ledger.start();pool=NestedServicePool(ledger);inner=Session(pool,profile_sha256,session_id,now)
   try:
    pipe.write(response('WORKFLOW_RESERVED',dict(head_sha256=m.sha(ledger.current),reservation=ledger.body['reservation'],paths=ledger.profile['paths'])))
    while not done:
     raw=pipe.read();q=m.load.load_json_bytes(raw)
     m.need(type(q) is dict and set(q)=={'schema','session_id','sequence','operation','inputs'} and q['schema']=='vfy.service-workflow-frame/1'
      and q['session_id']==session_id and type(q['sequence']) is int and q['sequence']==sequence+1)
     op=q['operation'];sequence+=1
     if op=='ACQUIRED':
      data=_inputs(q['inputs'],('acquisition',),MAX_INPUTS);a=m.load.load_json_bytes(data['acquisition'])
      m.need(set(a)=={'used','root','preview_sha256'})
      ledger.acquired(a['used'],a['root'],a['preview_sha256']);record=dict(head_sha256=m.sha(ledger.current));state='OBSERVATION_PREPARED'
     elif op in {'ADMIT','CONSUME','SETTLE','UNKNOWN'}:
      frame=dict(q,schema='vfy.service-accounting-frame/1',sequence=inner.sequence+1)
      result=inner.handle(m.raw(frame)+b'\n');record=result['record'];state=result['state']
      if op=='UNKNOWN':done=True
     elif op=='METER':
      data=_inputs(q['inputs'],('acquisition',),MAX_INPUTS);used=m.load.load_json_bytes(data['acquisition'])
      m.need(ledger.body['phase']=='OBSERVATION_SETTLED' and set(used)==ACQUISITION)
      m.need(all(type(v) is int and ledger.body['acquisition_used'][k]<=v<=ledger.profile['acquisition_limits'][k] for k,v in used.items()))
      ledger.body['acquisition_used']=used;ledger.publish(ledger.body);record=dict(head_sha256=m.sha(ledger.current));state='METERED'
     elif op=='PREPARE':
      m.need(q['inputs']=={});record=prepare(ledger);state='PREPARED';done=True
     else:raise ValueError('Unsupported workflow stage')
     pipe.write(response(state,record,digest=m.sha(raw)))
    return 0
   finally:
    pool._live.clear()
    if not done:
     try:ledger.abandon()
     except Exception:pass
 except Exception as exc:
  try:pipe.write(response('REFUSED_OR_UNKNOWN',error=type(exc).__name__))
  except Exception:pass
  return 12

def recover(ledger):
 with ledger.locked(inspect_pending=True):
  pending=ledger.root/'pending.json'
  if os.path.lexists(pending):
   marker=ledger.root/('workflow-recovery-'+ledger.profile_sha+'.json')
   m.need(not os.path.lexists(marker),'Recovery already consumed.')
   raw=bounded_file(pending,ledger.profile['recovery_bytes']);record=m.load.load_json_bytes(raw);b=m.authenticate(record,ledger.owner.trust)
   m.need(record['issuer_identity']==ledger.owner.issuer and b['schema']==FORMAT and b['identity']==identity()
    and b['profile_sha256']==ledger.profile_sha and b['legacy_sha256']==m.sha(ledger.legacy)
    and b['previous']==m.sha(ledger.current) and b['pool_root']==str(ledger.root)
    and b['task_id']==ledger.profile['task_id'] and b['attempt_id']==ledger.profile['attempt_id']
    and type(b['revision']) is int and b['revision']>0 and not b['recovery_used']
    and b['reservation']['recovery_bytes']==ledger.profile['recovery_bytes'])
   if ledger.current==ledger.legacy:m.need(b['revision']==1 and b['phase']=='WORKFLOW_RESERVED')
   else:
    old=ledger.load();m.need(b['revision']==old['revision']+1 and not old['recovery_used'])
   receipt=m.envelope(dict(schema=FORMAT+'/publication-recovery',current_sha256=m.sha(ledger.current),pending_sha256=m.sha(raw),state='UNKNOWN_PUBLICATION',charged_recovery_bytes=ledger.profile['recovery_bytes'],authority_granted=False,automatic_retry=False),ledger.owner.key,ledger.owner.issuer)
   m.fresh(marker,m.raw(receipt));m.sync_dir(ledger.root)
   return dict(state='UNKNOWN_PUBLICATION',head_sha256=m.sha(ledger.current),receipt=receipt,construction_resumed=False,automatic_retry=False,authority_granted=False)
  b=ledger.load();m.need(not b['recovery_used'] and len(ledger.current)<=ledger.profile['recovery_bytes'],'Recovery allowance unavailable.')
  b['recovery_used']=True;head=ledger.publish(b)
  return dict(state=b['phase'],head_sha256=head,completion=b['completion'],construction_resumed=False,automatic_retry=False,authority_granted=False,full_physical_cost='UNKNOWN')
