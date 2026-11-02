"""Explicit isolated-copy adoption. No service executor, implicit grants or retries.

Trusted local controller and cooperative filesystem; see SERVICE_ADOPTION_CONTRACT.md.
"""
import contextlib
import fcntl
import os
import stat
import tempfile
import threading
from pathlib import Path, PurePosixPath
from vfy import child_ledger as m, common_capacity as common, service_attempt as service
from vfy import service_tests, authorization as auth, store

PROFILE = 'vfy.service-adoption/1'
RESOURCES = ('read_bytes', 'write_bytes', 'file_mutations', 'journal_bytes')
FLAGS = dict(authority_granted=False, automatic_retry=False)


def identity():
    return dict(profile=PROFILE, source_sha256=m.sha(Path(__file__).read_bytes()))


def _limits(value):
    m.need(type(value) is dict and set(value) == {'files', 'source_bytes', *RESOURCES})
    m.need(all(common.integer(v) and v > 0 for v in value.values()))


def _manifest(raw, limits):
    _limits(limits)
    v=m.load.load_json_bytes(raw)
    m.need(type(v) is dict and 0 < len(v) <= limits['files'])
    total=0
    for name, entry in v.items():
        p=PurePosixPath(name)
        m.need(m.text(name) and not p.is_absolute() and str(p)==name and
               all(c not in ('.','..','.git') for c in p.parts) and '\\' not in name and
               len(p.parts)<=64 and len(name.encode('utf-8'))<=4096 and '\x00' not in name)
        m.need(type(entry) is dict and set(entry)=={'sha256','bytes','executable'})
        m.need(m.hex64(entry['sha256']) and common.integer(entry['bytes']) and
               entry['bytes'] <= m.MAX_BYTES and common.integer(entry['executable']) and
               entry['executable'] & ~0o111 == 0)
        m.need(not any(str(parent) in v for parent in p.parents if str(parent)!='.'))
        total+=entry['bytes']
    m.need(total <= limits['source_bytes'])
    return v


def _payloads(manifest, files):
    m.need(type(files) is dict and set(files)==set(manifest))
    for p,b in files.items():
        m.need(type(b) is bytes and len(b)==manifest[p]['bytes'] and m.sha(b)==manifest[p]['sha256'])


def _path(value):
    p=Path(value)
    m.need(p.is_absolute() and p==p.resolve(), 'Canonical unaliased path required.')
    return p


def _disjoint(a,b):
    m.need(a!=b and a not in b.parents and b not in a.parents, 'Original and managed/store roots must be disjoint.')


def _dir_id(p):
    s=p.lstat()
    m.need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid())
    return dict(path=str(p),device=s.st_dev,inode=s.st_ino,uid=s.st_uid)


def _fixture(root):
    root=_path(root)
    m.need(root.parent==Path(tempfile.gettempdir()).resolve() and root.name.startswith('verify-service-adoption-'))
    m.need(root.stat().st_mode & 0o077 == 0)
    v=m.load.load_json_bytes(m.read_file(root/'FIXTURE.json'))
    m.need(v['schema']==PROFILE and v['root']==_dir_id(root) and v['copy']==_dir_id(root/'copy'))
    _disjoint(root,_path(v['original_root']));_limits(v['limits'])
    return v


@contextlib.contextmanager
def _locked(root, *, shared=False):
    _fixture(root)
    fd=os.open(root/'LOCK',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);m.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1)
        fcntl.flock(fd,(fcntl.LOCK_SH if shared else fcntl.LOCK_EX)|fcntl.LOCK_NB)
        _fixture(root)
        yield
    finally:os.close(fd)


class _Meter:
    def __init__(self,limits):self.limits=limits;self.used=dict.fromkeys(RESOURCES,0)
    def charge(self,k,n):
        m.need(self.used[k]+n <= self.limits[k], 'Declared '+k+' exhausted.')
        self.used[k]+=n
    def read(self,p):
        # Check before reading, not just after allocating bytes.
        size=p.lstat().st_size
        self.charge('read_bytes',size)
        data=m.read_file(p);m.need(len(data)==size)
        return data


def _scan(root,limits,meter=None):
    result={};total=0;directories=0
    for parent, dirs, files in os.walk(root,followlinks=False):
        for name in dirs:
            directories+=1;m.need(directories<=limits['files']*64,'Directory walk bound exceeded.')
            p=Path(parent)/name
            m.need(stat.S_ISDIR(p.lstat().st_mode) and p==p.resolve())
        for name in files:
            p=Path(parent)/name;relative=p.relative_to(root).as_posix()
            m.need(len(result)<limits['files'] and total+p.lstat().st_size<=limits['source_bytes'])
            raw=meter.read(p) if meter else m.read_file(p)
            total+=len(raw);m.need(total<=limits['source_bytes'])
            result[relative]=dict(sha256=m.sha(raw),bytes=len(raw),executable=p.stat().st_mode & 0o111)
    return result


def provision_managed_copy(*,base_manifest_bytes,base_files,original_root,limits):
    base=_manifest(base_manifest_bytes,limits);_payloads(base,base_files)
    original=_path(original_root);m.need(original.is_dir())
    root=Path(tempfile.mkdtemp(prefix='verify-service-adoption-')).resolve()
    _disjoint(root,original)
    (root/'copy').mkdir(mode=0o700)
    for name,b in base_files.items():
        p=root/'copy'/name;p.parent.mkdir(parents=True,exist_ok=True)
        m.fresh(p,b);os.chmod(p,0o600|base[name]['executable'])
        with p.open('rb') as f:os.fsync(f.fileno())
    for parent,_,_ in os.walk(root/'copy',topdown=False):m.sync_dir(Path(parent))
    m.fresh(root/'BASE.json',base_manifest_bytes)
    m.fresh(root/'LOCK',b'')
    fixture=dict(schema=PROFILE,root=_dir_id(root),copy=_dir_id(root/'copy'),
        original_root=str(original),base_sha256=m.sha(base_manifest_bytes),limits=limits,
        preparation=dict(files=len(base),source_bytes=sum(e['bytes'] for e in base.values()),
                         shared_pool_charged=False),**FLAGS)
    m.fresh(root/'FIXTURE.json',m.raw(fixture))
    return root


def prepare_adoption(root,*,candidate_manifest_bytes,candidate_files,task_id,checker,check_inputs,limits):
    root=_path(root);_limits(limits);m.need(m.text(task_id))
    m.need(type(checker) is service_tests.TestObservationChecker)
    candidate=_manifest(candidate_manifest_bytes,limits);_payloads(candidate,candidate_files)
    with _locked(root):
        fixture=_fixture(root);m.need(fixture['limits']==limits)
        base=_manifest(m.read_file(root/'BASE.json'),limits)
        m.need(set(base)==set(candidate),'Only replacement of frozen source population supported.')
        m.need(_scan(root/'copy',limits)==base,'Managed copy is not complete BASE.')
        check=checker.check(**check_inputs)
        m.need(check['state']=='OBSERVED_SELECTED_CASES_SUCCESS','Selected observations not accepted.')
        preview=service.evidence(check_inputs['preview_bytes'])
        m.need(preview['source']==candidate,'Candidate differs from exact tested source.')
        changed=sorted(p for p in base if base[p]!=candidate[p]);m.need(bool(changed))
        m.need(len(changed)<=limits['file_mutations'] and
               sum(candidate[p]['bytes'] for p in changed)<=limits['write_bytes'])
        evidence=dict(checker.selected,**{k:v for k,v in check_inputs.items() if k!='request_sha256'})
        evidence['request_sha256']=m.raw(check_inputs['request_sha256'])
        evidence['check']=m.raw(check)
        m.need(all(type(b) is bytes and len(b)<=m.MAX_BYTES for b in evidence.values()))
        plan=dict(schema='vfy.service-adoption-plan/1',fixture=fixture,
            original_root=fixture['original_root'],destination=str(root/'copy'),task_id=task_id,
            base_manifest=base,candidate_manifest=candidate,changed_paths=changed,
            evidence_sha256={p:m.sha(b) for p,b in evidence.items()},check_sha256=m.sha(evidence['check']),
            requirements_sha256=m.sha(evidence['requirements_bytes']),selection_sha256=m.sha(evidence['selection_bytes']),
            producer_identity=identity(),limits=dict(limits),
            accounting_pool_root=str(checker.pool.root),
            accounting_predecessor_sha256=m.sha(check_inputs['accounting_snapshot_bytes']),**FLAGS)
        # Reserved journal includes frozen records plus bounded final records.
        retained=sum(map(len,evidence.values()))+len(m.raw(plan))+len(candidate_manifest_bytes)+len(m.read_file(root/'BASE.json'))+len(m.raw(fixture))
        m.need(retained+65536<=limits['journal_bytes'],'Insufficient retained journal reservation.')
        (root/'evidence').mkdir(mode=0o700);(root/'candidate').mkdir(mode=0o700);(root/'stage').mkdir(mode=0o700)
        for p,b in evidence.items():m.fresh(root/'evidence'/p,b)
        for i,p in enumerate(changed):m.fresh(root/'candidate'/str(i),candidate_files[p])
        m.fresh(root/'CANDIDATE.json',candidate_manifest_bytes)
        m.fresh(root/'PLAN.json',m.raw(plan))
        return plan


def action_for(plan):
    return dict(candidate_id=m.digest(plan),kind='custom',action=dict(
        summary='Adopt approved service repair into isolated managed copy',tool=PROFILE,
        targets=[plan['destination']],params=dict(plan_sha256=m.digest(plan))))


def _plan(root,plan,meter=None):
    read=meter.read if meter else m.read_file
    fixture=_fixture(root)
    m.need(read(root/'PLAN.json')==m.raw(plan) and plan['fixture']==fixture and
           plan['schema']=='vfy.service-adoption-plan/1' and plan['producer_identity']==identity() and
           plan['destination']==str(root/'copy') and plan['original_root']==fixture['original_root'] and
           all(plan[k] is False for k in FLAGS))
    limits=plan['limits'];_limits(limits);m.need(limits==fixture['limits'])
    base=_manifest(read(root/'BASE.json'),limits);candidate=_manifest(read(root/'CANDIDATE.json'),limits)
    m.need(m.sha(m.raw(base))==m.sha(m.raw(plan['base_manifest'])))
    m.need(m.sha(read(root/'BASE.json'))==fixture['base_sha256'])
    m.need(plan['accounting_predecessor_sha256']==plan['evidence_sha256']['accounting_snapshot_bytes'])
    m.need(base==plan['base_manifest'] and candidate==plan['candidate_manifest'] and set(base)==set(candidate))
    m.need(plan['changed_paths']==sorted(p for p in base if base[p]!=candidate[p]))
    m.need(set(p.name for p in (root/'evidence').iterdir())==set(plan['evidence_sha256']))
    for name,digest in plan['evidence_sha256'].items():
        m.need('/' not in name and name not in ('.','..') and m.sha(read(root/'evidence'/name))==digest)
    m.need(plan['check_sha256']==plan['evidence_sha256']['check'] and
           plan['requirements_sha256']==plan['evidence_sha256']['requirements_bytes'] and
           plan['selection_sha256']==plan['evidence_sha256']['selection_bytes'])
    return base,candidate


class AdoptionPool:
    """Explicit monotone successor at the selected ServicePool's existing state/lock."""
    def __init__(self,predecessor,*,expected_snapshot_bytes,policy_bytes):
        m.need(type(predecessor) is service.ServicePool)
        self.service=predecessor;self.owner=predecessor.owner;self.root=predecessor.root
        self.head=expected_snapshot_bytes;prior=predecessor.verify_snapshot(self.head)
        self.prior=m.load.load_json_bytes(self.head);self.base_used=prior['used'];self.caps=prior['capacities']
        self.policy_bytes=policy_bytes;self.policy=p=m.load.load_json_bytes(policy_bytes)
        m.need(set(p)=={'schema','pool_root','predecessor_sha256','producer_identity','resource_capacities',
                       'runtime_id','authorization_store_root','action_key',*FLAGS})
        m.need(p['schema']=='vfy.service-adoption-policy/1' and p['pool_root']==str(self.root) and
               p['predecessor_sha256']==m.sha(self.head) and p['producer_identity']==identity() and
               all(p[k] is False for k in FLAGS) and m.text(p['runtime_id']))
        m.need(set(p['resource_capacities'])==set(RESOURCES) and
               all(common.integer(v) for v in p['resource_capacities'].values()))
        _path(p['authorization_store_root']);k=p['action_key']
        m.need(set(k)=={'key_id','key_version','public_key_hex'} and m.text(k['key_id']) and
               common.integer(k['key_version']) and k['key_version']>0 and m.hex64(k['public_key_hex']))
        excluded={v['public_key_hex'] for v in self.owner.trust.values()}
        excluded.update(v['public_key_hex'] for v in self.owner.child_trust.values())
        m.need(k['public_key_hex'] not in excluded,'Select independent current action trust.')
        self._live=set();self._cap_lock=threading.Lock()

    @classmethod
    def attach(cls,predecessor,*,expected_snapshot_bytes,policy_bytes):
        o=cls(predecessor,expected_snapshot_bytes=expected_snapshot_bytes,policy_bytes=policy_bytes)
        with o.owner.locked():
            m.need(m.read_file(o.root/'state.json')==o.head,'Selected shared head changed; no reset.')
            o._publish(dict(schema=PROFILE,pool_root=str(o.root),policy_sha256=m.sha(policy_bytes),
                producer_identity=identity(),predecessor_raw_hex=o.head.hex(),entries=[],
                revision=o.prior['body']['revision']+1,previous=o.prior['sha256'],**FLAGS))
        return o

    def _totals(self,b):
        used=dict(self.base_used);adoption=dict.fromkeys(RESOURCES,0)
        for e in b['entries']:
            used['dispatch_slots']+=1;used['retained_output_bytes']+=e['resources']['journal_bytes']
            for k in RESOURCES:adoption[k]+=e['resources'][k]
        m.need(all(common.integer(v) and v<=self.caps[k] for k,v in used.items()),'Shared pool exhausted.')
        m.need(all(common.integer(v) and v<=self.policy['resource_capacities'][k] for k,v in adoption.items()),'Adoption resource capacity exhausted.')
        return used,adoption

    def _validate(self,record):
        b=m.authenticate(record,self.owner.trust);m.need(record['issuer_identity']==self.owner.issuer)
        m.need(set(b)=={'schema','pool_root','policy_sha256','producer_identity','predecessor_raw_hex',
                       'entries','revision','previous',*FLAGS})
        m.need(b['schema']==PROFILE and b['pool_root']==str(self.root) and
               b['policy_sha256']==m.sha(self.policy_bytes) and b['producer_identity']==identity() and
               b['predecessor_raw_hex']==self.head.hex() and all(b[k] is False for k in FLAGS) and m.hex64(b['previous']))
        m.need(type(b['entries']) is list);seen=set();roots=set();events=1
        for e in b['entries']:
            m.need(set(e)=={'plan_sha256','root','resources','recorded_at','intent','completion'})
            m.need(m.hex64(e['plan_sha256']) and m.text(e['root']) and m.text(e['recorded_at']) and
                   e['plan_sha256'] not in seen and e['root'] not in roots)
            seen.add(e['plan_sha256']);roots.add(e['root'])
            m.need(set(e['resources'])==set(RESOURCES) and all(common.integer(v) and v>0 for v in e['resources'].values()))
            events+=1
            if e['intent'] is not None:
                m.need(m.hex64(e['intent']));events+=1
            if e['completion'] is not None:
                m.need(e['intent'] is not None and m.hex64(e['completion']));events+=1
        m.need(b['revision']==self.prior['body']['revision']+events)
        self._totals(b);return record

    def _publish(self,b):
        record=m.envelope(b,self.owner.key,self.owner.issuer);self._validate(record)
        raw=m.raw(record);m.need(len(raw)<=m.MAX_BYTES)
        m.fresh(self.root/'pending.json',raw);os.replace(self.root/'pending.json',self.root/'state.json');m.sync_dir(self.root)
        return record

    def _change(self,fn):
        with self.owner.locked():
            old=self._validate(m.load.load_json_bytes(m.read_file(self.root/'state.json')))
            b=old['body'];fn(b);b['revision']+=1;b['previous']=old['sha256'];return self._publish(b)

    def snapshot(self):
        with self.owner.locked():
            raw=m.read_file(self.root/'state.json');self.verify_snapshot(raw);return raw

    def verify_snapshot(self,raw):
        b=self._validate(m.load.load_json_bytes(raw))['body'];used,adoption=self._totals(b)
        return dict(state='VERIFIED_SELECTED_ADOPTION_ACCOUNTING_NOT_FRESHNESS',used=used,
            capacities=self.caps,adoption_used=adoption,adoption_capacities=self.policy['resource_capacities'],
            revision=b['revision'],full_lifecycle='UNKNOWN',**FLAGS)

    def reserve(self,plan,*,recorded_at):
        root=_path(plan['fixture']['root']['path']);m.need(m.text(recorded_at))
        m.need(plan['accounting_pool_root']==str(self.root) and
               plan['accounting_predecessor_sha256']==m.sha(self.head),
               'Adoption must inherit the exact checked service pool/head.')
        with _locked(root,shared=True):
            m.need(m.read_file(root/'PLAN.json')==m.raw(plan))
        key=m.digest(plan)
        def change(b):
            b['entries'].append(dict(plan_sha256=key,root=str(root),resources={k:plan['limits'][k] for k in RESOURCES},
                                    recorded_at=recorded_at,intent=None,completion=None))
        with self._cap_lock:
            ticket=self._change(change);self._live.add(key);return ticket

    def _key(self,ticket,plan):
        b=self._validate(ticket)['body'];m.need(bool(b['entries']))
        e=b['entries'][-1];m.need(e['plan_sha256']==m.digest(plan) and e['intent'] is None)
        return e['plan_sha256']

    def _consume(self,ticket,plan,intent):
        key=self._key(ticket,plan)
        with self._cap_lock:
            m.need(key in self._live,'No live reservation; UNKNOWN, no retry.')
            self._live.remove(key)
            def change(b):
                e=next(e for e in b['entries'] if e['plan_sha256']==key)
                m.need(e['intent'] is None);e['intent']=m.digest(intent)
            return self._change(change)

    def _complete(self,ticket,plan,receipt):
        key=self._key(ticket,plan)
        def change(b):
            e=next(e for e in b['entries'] if e['plan_sha256']==key)
            m.need(e['intent'] is not None and e['completion'] is None)
            e['completion']=m.digest(receipt)
        return self._change(change)


def _fault(stage):
    """Test injection seam: after_intent, after_replace (each path), before_complete."""


def adopt(root,plan,*,pool,ticket,pinned,snapshot,result,authorization,runtime_id,
          verification_time,authorization_keys,registry,authorization_store):
    from vfy.service_lifecycle import LifecycleAdoptionPool
    root=_path(root);m.need(type(pool) in (AdoptionPool, LifecycleAdoptionPool))
    # Cheap current-approval checks precede any selected source/evidence reads.
    policy=pool.policy;selected=policy['action_key'];sig=authorization['signature']
    m.need(verification_time is not None and runtime_id==policy['runtime_id'])
    m.need(sig['key_id']==selected['key_id'] and sig['key_version']==selected['key_version'])
    key=authorization_keys.get((sig['key_id'],sig['key_version']))
    m.need(key is not None and key['public_key'].hex()==selected['public_key_hex'])
    nonces=authorization_store
    m.need(type(nonces) is store.LocalStore and nonces._writable and
           str(_path(nonces.root))==policy['authorization_store_root'])
    _disjoint(nonces.root,root);_disjoint(nonces.root,_path(plan['original_root']))
    consumed={authorization['nonce']} if nonces.is_consumed(authorization['nonce']) else set()
    verified=auth.verify_authorization(authorization,pinned,action_for(plan),snapshot,result,
        runtime_id,verification_time,authorization_keys,registry,consumed_nonces=consumed)
    with _locked(root):
        m.need(not os.path.lexists(root/'INTENT.json') and not os.path.lexists(root/'COMPLETE.json'),'Existing intent; no retry.')
        # Keep authorization inputs exact and bounded inside the single durable intent.
        intent=dict(schema='vfy.service-adoption-intent/1',plan_sha256=m.digest(plan),
            authorization=authorization,rulebook=pinned.value(),snapshot=snapshot.value(),
            result=result.value(),runtime_id=runtime_id,verification_time=verification_time,
            ticket_sha256=m.digest(ticket),pool_root=str(pool.root),policy_sha256=m.sha(pool.policy_bytes),
            source_sha256=m.digest(plan['base_manifest']),destination=plan['destination'],**FLAGS)
        intent_raw=m.raw(intent);m.need(len(intent_raw)<=32768,'Authorization intent exceeds journal bound.')
        # Consume once BEFORE source validation reads. Failed/changed-base validation
        # holds every reservation and cannot acquire another read budget on retry.
        pool._consume(ticket,plan,intent)
        meter=_Meter(plan['limits']);base,candidate=_plan(root,plan,meter)
        m.need(_scan(root/'copy',plan['limits'],meter)==base,'Changed complete BASE; refused.')
        payloads={}
        for i,p in enumerate(plan['changed_paths']):
            data=meter.read(root/'candidate'/str(i));entry=candidate[p]
            m.need(len(data)==entry['bytes'] and m.sha(data)==entry['sha256']);payloads[p]=data
        # Count frozen journal bytes; candidate inputs are charged separately as staging payload.
        journal=sum(p.stat().st_size for p in (root/'evidence').iterdir())
        journal+=sum((root/n).stat().st_size for n in ('PLAN.json','BASE.json','CANDIDATE.json','FIXTURE.json'))
        meter.charge('journal_bytes',journal+len(intent_raw)+32768)
        nonces.consume_once(verified)
        fd=os.open(nonces._consumption_path(verified.nonce),os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        m.sync_dir(nonces.root/'consumed')
        m.fresh(root/'INTENT.json',intent_raw)
        _fault('after_intent')
        for i,p in enumerate(plan['changed_paths']):
            staged=root/'stage'/str(i);data=payloads[p]
            meter.charge('write_bytes',len(data));m.fresh(staged,data)
            os.chmod(staged,0o600|candidate[p]['executable'])
            with staged.open('rb') as f:os.fsync(f.fileno())
            meter.charge('file_mutations',1)
            os.replace(staged,root/'copy'/p);m.sync_dir((root/'copy'/p).parent);m.sync_dir(root/'stage')
            _fault('after_replace')
        m.need(_scan(root/'copy',plan['limits'],meter)==candidate,'Candidate verification incomplete.')
        _fault('before_complete')
        body=dict(schema='vfy.service-adoption-completion/1',state='OBSERVED_CANDIDATE',
            plan_sha256=m.digest(plan),intent_sha256=m.sha(intent_raw),candidate_sha256=m.digest(candidate),
            destination=plan['destination'],resources_reserved={k:plan['limits'][k] for k in RESOURCES},
            measured=meter.used,service_execution=False,semantic_acceptance='UNESTABLISHED',**FLAGS)
        receipt=m.envelope(body,pool.owner.key,pool.owner.issuer);m.need(len(m.raw(receipt))<=32768)
        # Publish shared settlement before local completion. A crash in this gap remains UNKNOWN locally.
        pool._complete(ticket,plan,receipt)
        m.fresh(root/'COMPLETE.json',m.raw(receipt))
        return receipt


def reconcile(root,plan,*,owner_trust=None):
    result=dict(state='UNKNOWN',content_state='UNKNOWN',intent_present=None,service_execution=False,
                semantic_acceptance='UNESTABLISHED',**FLAGS)
    try:
        root=_path(root)
        with _locked(root,shared=True):
            base,candidate=_plan(root,plan)
            actual=_scan(root/'copy',plan['limits'])
            state='BASE' if actual==base else 'CANDIDATE' if actual==candidate else 'UNKNOWN'
            if state=='UNKNOWN' and set(actual)==set(base) and all(actual[p] in (base[p],candidate[p]) for p in base):state='MIXED'
            result['content_state']=state;result['intent_present']=os.path.lexists(root/'INTENT.json')
            intent_raw=m.read_file(root/'INTENT.json');intent=m.load.load_json_bytes(intent_raw)
            m.need(intent['plan_sha256']==m.digest(plan) and intent['destination']==plan['destination'] and
                   intent['source_sha256']==m.digest(base) and all(intent[k] is False for k in FLAGS))
            receipt=m.load.load_json_bytes(m.read_file(root/'COMPLETE.json'))
            body=m.authenticate(receipt,owner_trust or {})
            m.need(body['schema']=='vfy.service-adoption-completion/1' and body['state']=='OBSERVED_CANDIDATE' and
                   body['plan_sha256']==m.digest(plan) and body['intent_sha256']==m.sha(intent_raw) and
                   body['candidate_sha256']==m.digest(candidate) and body['destination']==plan['destination'] and
                   body['service_execution'] is False and all(body[k] is False for k in FLAGS) and state=='CANDIDATE')
            result['state']='OBSERVED_CANDIDATE';result['receipt_sha256']=m.digest(receipt)
    except Exception:
        pass  # A read-only observation cannot repair ambiguity or recreate authority.
    return result
