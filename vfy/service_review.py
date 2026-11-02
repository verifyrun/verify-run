"""Explicit paid retained review, separate from unchanged historical reconciliation.

Charges bounded selected payload access and retention, not total lifecycle costs.
"""
import os
import stat
import threading
import types
from pathlib import Path
from vfy import child_ledger as m, common_capacity as common, service_attempt, service_adoption

PROFILE='vfy.service-review/1'
ADOPTION_SHA256='0c98ad29c930d7a772ebe2203ab0c7a1c12f958ddaa4abb5f14e70d04826be66'
RESOURCES=('read_bytes','read_calls','retained_bytes')
FLAGS=dict(authority_granted=False,automatic_retry=False)
EXCLUSIONS=['selection/preparation','imports and dependency loading','module self-identity reads',
            'filesystem metadata and locks','accounting store I/O','CPU/wall enforcement',
            'physical I/O and disk overhead','receipt verification and historical reading']


def identity():return dict(profile=PROFILE,source_sha256=m.sha(Path(__file__).read_bytes()))

def _path(s):
    m.need(type(s) is str and len(s)<=4096 and '\x00' not in s)
    p=Path(s);m.need(p.is_absolute() and str(p)==s and p==p.resolve());return p

def _resources(v):
    m.need(type(v) is dict and set(v)==set(RESOURCES) and all(common.integer(n) for n in v.values()))

def _disjoint(a,b):m.need(a!=b and a not in b.parents and b not in a.parents,'Review accounting must be disjoint from retained operation.')

def _unknown():
    return dict(state='UNKNOWN',content_state='UNKNOWN',intent_present=None,service_execution=False,
                semantic_acceptance='UNESTABLISHED',**FLAGS)


class PaidReviewPool:
    """Monotone selected successor at the SAME accounting root; no create/reset API."""
    def __init__(self,predecessor,*,expected_snapshot_bytes,policy_bytes):
        m.need(type(predecessor) in (common.CapacityOwner,service_attempt.ServicePool,service_adoption.AdoptionPool))
        self.predecessor=predecessor;self.root=predecessor.root
        self.owner=predecessor if type(predecessor) is common.CapacityOwner else predecessor.owner
        self.head=expected_snapshot_bytes
        if type(predecessor) is common.CapacityOwner:
            self.prior=predecessor._validate_record(m.load.load_json_bytes(self.head))
            self.base_used=predecessor.usage(self.prior['body']);self.caps=predecessor.config['capacities']
        else:
            view=predecessor.verify_snapshot(self.head);self.base_used=view['used'];self.caps=view['capacities']
            self.prior=m.load.load_json_bytes(self.head)
        self.policy_bytes=policy_bytes;m.need(type(policy_bytes) is bytes and len(policy_bytes)<=65536)
        self.policy=p=m.load.load_json_bytes(policy_bytes)
        m.need(set(p)=={'schema','pool_root','predecessor_sha256','review_identity','adoption_sha256',
                       'resource_capacities','accounting_scope',*FLAGS})
        m.need(p['schema']=='vfy.service-review-policy/1' and p['pool_root']==str(self.root) and
               p['predecessor_sha256']==m.sha(self.head) and p['review_identity']==identity() and
               p['adoption_sha256']==ADOPTION_SHA256 and p['accounting_scope']=='EXPLICIT_DEVELOPMENT_REVIEW_ONLY' and
               all(p[k] is False for k in FLAGS))
        _resources(p['resource_capacities']);self._live=set();self._cap_lock=threading.Lock()

    @classmethod
    def attach(cls,predecessor,*,expected_snapshot_bytes,policy_bytes):
        o=cls(predecessor,expected_snapshot_bytes=expected_snapshot_bytes,policy_bytes=policy_bytes)
        with o.owner.locked():
            m.need(m.read_file(o.root/'state.json')==o.head,'Selected head changed; no reset or reattach.')
            m.need(not os.path.lexists(o.root/'reviews'))
            (o.root/'reviews').mkdir(mode=0o700);m.sync_dir(o.root)
            o._publish(dict(schema=PROFILE,pool_root=str(o.root),policy_sha256=m.sha(policy_bytes),
                review_identity=identity(),predecessor_raw_hex=o.head.hex(),entries=[],
                revision=o.prior['body']['revision']+1,previous=o.prior['sha256'],**FLAGS))
        return o

    def _request(self,raw):
        m.need(type(raw) is bytes and len(raw)<=65536)
        q=m.load.load_json_bytes(raw)
        m.need(set(q)=={'schema','review_id','pool_root','policy_sha256','operation_root',
            'plan_path','plan_sha256','trust_path','trust_sha256','adoption_module_path','adoption_sha256',
            'expected_source_sha256','resources',*FLAGS})
        m.need(q['schema']=='vfy.service-review-request/1' and m.text(q['review_id']) and len(q['review_id'])<=256 and
               q['pool_root']==str(self.root) and q['policy_sha256']==m.sha(self.policy_bytes) and
               q['adoption_sha256']==ADOPTION_SHA256 and all(q[k] is False for k in FLAGS))
        for k in ('plan_sha256','trust_sha256','adoption_sha256','expected_source_sha256'):m.need(m.hex64(q[k]))
        # Syntax only here: admission does not read or resolve selected filesystem paths.
        for k in ('operation_root','plan_path','trust_path','adoption_module_path'):
            v=q[k];m.need(type(v) is str and len(v)<=4096 and '\x00' not in v and Path(v).is_absolute() and
                        str(Path(v))==v and '..' not in Path(v).parts)
        _disjoint(self.root,Path(q['operation_root']))
        _resources(q['resources']);m.need(all(v>0 for v in q['resources'].values()))
        m.need(65536<=q['resources']['retained_bytes']<=m.MAX_BYTES and q['resources']['read_calls']<=100000)
        return q

    def _totals(self,b):
        used=dict(self.base_used);reviews=dict.fromkeys(RESOURCES,0)
        for e in b['entries']:
            q=self._request(bytes.fromhex(e['request_raw_hex']))
            used['dispatch_slots']+=1;used['retained_output_bytes']+=q['resources']['retained_bytes']
            for k in RESOURCES:reviews[k]+=q['resources'][k]
        m.need(all(common.integer(n) and n<=self.caps[k] for k,n in used.items()),'Selected shared capacity exhausted.')
        m.need(all(common.integer(n) and n<=self.policy['resource_capacities'][k] for k,n in reviews.items()),'Selected review capacity exhausted.')
        return used,reviews

    def _validate(self,record):
        b=m.authenticate(record,self.owner.trust);m.need(record['issuer_identity']==self.owner.issuer)
        m.need(set(b)=={'schema','pool_root','policy_sha256','review_identity','predecessor_raw_hex','entries','revision','previous',*FLAGS})
        m.need(b['schema']==PROFILE and b['pool_root']==str(self.root) and b['policy_sha256']==m.sha(self.policy_bytes) and
               b['review_identity']==identity() and b['predecessor_raw_hex']==self.head.hex() and
               all(b[k] is False for k in FLAGS) and m.hex64(b['previous']))
        m.need(type(b['entries']) is list);seen=set();events=1
        for e in b['entries']:
            m.need(set(e)=={'request_raw_hex','request_sha256','recorded_at','consumed_at','receipt_sha256'})
            raw=bytes.fromhex(e['request_raw_hex']);q=self._request(raw)
            m.need(e['request_sha256']==m.sha(raw) and q['review_id'] not in seen and m.text(e['recorded_at']))
            seen.add(q['review_id']);events+=1
            if e['consumed_at'] is not None:m.need(m.text(e['consumed_at']));events+=1
            if e['receipt_sha256'] is not None:m.need(e['consumed_at'] is not None and m.hex64(e['receipt_sha256']));events+=1
        m.need(b['revision']==self.prior['body']['revision']+events);self._totals(b);return record

    def _publish(self,b):
        record=m.envelope(b,self.owner.key,self.owner.issuer);self._validate(record);raw=m.raw(record)
        m.need(len(raw)<=m.MAX_BYTES);m.fresh(self.root/'pending.json',raw)
        os.replace(self.root/'pending.json',self.root/'state.json');m.sync_dir(self.root);return record

    def _change(self,fn):
        with self.owner.locked():
            old=self._validate(m.load.load_json_bytes(m.read_file(self.root/'state.json')))
            b=old['body'];fn(b);b['revision']+=1;b['previous']=old['sha256'];return self._publish(b)

    def snapshot(self):
        with self.owner.locked():
            raw=m.read_file(self.root/'state.json');self.verify_snapshot(raw);return raw

    def verify_snapshot(self,raw):
        b=self._validate(m.load.load_json_bytes(raw))['body'];used,reviews=self._totals(b)
        return dict(state='VERIFIED_SELECTED_REVIEW_ACCOUNTING_NOT_FRESHNESS',revision=b['revision'],used=used,
            capacities=self.caps,review_used=reviews,review_capacities=self.policy['resource_capacities'],
            full_cost='UNKNOWN',**FLAGS)

    def reserve(self,*,request_bytes,recorded_at):
        self._request(request_bytes);m.need(m.text(recorded_at));key=m.sha(request_bytes)
        def change(b):
            b['entries'].append(dict(request_raw_hex=request_bytes.hex(),request_sha256=key,
                                    recorded_at=recorded_at,consumed_at=None,receipt_sha256=None))
        with self._cap_lock:
            ticket=self._change(change);self._live.add(key);return ticket

    def _key(self,ticket):
        b=self._validate(ticket)['body'];m.need(bool(b['entries']))
        e=b['entries'][-1];m.need(e['consumed_at'] is None and e['receipt_sha256'] is None)
        return e['request_sha256']

    @staticmethod
    def _entry(b,key):
        found=[e for e in b['entries'] if e['request_sha256']==key];m.need(len(found)==1);return found[0]

    def _consume(self,ticket,raw,recorded_at):
        key=self._key(ticket);m.need(key==m.sha(raw) and m.text(recorded_at))
        with self._cap_lock:
            m.need(key in self._live,'No live paid-review capability; no retry.')
            self._live.remove(key)
            def change(b):
                e=self._entry(b,key);m.need(e['consumed_at'] is None);e['consumed_at']=recorded_at
            self._change(change)
        return key

    def _finish(self,key,receipt):
        def change(b):
            e=self._entry(b,key);m.need(e['consumed_at'] is not None and e['receipt_sha256'] is None)
            e['receipt_sha256']=m.digest(receipt)
        self._change(change)

    def inspect(self,ticket):
        key=self._key(ticket);b=self._validate(m.load.load_json_bytes(self.snapshot()))['body'];e=self._entry(b,key)
        return dict(state='RECEIPT_LINKED' if e['receipt_sha256'] else 'UNKNOWN_HOLD_RETAINED',
                    entry=e,full_reservation_retained=True,**FLAGS)


class _Reader:
    def __init__(self,limits):
        self.limits=limits;self.used=dict(read_bytes=0,read_calls=0);self.trace=[];self.failed=False
        self.trace_size=2
    def read(self,path):
        try:
            p=_path(str(path));m.need(self.used['read_calls']<self.limits['read_calls'],'Read call limit exhausted.')
            # Reserve trace space BEFORE accessing payload. Retention overhead is conservative.
            allowance=len(m.raw(dict(path=str(p),bytes=m.MAX_BYTES,sha256='f'*64)))+1
            m.need(self.trace_size+allowance<=self.limits['retained_bytes']-32768,'Read trace retention limit exhausted.')
            self.trace_size+=allowance;self.used['read_calls']+=1
            fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                s=os.fstat(fd)
                m.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=m.MAX_BYTES)
                m.need(self.used['read_bytes']+s.st_size<=self.limits['read_bytes'],'Read payload limit exhausted.')
                # Charge requested logical length conservatively even if an I/O fails.
                self.used['read_bytes']+=s.st_size
                with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(s.st_size)
                after=os.fstat(fd)
                m.need(len(raw)==s.st_size and (s.st_size,s.st_mtime_ns,s.st_ino)==(after.st_size,after.st_mtime_ns,after.st_ino))
                self.trace.append(dict(path=str(p),bytes=len(raw),sha256=m.sha(raw)))
                return raw
            finally:os.close(fd)
        except Exception:
            self.failed=True;raise


def _fault(stage):
    """Test-only interruption seam: after_consume, after_read, before_receipt."""


def paid_review(pool,ticket,*,request_bytes,recorded_at):
    m.need(type(pool) is PaidReviewPool)
    q=pool._request(request_bytes);key=pool._consume(ticket,request_bytes,recorded_at)
    _fault('after_consume')
    reader=_Reader(q['resources']);result=_unknown();observed=None;reason=None;state='UNKNOWN_HOLD_RETAINED'
    plan=None
    try:
        root=_path(q['operation_root']);_disjoint(pool.root,root)
        selected={}
        for name,pathkey,hashkey in [('plan','plan_path','plan_sha256'),('trust','trust_path','trust_sha256'),
                                    ('module','adoption_module_path','adoption_sha256')]:
            raw=reader.read(q[pathkey]);m.need(m.sha(raw)==q[hashkey],'Selected '+name+' bytes changed.')
            selected[name]=raw
        plan=m.load.load_json_bytes(selected['plan']);trust=m.load.load_json_bytes(selected['trust'])
        m.need(type(plan) is dict and type(trust) is dict and bool(trust))
        m.need(plan['fixture']['root']['path']==str(root) and plan['producer_identity']['source_sha256']==ADOPTION_SHA256)
        # Load the EXACT selected old code into private globals. No sys.modules replacement,
        # reload or global m.read_file monkeypatch; original historical API is untouched.
        runtime=types.ModuleType('_vfy_paid_adoption_reader')
        runtime.__file__=q['adoption_module_path'];runtime.__package__='vfy'
        exec(compile(selected['module'],runtime.__file__,'exec'),runtime.__dict__)
        proxy=types.SimpleNamespace(**vars(m));proxy.read_file=reader.read;runtime.m=proxy
        # Old os.walk silently omits scandir failures. Only this private reader
        # changes enumeration policy; historical module/globals remain untouched.
        os_proxy=types.SimpleNamespace(**vars(os))
        def fail_walk(error):
            reader.failed=True
            raise error
        def walk(top,**kwargs):
            kwargs['onerror']=fail_walk
            return os.walk(top,**kwargs)
        os_proxy.walk=walk;runtime.os=os_proxy
        original_scan=runtime._scan
        def scan(*args,**kwargs):
            nonlocal observed
            manifest=original_scan(*args,**kwargs);observed=m.digest(manifest);return manifest
        runtime._scan=scan
        result=runtime.reconcile(root,plan,owner_trust=trust)
        _fault('after_read')
        if reader.failed:reason='BOUNDED_READ_FAILED'
        else:state='REVIEW_RECORDED'
    except Exception as exc:reason=type(exc).__name__
    relation='UNKNOWN' if observed is None else 'MATCH' if observed==q['expected_source_sha256'] else 'MISMATCH'
    if state!='REVIEW_RECORDED' or relation!='MATCH':result=_unknown()
    trace_raw=m.raw(reader.trace)
    body=dict(schema='vfy.service-review-receipt/1',state=state,request=q,request_sha256=key,
        ticket_sha256=m.digest(ticket),review_identity=identity(),observed_source_sha256=observed,
        source_relation=relation,run_result=result,charged=reader.used,reserved=q['resources'],
        full_reservation_retained=True,trace_sha256=m.sha(trace_raw),reason=reason,recorded_at=recorded_at,
        task_id=plan.get('task_id') if type(plan) is dict else None,
        requirements_sha256=plan.get('requirements_sha256') if type(plan) is dict else None,
        selection_sha256=plan.get('selection_sha256') if type(plan) is dict else None,
        full_cost='UNKNOWN',exclusions=EXCLUSIONS,service_execution=False,**FLAGS)
    receipt=m.envelope(body,pool.owner.key,pool.owner.issuer);raw=m.raw(receipt)
    m.need(len(raw)<=32768 and len(raw)+len(trace_raw)<=q['resources']['retained_bytes'])
    _fault('before_receipt')
    dest=pool.root/'reviews'/key;dest.mkdir(mode=0o700);m.sync_dir(dest.parent)
    m.fresh(dest/'TRACE.json',trace_raw);m.fresh(dest/'RECEIPT.json',raw)
    pool._finish(key,receipt)
    return receipt
