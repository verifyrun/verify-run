"""One independently selected protected local pool. No global/host capacity claim.

Distinct owner issuer; cumulative dispatch slots and retained child output payload bytes.
Trusted local owner controls one store and signing key; no hostile-owner rollback defense.
"""
import contextlib
import fcntl
import json
import os
import stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from vfy import child_ledger as m

OUTPUT_HOLD=262144
PROFILE='vfy.common-capacity/1'

def integer(n):return type(n) is int and 0<=n<=m.canon.MAX_SAFE_INTEGER

def owner_identity():return {'profile':PROFILE,'source_sha256':m.sha(Path(__file__).read_bytes())}

class CapacityOwner:
    def __init__(self,root,owner_seed,owner_issuer,owner_trust,*,expected_config_bytes,child_trust,selected_observer):
        self.root=Path(root);m.need(self.root.is_absolute() and self.root==self.root.resolve() and self.root.is_dir())
        self.key=Ed25519PrivateKey.from_private_bytes(owner_seed);self.issuer=owner_issuer;self.trust=owner_trust
        self.config_bytes=expected_config_bytes;self.config=m.load.load_json_bytes(expected_config_bytes)
        self.child_trust=child_trust;self.observer=selected_observer
        pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        m.need(owner_trust.get(owner_issuer)=={'public_key_hex':pub,'producer_identity':m.producer()})
        m.need(child_trust and all(v['public_key_hex']!=pub for v in child_trust.values()),'Capacity owner must use independently selected issuer key.')
        c=self.config;m.need(set(c)=={'schema','pool_id','owner_issuer','capacities','scope'})
        m.need(c['schema']==PROFILE and c['owner_issuer']==owner_issuer and m.text(c['pool_id']) and c['scope']=='REVIEWED_LOCAL_VERIFIER_ONLY')
        m.need(set(c['capacities'])=={'dispatch_slots','retained_output_bytes'} and all(integer(v) for v in c['capacities'].values()))
    @classmethod
    def create(cls,root,config_bytes,owner_seed,owner_issuer,owner_trust,*,child_trust,selected_observer):
        p=Path(root);m.need(p.is_absolute() and p==p.resolve() and not p.exists());p.mkdir(mode=0o700);m.sync_dir(p.parent)
        o=cls(p,owner_seed,owner_issuer,owner_trust,expected_config_bytes=config_bytes,child_trust=child_trust,selected_observer=selected_observer)
        body={'schema':'vfy.common-capacity-state/1','pool_root':str(p),'config_sha256':m.sha(config_bytes),'owner_profile':owner_identity(),
              'observer':selected_observer,'revision':0,'previous':None,'entries':[],
              'authority_granted':False,'automatic_retry':False}
        m.fresh(p/'lock',b'');m.fresh(p/'state.json',m.raw(m.envelope(body,o.key,o.issuer)))
        return o
    @contextlib.contextmanager
    def locked(self):
        fd=os.open(self.root/'lock',os.O_RDWR|os.O_NOFOLLOW)
        try:
            st=os.fstat(fd);m.need(stat.S_ISREG(st.st_mode) and st.st_nlink==1)
            fcntl.flock(fd,fcntl.LOCK_EX)
            m.need(not os.path.lexists(self.root/'pending.json'),'Interrupted pool publication; UNKNOWN, no new dispatch.')
            yield
        finally:os.close(fd)
    def _load(self):
        return self._validate_record(m.load.load_json_bytes(m.read_file(self.root/'state.json')))
    def _validate_record(self,record):
        m.need(record['issuer_identity']==self.config['owner_issuer'])
        b=m.authenticate(record,self.trust)
        m.need(b['schema']=='vfy.common-capacity-state/1' and b['pool_root']==str(self.root) and b['config_sha256']==m.sha(self.config_bytes))
        m.need(b['owner_profile']==owner_identity() and b['observer']==self.observer and b['automatic_retry'] is False)
        keys=set();logical=set();event_count=0
        m.need(type(b['revision']) is int and b['revision']>=0)
        for e in b['entries']:
            m.need(e['key'] not in keys);keys.add(e['key'])
            logical_key=tuple(e['binding'][k] for k in ('task_key','parent_operation_id','parent_attempt_id','child_id'))
            m.need(logical_key not in logical);logical.add(logical_key)
            event_count+=1+(e['dispatch'] is not None)+(e['settlement'] is not None)
            m.need(e['key']==m.digest(e['binding']))
            child_trust=e['binding']['child_trust']
            owner_public=self.trust[self.config['owner_issuer']]['public_key_hex']
            m.need(child_trust and all(v['public_key_hex']!=owner_public for v in child_trust.values()))
            if e['dispatch'] is not None:
                cr=m.authenticate(e['dispatch']['reservation'],child_trust)
                cb=m.authenticate(e['dispatch']['binding'],child_trust)
                m.need(cr['parent_start_sha256']==e['binding']['parent_start_sha256'] and cr['child_id']==e['binding']['child_id'])
                m.need(cb['request_identity']==e['binding']['request_identity'] and cb['request_sha256']==e['binding']['request_sha256'])
                m.need(cb['reservation_sha256']==e['dispatch']['reservation']['sha256'] and cb['common_reservation_sha256']==e['ticket']['sha256'])
            m.need(e['ticket']['issuer_identity']==self.config['owner_issuer'])
            t=m.authenticate(e['ticket'],self.trust)
            m.need(t==dict(e['binding'],schema='vfy.common-reservation/1',reservation_id=e['key'],retained_output_bytes=OUTPUT_HOLD,dispatch_slots=1,authority_granted=False,automatic_retry=False))
            m.need(integer(e['retained_bytes']) and 0<=e['retained_bytes']<=OUTPUT_HOLD)
            if e['settlement'] is None:m.need(e['retained_bytes']==OUTPUT_HOLD)
            else:
                m.need(e['settlement']['issuer_identity']==self.config['owner_issuer'])
                f=m.authenticate(e['settlement'],self.trust)
                m.need(f['reservation_id']==e['key'] and f['reservation_sha256']==e['ticket']['sha256'] and f['retained_bytes']==e['retained_bytes'] and f['dispatch_slots_consumed']==1)
                m.need(e['dispatch'] is not None and f['state'] in ('KNOWN_LOCAL_RETAINED_OUTPUT','UNKNOWN_HOLD_RETAINED'))
                if f['state']=='UNKNOWN_HOLD_RETAINED':m.need(e['retained_bytes']==OUTPUT_HOLD)
        m.need(b['revision']==event_count)
        used=self.usage(b);m.need(all(used[k]<=v for k,v in self.config['capacities'].items()))
        return record
    @staticmethod
    def usage(b):return {'dispatch_slots':len(b['entries']),'retained_output_bytes':sum(e['retained_bytes'] for e in b['entries'])}
    def snapshot(self):
        with self.locked():return m.raw(self._load())
    def _change(self,fn):
        with self.locked():
            old=self._load();b=old['body'];result=fn(b)
            b['revision']+=1;b['previous']=old['sha256'];data=m.raw(m.envelope(b,self.key,self.issuer));m.need(len(data)<=m.MAX_BYTES)
            m.fresh(self.root/'pending.json',data);os.replace(self.root/'pending.json',self.root/'state.json');m.sync_dir(self.root)
            return result
    def reserve(self,ledger,request_bytes):
        q=m.load.load_json_bytes(request_bytes);sb,basis,bb=ledger.expected;p=m.parent_binding(sb,basis)
        m.need(q['schema']=='engineer.child-dispatch-request/1' and q['authority_granted'] is False and q['automatic_retry'] is False)
        m.need(q['task_key']==p['task_key'] and q['task_identity']==p['task_identity'] and q['operation_id']==p['parent_binding']['operation_id'] and q['attempt_id']==p['parent_binding']['attempt_id'])
        m.need(q['parent_start']['sha256']==m.sha(sb) and q['child_id'] in p['expected_child_ids'])
        unsigned={k:v for k,v in q.items() if k!='identity_sha256'}
        m.need(q['identity_sha256']==m.sha(json.dumps(unsigned,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()))
        m.need(ledger.trust==self.child_trust,'Unselected child issuer.')
        binding={'pool_id':self.config['pool_id'],'config_sha256':m.sha(self.config_bytes),'pool_root':str(self.root),
                 'task_key':p['task_key'],'task_identity':p['task_identity'],'parent_start_sha256':m.sha(sb),
                 'parent_operation_id':p['parent_binding']['operation_id'],'parent_attempt_id':p['parent_binding']['attempt_id'],
                 'child_id':q['child_id'],'request_identity':q['identity_sha256'],'request_sha256':m.sha(request_bytes),
                 'child_trust':self.child_trust,'input_sha256':q['input_sha256'],'ledger_root':str(ledger.root),'budget_sha256':m.sha(bb),'observer':self.observer}
        key=m.digest(binding)
        def change(b):
            marker_body={'schema':'vfy.common-owner-binding/1','pool_root':str(self.root),
                         'config_sha256':m.sha(self.config_bytes),'owner_issuer':self.issuer,
                         'ledger_root':str(ledger.root),'authority_granted':False,'automatic_retry':False}
            marker=m.raw(m.envelope(marker_body,self.key,self.issuer));path=ledger.root/'common-owner.json'
            if path.exists():m.need(m.read_file(path)==marker,'Partition bound to a different pool.')
            else:m.fresh(path,marker)
            # Changing request bytes or partition store cannot buy a second attempt at same child.
            m.need(not any((e['binding']['parent_start_sha256']==binding['parent_start_sha256'] and e['binding']['child_id']==binding['child_id']) or
                all(e['binding'][k]==binding[k] for k in ('task_key','parent_operation_id','parent_attempt_id','child_id'))
                for e in b['entries']),'Child already held/consumed in this pool; no resend.')
            used=self.usage(b);m.need(used['dispatch_slots']+1<=self.config['capacities']['dispatch_slots'] and used['retained_output_bytes']+OUTPUT_HOLD<=self.config['capacities']['retained_output_bytes'],'Common capacity exhausted; no dispatch.')
            ticket=m.envelope(dict(binding,schema='vfy.common-reservation/1',reservation_id=key,retained_output_bytes=OUTPUT_HOLD,dispatch_slots=1,authority_granted=False,automatic_retry=False),self.key,self.issuer)
            b['entries'].append({'key':key,'binding':binding,'ticket':ticket,'dispatch':None,'settlement':None,'retained_bytes':OUTPUT_HOLD})
            return ticket
        return self._change(change)
    def _entry(self,b,ticket):
        t=m.authenticate(ticket,self.trust);found=[e for e in b['entries'] if e['key']==t['reservation_id']]
        m.need(len(found)==1 and found[0]['ticket']==ticket);return found[0]
    def bind_dispatch(self,ticket,reservation,binding_record):
        def change(b):
            e=self._entry(b,ticket);m.need(e['dispatch'] is None and self.child_trust==e['binding']['child_trust'])
            r=m.authenticate(reservation,self.child_trust);d=m.authenticate(binding_record,self.child_trust);p=e['binding']
            m.need(r['parent_start_sha256']==p['parent_start_sha256'] and r['child_id']==p['child_id'] and r['budget_sha256']==p['budget_sha256'])
            m.need(d['reservation_sha256']==reservation['sha256'] and d['request_sha256']==p['request_sha256'] and d['request_identity']==p['request_identity'] and d['observer']==self.observer)
            m.need(d['common_reservation_sha256']==ticket['sha256'])
            e['dispatch']={'reservation':reservation,'binding':binding_record}
            return e['dispatch']
        return self._change(change)
    def settle(self,ticket,result):
        def change(b):
            e=self._entry(b,ticket);m.need(e['settlement'] is None and e['dispatch'] is not None and self.child_trust==e['binding']['child_trust'])
            d=e['dispatch'];m.need(result['reservation']==d['reservation'])
            a=m.authenticate(result['acquisition'],self.child_trust);c=m.authenticate(result['completion'],self.child_trust);s=m.authenticate(result['settlement'],self.child_trust)
            m.need(a['binding_sha256']==m.sha(m.raw(d['binding'])) and a['observer']==self.observer)
            m.need(a['completion_sha256']==result['completion']['sha256'] and a['settlement_sha256']==result['settlement']['sha256'])
            m.need(c['reservation_sha256']==d['reservation']['sha256'] and s['reservation_sha256']==d['reservation']['sha256'] and s['completion_sha256']==result['completion']['sha256'])
            n=len(result['stdout'])+len(result['stderr']);m.need(n<=OUTPUT_HOLD and a['captured_bytes']==n)
            m.need(m.sha(result['stdout'])==a['stdout_sha256'] and m.sha(result['stderr'])==a['stderr_sha256'])
            measured=m.axes(c['resource_rows'],'measured_amount');m.need(measured['captured_console_bytes']==n)
            known=(a['service_performed']==c['service_performed']==s['service_performed']=='PERFORMED' and not a['timed_out'] and not a['output_truncated'] and a['exit_status']==0)
            if known:m.need(m.axes(s['resource_rows'],'settled_amount_or_UNKNOWN')['captured_console_bytes']==n)
            e['retained_bytes']=n if known else OUTPUT_HOLD
            body={'schema':'vfy.common-settlement/1','reservation_id':e['key'],'reservation_sha256':ticket['sha256'],
                  'acquisition_sha256':result['acquisition']['sha256'],'child_settlement_sha256':result['settlement']['sha256'],
                  'retained_bytes':e['retained_bytes'],'dispatch_slots_consumed':1,
                  'state':'KNOWN_LOCAL_RETAINED_OUTPUT' if known else 'UNKNOWN_HOLD_RETAINED','authority_granted':False,'automatic_retry':False}
            e['settlement']=m.envelope(body,self.key,self.issuer);return e['settlement']
        return self._change(change)


def dispatch_common(ledger,owner,request_bytes,input_bytes,*,selected_observer,recorded_at,interrupt=False,timeout_seconds=30):
    from vfy import child_observer
    m.need(type(owner) is CapacityOwner and selected_observer==owner.observer)
    return child_observer.dispatch_development(ledger,request_bytes,input_bytes,selected_observer=selected_observer,
        recorded_at=recorded_at,interrupt=interrupt,timeout_seconds=timeout_seconds,common_owner=owner)


def verify_capacity_snapshot(snapshot_bytes,owner_trust,expected_config_bytes,*,expected_pool_root,expected_child_trusts,selected_observer,minimum_revision=0):
    """Selected-byte public correspondence only, NOT freshness or hostile rollback proof."""
    m.need(type(snapshot_bytes) is bytes and len(snapshot_bytes)<=m.MAX_BYTES)
    c=m.load.load_json_bytes(expected_config_bytes)
    m.need(set(c)=={'schema','pool_id','owner_issuer','capacities','scope'} and c['schema']==PROFILE and c['scope']=='REVIEWED_LOCAL_VERIFIER_ONLY')
    m.need(set(c['capacities'])=={'dispatch_slots','retained_output_bytes'} and all(integer(v) for v in c['capacities'].values()))
    m.need(m.text(c['pool_id']) and c['owner_issuer'] in owner_trust)
    m.need(type(expected_child_trusts) is dict)
    view=object.__new__(CapacityOwner);view.root=Path(expected_pool_root)
    m.need(view.root.is_absolute() and str(view.root)==expected_pool_root)
    view.config_bytes=expected_config_bytes;view.config=c;view.trust=owner_trust;view.observer=selected_observer
    record=view._validate_record(m.load.load_json_bytes(snapshot_bytes));b=record['body']
    selected={e['binding']['request_identity']:e['binding']['child_trust'] for e in b['entries']}
    m.need(selected==expected_child_trusts,'Exact per-request child trust selections required.')
    m.need(integer(minimum_revision) and b['revision']>=minimum_revision)
    return {'state':'VERIFIED_SELECTED_COMMON_CAPACITY_NOT_FRESHNESS','revision':b['revision'],
            'pool_id':c['pool_id'],'config_sha256':m.sha(expected_config_bytes),'used':view.usage(b),
            'capacities':c['capacities'],'scope':'CUMULATIVE_DISPATCH_SLOTS_AND_RETAINED_CAPTURED_PAYLOAD_ONLY',
            'full_lifecycle_accounting':'UNKNOWN','authority_granted':False,'automatic_retry':False}
