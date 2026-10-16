"""Versioned single-attempt preparation/adoption lifecycle on the selected allocator.

Exact current head required; no intervening allocations, resumed construction or
legacy reinterpretation. Physical CPU/cache cost remains UNKNOWN.
"""
import base64
import contextlib
import fcntl
import os
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vfy import child_ledger as m, service_tests, service_adoption as a
from vfy import authorization, gate, rulebook, snapshot, schema, resources, store
from vfy.service_accounting_cli import bounded_file, MAX_STDIN
from vfy.service_read_cli import _inputs, MAX_INPUTS

FORMAT='vfy.service-preparation-lifecycle/1'
PREP_AXES={'payload_bytes','copy_bytes','staged_bytes','checked_bytes','files','artifact_bytes'}


def now():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def identity():return {'schema':FORMAT,'source_sha256':m.sha(Path(__file__).read_bytes()),'adoption':a.identity()}
def positive(v):return type(v) is int and 0<v<=m.canon.MAX_SAFE_INTEGER

def fault(stage):pass


class Ledger:
    def __init__(self, profile_path, digest, expected_head):
        self.path=profile_path;self.raw=bounded_file(profile_path,MAX_STDIN)
        m.need(m.sha(self.raw)==digest and m.hex64(expected_head))
        self.profile=p=m.load.load_json_bytes(self.raw)
        m.need(set(p)=={'schema','scope','service_profile','service_profile_sha256','task_id','attempt_id',
            'payload_sha256','preparation_limits','adoption_limits','recovery_bytes','checker','action_key','runtime_id','authorization_store_root'})
        m.need(p['schema']==FORMAT and p['scope']=='DISPOSABLE_DEVELOPMENT_ONLY')
        m.need(m.text(p['task_id']) and m.text(p['attempt_id']) and m.hex64(p['payload_sha256']))
        m.need(set(p['preparation_limits'])==PREP_AXES and all(positive(v) for v in p['preparation_limits'].values()))
        m.need(positive(p['recovery_bytes']) and p['preparation_limits']['payload_bytes']<=MAX_STDIN)
        a._limits(p['adoption_limits'])
        sr=bounded_file(p['service_profile'],MAX_STDIN);m.need(m.sha(sr)==p['service_profile_sha256'])
        self.service_profile=s=m.load.load_json_bytes(sr)
        m.need(s['schema']=='vfy.service-accounting-profile/1' and s['scope']=='DISPOSABLE_DEVELOPMENT_ONLY')
        data=_inputs(s['inputs'],('snapshot','config','predecessor','policy','managed_legacy'),MAX_INPUTS)
        self.legacy=data['snapshot']
        self.service=service_tests.load_service_pool(**s['selection'],snapshot_bytes=data['snapshot'],
            expected_config_bytes=data['config'],predecessor_snapshot_bytes=data['predecessor'],
            policy_bytes=data['policy'],managed_legacy_snapshot_bytes=data['managed_legacy'] or None)
        self.owner=self.service.owner;self.root=self.owner.root
        key=Ed25519PrivateKey.from_private_bytes(bounded_file(s['key_file'],32,secret=True))
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        m.need(self.owner.trust[self.owner.issuer]=={'public_key_hex':pub,'producer_identity':m.producer()})
        self.owner.key=key;self.expected=expected_head;self.profile_sha=digest
        action=p['action_key']
        m.need(set(action)=={'key_id','key_version','public_key_hex','status'} and m.hex64(action['public_key_hex']))
        excluded={v['public_key_hex'] for v in self.owner.trust.values()}
        excluded.update(v['public_key_hex'] for v in self.owner.child_trust.values())
        m.need(action['public_key_hex'] not in excluded,'Independent action key required.')

    @contextlib.contextmanager
    def locked(self):
        fd=os.open(self.root/'lock',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            m.need(not os.path.lexists(self.root/'pending.json'),'Interrupted publication; retained UNKNOWN.')
            self.current=bounded_file(self.root/'state.json',m.MAX_BYTES)
            m.need(m.sha(self.current)==self.expected,'Current head changed; no replay or reconstruction.')
            self.check_profile()
            yield self
        finally:os.close(fd)

    def check_profile(self):
        m.need(bounded_file(self.path,MAX_STDIN)==self.raw,'Selected current trust changed.')

    def load(self):
        r=m.load.load_json_bytes(self.current);b=m.authenticate(r,self.owner.trust)
        m.need(r['issuer_identity']==self.owner.issuer and b['schema']==FORMAT and b['identity']==identity()
            and b['profile_sha256']==self.profile_sha and b['legacy_sha256']==m.sha(self.legacy)
            and b['pool_root']==str(self.root) and b['task_id']==self.profile['task_id']
            and b['attempt_id']==self.profile['attempt_id'] and b['payload_sha256']==self.profile['payload_sha256'])
        m.need(b['phase'] in {'PREPARING','UNKNOWN','PREPARED','ADOPTING','COMPLETE'})
        m.need(type(b['revision']) is int and b['revision']>0 and m.hex64(b['previous']))
        self.body=b;return b

    def publish(self,b):
        self.check_profile()
        b=dict(b,revision=b.get('revision',0)+1,previous=m.sha(self.current))
        raw=m.raw(m.envelope(b,self.owner.key,self.owner.issuer));m.need(len(raw)<=m.MAX_BYTES)
        m.fresh(self.root/'pending.json',raw);os.replace(self.root/'pending.json',self.root/'state.json');m.sync_dir(self.root)
        self.current=raw;self.body=b;return m.sha(raw)

    def start(self):
        m.need(self.current==self.legacy,'Preparation requires exact original service head; no replay.')
        prior=self.service.verify_snapshot(self.legacy)
        p=self.profile;limits=p['preparation_limits']
        hold=limits['artifact_bytes']+p['adoption_limits']['journal_bytes']+p['recovery_bytes']
        m.need(prior['used']['dispatch_slots']+2<=prior['capacities']['dispatch_slots']
            and prior['used']['retained_output_bytes']+hold<=prior['capacities']['retained_output_bytes'],'Insufficient combined preparation/adoption/recovery capacity.')
        return self.publish(dict(schema=FORMAT,identity=identity(),profile_sha256=self.profile_sha,
            legacy_sha256=m.sha(self.legacy),pool_root=str(self.root),task_id=p['task_id'],attempt_id=p['attempt_id'],
            payload_sha256=p['payload_sha256'],phase='PREPARING',reserved=dict(dispatch_slots=2,retained_output_bytes=hold,
            preparation=limits,adoption=p['adoption_limits'],recovery_bytes=p['recovery_bytes']),
            measured={},managed_root=None,plan=None,preparation_receipt=None,completion=None,recovery_used=False,
            full_physical_cost='UNKNOWN',authority_granted=False,automatic_retry=False,acquisition='bounded profile, trust and state reads outside these logical payload measures'))


def decode_files(value):
    m.need(type(value) is dict)
    return {k:base64.b64decode(v,validate=True) for k,v in value.items()}


def prepare(ledger,payload_path):
    with ledger.locked():
        ledger.start();fault('after_reservation')
        try:
            p=ledger.profile;limits=p['preparation_limits']
            raw=bounded_file(payload_path,limits['payload_bytes'])
            m.need(m.sha(raw)==p['payload_sha256'],'Prepared input identity differs.')
            q=m.load.load_json_bytes(raw)
            m.need(set(q)=={'base_manifest','base_files','candidate_manifest','candidate_files','original_root','check_inputs'})
            base=decode_files(q['base_files']);candidate=decode_files(q['candidate_files'])
            inputs={k:(v if k=='request_sha256' else base64.b64decode(v,validate=True)) for k,v in q['check_inputs'].items()}
            selected={k:base64.b64decode(v,validate=True) for k,v in p['checker']['inputs'].items()}
            counts=dict(payload_bytes=len(raw),copy_bytes=sum(map(len,base.values())),
                staged_bytes=sum(map(len,candidate.values())),checked_bytes=sum(len(v) for k,v in inputs.items() if k!='request_sha256')+sum(map(len,selected.values())),
                files=len(base)+len(candidate),artifact_bytes=4*len(raw)+2*sum(map(len,base.values()))+sum(map(len,candidate.values()))+262144)
            m.need(all(counts[k]<=limits[k] for k in PREP_AXES),'Preparation resource bound exceeded.')
            ledger.body['measured']=counts;ledger.publish(ledger.body)
            checker=service_tests.TestObservationChecker(ledger.service,**selected,limits=p['checker']['limits'])
            root=a.provision_managed_copy(base_manifest_bytes=m.raw(q['base_manifest']),base_files=base,
                original_root=q['original_root'],limits=p['adoption_limits'])
            ledger.body['managed_root']=str(root);ledger.publish(ledger.body);fault('after_copy')
            plan=a.prepare_adoption(root,candidate_manifest_bytes=m.raw(q['candidate_manifest']),candidate_files=candidate,
                task_id=p['task_id'],checker=checker,check_inputs=inputs,limits=p['adoption_limits'])
            receipt=m.envelope(dict(schema=FORMAT+'/prepared',profile_sha256=ledger.profile_sha,
                task_id=p['task_id'],attempt_id=p['attempt_id'],payload_sha256=p['payload_sha256'],
                base_plan_sha256=m.digest(plan),measured=counts,reserved=ledger.body['reserved'],
                predecessor_sha256=m.sha(ledger.current),identity=identity(),full_physical_cost='UNKNOWN',authority_granted=False,automatic_retry=False),ledger.owner.key,ledger.owner.issuer)
            plan=dict(plan,preparation_receipt_sha256=m.digest(receipt))
            # Complete private construction, never execution/adoption. An interruption
            # here leaves a held attempt; no reconstruction path is provided.
            (root/'PLAN.json').write_bytes(m.raw(plan))
            with (root/'PLAN.json').open('rb') as stream:os.fsync(stream.fileno())
            m.sync_dir(root)
            ledger.body.update(phase='PREPARED',plan=plan,preparation_receipt=receipt)
            head=ledger.publish(ledger.body)
            return dict(state='PREPARED',head_sha256=head,plan=plan,preparation_receipt=receipt,automatic_retry=False)
        except BaseException:
            ledger.body['phase']='UNKNOWN'
            ledger.publish(ledger.body)
            raise


class LifecycleAdoptionPool:
    def __init__(self,ledger):
        self.ledger=ledger;self.owner=ledger.owner;self.root=ledger.root
        p=ledger.profile
        self.policy=dict(runtime_id=p['runtime_id'],action_key={k:p['action_key'][k] for k in ('key_id','key_version','public_key_hex')},authorization_store_root=p['authorization_store_root'])
        self.policy_bytes=m.raw(self.policy)
    def _consume(self,ticket,plan,intent):
        b=self.ledger.body
        m.need(b['phase']=='PREPARED' and plan==b['plan'] and ticket==m.sha(self.ledger.current))
        b['phase']='ADOPTING';self.ledger.publish(b);fault('after_adoption_intent')
    def _complete(self,ticket,plan,receipt):
        m.need(self.ledger.body['phase']=='ADOPTING')
        self.ledger.body.update(phase='COMPLETE',completion=receipt)
        self.ledger.publish(self.ledger.body)


def adopt(ledger,request):
    with ledger.locked():
        b=ledger.load();p=ledger.profile
        m.need(b['phase']=='PREPARED','Not a fresh prepared action; inspect recovery, no replay.')
        receipt=b['preparation_receipt'];body=m.authenticate(receipt,ledger.owner.trust)
        m.need(receipt['issuer_identity']==ledger.owner.issuer and body['profile_sha256']==ledger.profile_sha)
        plan=b['plan'];base=dict(plan);base.pop('preparation_receipt_sha256')
        m.need(plan['preparation_receipt_sha256']==m.digest(receipt) and body['base_plan_sha256']==m.digest(base))
        m.need(set(request)=={'rulebook','snapshot','result','authorization'})
        registry=schema.build_registry([m.load.load_json_bytes(f.read_bytes()) for f in sorted(resources.schema_dir().glob('*.schema.json'))])
        pinned=rulebook.load_rulebook_bytes(m.raw(request['rulebook']),registry)
        frozen=snapshot.verify_snapshot_value(request['snapshot'],pinned,registry)
        result=gate.evaluate(pinned,a.action_for(plan),frozen.value(),registry)
        m.need(result.value()==request['result'],'Result differs from Run evaluation.')
        key=p['action_key'];keys=authorization.build_key_registry([dict(key_id=key['key_id'],key_version=key['key_version'],public_key=bytes.fromhex(key['public_key_hex']),status=key['status'])])
        nonce_root=a._path(p['authorization_store_root']);m.need(nonce_root.is_dir())
        ledger.check_profile()
        receipt=a.adopt(b['managed_root'],plan,pool=LifecycleAdoptionPool(ledger),ticket=m.sha(ledger.current),
            pinned=pinned,snapshot=frozen,result=result,authorization=request['authorization'],runtime_id=p['runtime_id'],
            verification_time=now(),authorization_keys=keys,registry=registry,authorization_store=store.LocalStore(nonce_root))
        return dict(state='COMPLETE',head_sha256=m.sha(ledger.current),receipt=receipt,automatic_retry=False)


def recover(ledger):
    with ledger.locked():
        b=ledger.load();m.need(not b['recovery_used'],'Recovery budget consumed; no repeat.')
        m.need(len(ledger.current)<=ledger.profile['recovery_bytes'],'Recovery input exceeds reserved bytes.')
        b['recovery_used']=True;head=ledger.publish(b)
        return dict(state=b['phase'],head_sha256=head,completion=b['completion'],automatic_retry=False,
            construction_resumed=False,authority_granted=False,charged_recovery_bytes=ledger.profile['recovery_bytes'])
