"""Bounded historical receipt-chain verification. Never adoption or current freshness.

The caller appoints policy from its own registry. Uploaded policy is not authority.
No filesystem source, nonce store, managed copy or producer is read or modified.
"""
from vfy import child_ledger as m, service_read_cli as read, service_adoption as adoption
from vfy import authorization, rulebook, snapshot, schema, resources, gate
MAX_BYTES=2*1024*1024
FLAGS=dict(authority_granted=False,current_reliance=False,automatic_retry=False,service_execution=False)

def verify(inputs,policy,expected_final_plan_sha256):
    m.need(set(inputs)=={'plan','preparation','intent','completion'} and all(type(v) is bytes for v in inputs.values()) and sum(map(len,inputs.values()))<=MAX_BYTES)
    m.need(set(policy)=={'owner_trust','owner_issuer','profile_sha256','runtime_id','action_key'})
    m.need(m.hex64(expected_final_plan_sha256) and m.hex64(policy['profile_sha256']))
    values={k:m.load.load_json_bytes(v) for k,v in inputs.items()}
    plan,prep,intent,completion=(values[k] for k in ('plan','preparation','intent','completion'))
    m.need(plan['schema']=='vfy.service-adoption-plan/1' and m.digest(plan)==expected_final_plan_sha256,'Wrong final plan.')
    m.need(all(plan[k] is False for k in adoption.FLAGS))
    prepared=m.authenticate(prep,policy['owner_trust']);done=m.authenticate(completion,policy['owner_trust'])
    m.need(prep['issuer_identity']==completion['issuer_identity']==policy['owner_issuer'],'Wrong receipt issuer.')
    base=dict(plan);base.pop('preparation_receipt_sha256')
    m.need(prepared['schema']=='vfy.service-preparation-lifecycle/1/prepared' and prepared['profile_sha256']==policy['profile_sha256'])
    m.need(plan['preparation_receipt_sha256']==m.digest(prep) and prepared['base_plan_sha256']==m.digest(base) and prepared['task_id']==plan['task_id'],'Preparation binding differs.')
    m.need(all(prepared[k] is False for k in adoption.FLAGS))
    m.need(intent['schema']=='vfy.service-adoption-intent/1' and intent['plan_sha256']==m.digest(plan) and intent['destination']==plan['destination'] and intent['source_sha256']==m.digest(plan['base_manifest']))
    m.need(intent['runtime_id']==policy['runtime_id'] and all(intent[k] is False for k in adoption.FLAGS))
    m.need(done['schema']=='vfy.service-adoption-completion/1' and done['state']=='OBSERVED_CANDIDATE' and done['plan_sha256']==m.digest(plan) and done['intent_sha256']==m.sha(inputs['intent']) and done['candidate_sha256']==m.digest(plan['candidate_manifest']) and done['destination']==plan['destination'])
    m.need(done['service_execution'] is False and done['semantic_acceptance']=='UNESTABLISHED' and all(done[k] is False for k in adoption.FLAGS))
    registry=schema.build_registry([m.load.load_json_bytes(p.read_bytes()) for p in sorted(resources.schema_dir().glob('*.schema.json'))])
    pinned=rulebook.load_rulebook_bytes(m.raw(intent['rulebook']),registry)
    frozen=snapshot.verify_snapshot_value(intent['snapshot'],pinned,registry)
    result=gate.evaluate(pinned,adoption.action_for(plan),frozen.value(),registry)
    m.need(result.value()==intent['result'],'Historical gate result differs.')
    key=policy['action_key'];sig=intent['authorization']['signature']
    m.need(set(key)=={'key_id','key_version','public_key_hex','status'} and sig['key_id']==key['key_id'] and sig['key_version']==key['key_version'])
    keys=authorization.build_key_registry([dict(key_id=key['key_id'],key_version=key['key_version'],public_key=bytes.fromhex(key['public_key_hex']),status=key['status'])])
    # Verify against the signed historical intent time, not current authorization.
    # No nonce store is consulted and no replay permission follows.
    authorization.verify_authorization(intent['authorization'],pinned,adoption.action_for(plan),frozen,result,policy['runtime_id'],intent['verification_time'],keys,registry)
    return dict(final_plan_sha256=m.digest(plan),base_plan_sha256=m.digest(base),preparation_receipt_sha256=m.digest(prep),authorization_sha256=m.digest(intent['authorization']),completion_sha256=m.digest(completion),intent_bytes_sha256=m.sha(inputs['intent']),source_sha256=m.digest(plan['base_manifest']),requirements_sha256=plan['requirements_sha256'],selection_sha256=plan['selection_sha256'],producer_identity=plan['producer_identity'],root=plan['fixture']['root']['path'],destination=plan['destination'],accounting_predecessor_sha256=plan['accounting_predecessor_sha256'],semantic_acceptance='UNESTABLISHED',full_physical_cost='UNKNOWN',**FLAGS)

def run(*,request_sha256,stdin,out):
    response=dict(schema='vfy.service-adoption-history-response/1',request_sha256=request_sha256,state='REFUSED',result=None,**FLAGS)
    code=12
    try:
        raw=stdin.read(MAX_BYTES+1)
        m.need(type(raw) is bytes and len(raw)<=MAX_BYTES and m.sha(raw)==request_sha256)
        q=m.load.load_json_bytes(raw)
        m.need(set(q)=={'schema','inputs','policy','expected_final_plan_sha256'} and q['schema']=='vfy.verify-service-adoption-history-request/1')
        inputs=read._inputs(q['inputs'],('plan','preparation','intent','completion'),MAX_BYTES)
        response['result']=verify(inputs,q['policy'],q['expected_final_plan_sha256'])
        m.need(len(m.raw(response))<=65536,'Historical response exceeds bound.')
        response['state']='HISTORICAL_ADOPTION_VERIFIED';code=0
    except Exception:
        response['result']=None
    out.write((m.raw(response)+b'\n').decode());return code
