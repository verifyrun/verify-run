"""Byte-only historical paid-review receipt correspondence; never reads an operation.

No spending key, pool object, reconciliation, filesystem traversal or freshness claim.
"""
from pathlib import PurePosixPath
from vfy import child_ledger as m, common_capacity as common

REVIEW_IDENTITY={'profile':'vfy.service-review/1','source_sha256':'31bcb1ac6b700b0bc8674a5d95491711afbdd3ca6a222eea6e2dad47bd26683d'}
ADOPTION_SHA256='0c98ad29c930d7a772ebe2203ab0c7a1c12f958ddaa4abb5f14e70d04826be66'
RESOURCES={'read_bytes','read_calls','retained_bytes'}
FLAGS={'authority_granted','automatic_retry'}
EXCLUSIONS=['selection/preparation','imports and dependency loading','module self-identity reads',
            'filesystem metadata and locks','accounting store I/O','CPU/wall enforcement',
            'physical I/O and disk overhead','receipt verification and historical reading']


def _path(value):
    m.need(type(value) is str and 0<len(value)<=4096 and '\x00' not in value)
    p=PurePosixPath(value);m.need(p.is_absolute() and str(p)==value and '..' not in p.parts)


def _flags(value):m.need(all(value[k] is False for k in FLAGS))

def _resources(value):
    m.need(type(value) is dict and set(value)==RESOURCES and all(common.integer(v) for v in value.values()))


def verify_receipt(*,receipt_bytes,trace_bytes,request_bytes,ticket_bytes,policy_bytes,
                   owner_trust,expected_owner_issuer,limits):
    """Raise on invalid correspondence; verified UNKNOWN remains historical UNKNOWN."""
    m.need(type(limits) is dict and set(limits)=={'input_bytes','trace_entries'} and
           all(common.integer(v) and v>0 for v in limits.values()))
    raws=[receipt_bytes,trace_bytes,request_bytes,ticket_bytes,policy_bytes]
    m.need(all(type(raw) is bytes and len(raw)<=m.MAX_BYTES for raw in raws) and
           sum(map(len,raws))<=limits['input_bytes'])
    m.need(len(request_bytes)<=65536 and len(policy_bytes)<=65536 and len(receipt_bytes)<=32768)
    m.need(type(owner_trust) is dict and m.text(expected_owner_issuer))
    receipt,trace,q,ticket,p=[m.load.load_json_bytes(raw) for raw in raws]
    m.need(ticket_bytes==m.raw(ticket) and receipt_bytes==m.raw(receipt), 'Select exact canonical signed records.')
    b=m.authenticate(receipt,owner_trust);t=m.authenticate(ticket,owner_trust)
    m.need(receipt['issuer_identity']==ticket['issuer_identity']==expected_owner_issuer)
    m.need(set(p)=={'schema','pool_root','predecessor_sha256','review_identity','adoption_sha256',
                   'resource_capacities','accounting_scope',*FLAGS})
    _flags(p);_path(p['pool_root']);_resources(p['resource_capacities'])
    m.need(p['schema']=='vfy.service-review-policy/1' and p['review_identity']==REVIEW_IDENTITY and
           p['adoption_sha256']==ADOPTION_SHA256 and m.hex64(p['predecessor_sha256']) and
           p['accounting_scope']=='EXPLICIT_DEVELOPMENT_REVIEW_ONLY')
    m.need(set(q)=={'schema','review_id','pool_root','policy_sha256','operation_root',
        'plan_path','plan_sha256','trust_path','trust_sha256','adoption_module_path','adoption_sha256',
        'expected_source_sha256','resources',*FLAGS})
    _flags(q);_resources(q['resources'])
    m.need(all(q['resources'][k]<=p['resource_capacities'][k] for k in RESOURCES))
    for key in ('pool_root','operation_root','plan_path','trust_path','adoption_module_path'):_path(q[key])
    for key in ('plan_sha256','trust_sha256','adoption_sha256','expected_source_sha256'):m.need(m.hex64(q[key]))
    m.need(q['schema']=='vfy.service-review-request/1' and q['pool_root']==p['pool_root'] and
           q['policy_sha256']==m.sha(policy_bytes) and q['adoption_sha256']==ADOPTION_SHA256 and
           m.text(q['review_id']) and len(q['review_id'])<=256 and all(v>0 for v in q['resources'].values()) and
           65536<=q['resources']['retained_bytes']<=m.MAX_BYTES and q['resources']['read_calls']<=100000)
    m.need(set(t)=={'schema','pool_root','policy_sha256','review_identity','predecessor_raw_hex','entries',
                   'revision','previous',*FLAGS})
    _flags(t)
    m.need(t['schema']=='vfy.service-review/1' and t['pool_root']==q['pool_root'] and
           t['policy_sha256']==q['policy_sha256'] and t['review_identity']==REVIEW_IDENTITY and
           m.sha(bytes.fromhex(t['predecessor_raw_hex']))==p['predecessor_sha256'] and
           common.integer(t['revision']) and m.hex64(t['previous']) and type(t['entries']) is list and bool(t['entries']))
    e=t['entries'][-1]
    m.need(set(e)=={'request_raw_hex','request_sha256','recorded_at','consumed_at','receipt_sha256'} and
           e['request_raw_hex']==request_bytes.hex() and e['request_sha256']==m.sha(request_bytes) and
           m.text(e['recorded_at']) and e['consumed_at'] is None and e['receipt_sha256'] is None)
    m.need(set(b)=={'schema','state','request','request_sha256','ticket_sha256','review_identity',
        'observed_source_sha256','source_relation','run_result','charged','reserved','full_reservation_retained',
        'trace_sha256','reason','recorded_at','task_id','requirements_sha256','selection_sha256',
        'full_cost','exclusions','service_execution',*FLAGS})
    _flags(b)
    m.need(b['schema']=='vfy.service-review-receipt/1' and b['state'] in ('REVIEW_RECORDED','UNKNOWN_HOLD_RETAINED') and
           b['request']==q and b['request_sha256']==m.sha(request_bytes) and
           b['ticket_sha256']==m.digest(ticket) and b['review_identity']==REVIEW_IDENTITY and
           b['reserved']==q['resources'] and b['full_reservation_retained'] is True and
           b['full_cost']=='UNKNOWN' and b['exclusions']==EXCLUSIONS and b['service_execution'] is False and
           m.text(b['recorded_at']) and (b['reason'] is None or m.text(b['reason'])))
    observed=b['observed_source_sha256'];m.need(observed is None or m.hex64(observed))
    relation='UNKNOWN' if observed is None else 'MATCH' if observed==q['expected_source_sha256'] else 'MISMATCH'
    m.need(b['source_relation']==relation)
    run=b['run_result'];_flags(run)
    m.need(run['service_execution'] is False and run['semantic_acceptance']=='UNESTABLISHED' and
           run['state'] in ('UNKNOWN','OBSERVED_CANDIDATE') and run['content_state'] in ('BASE','CANDIDATE','MIXED','UNKNOWN') and
           (run['intent_present'] is None or type(run['intent_present']) is bool))
    if run['state']=='OBSERVED_CANDIDATE':
        m.need(b['state']=='REVIEW_RECORDED' and relation=='MATCH' and run['content_state']=='CANDIDATE' and
               run['intent_present'] is True and m.hex64(run['receipt_sha256']))
    if b['state']=='UNKNOWN_HOLD_RETAINED' or relation!='MATCH':m.need(run['state']=='UNKNOWN')
    if b['state']=='REVIEW_RECORDED':m.need(b['reason'] is None)
    for key in ('requirements_sha256','selection_sha256'):m.need(b[key] is None or m.hex64(b[key]))
    m.need(b['task_id'] is None or m.text(b['task_id']))
    m.need(type(trace) is list and len(trace)<=limits['trace_entries'] and m.sha(trace_bytes)==b['trace_sha256'])
    total=0
    for event in trace:
        m.need(type(event) is dict and set(event)=={'path','bytes','sha256'})
        _path(event['path']);m.need(common.integer(event['bytes']) and event['bytes']<=m.MAX_BYTES and m.hex64(event['sha256']))
        total+=event['bytes']
    charged=b['charged']
    m.need(type(charged) is dict and set(charged)=={'read_bytes','read_calls'} and
           all(common.integer(n) and n<=q['resources'][k] for k,n in charged.items()) and
           charged['read_bytes']>=total and charged['read_calls']>=len(trace))
    if b['state']=='REVIEW_RECORDED':
        m.need(charged==dict(read_bytes=total,read_calls=len(trace)) and len(trace)>=3)
        for event,pathkey,hashkey in zip(trace[:3],('plan_path','trust_path','adoption_module_path'),
                                       ('plan_sha256','trust_sha256','adoption_sha256')):
            m.need(event['path']==q[pathkey] and event['sha256']==q[hashkey])
    m.need(len(receipt_bytes)+len(trace_bytes)<=q['resources']['retained_bytes'])
    return dict(state='VERIFIED_HISTORICAL_REVIEW_RECEIPT',recorded_review_state=b['state'],run_result=run,
        request_sha256=m.sha(request_bytes),ticket_sha256=m.digest(ticket),receipt_sha256=m.sha(receipt_bytes),
        trace_sha256=m.sha(trace_bytes),recorded_at=b['recorded_at'],selection=q,task_id=b['task_id'],
        requirements_sha256=b['requirements_sha256'],selection_sha256=b['selection_sha256'],
        source_relation=relation,observed_source_sha256=observed,charged=charged,reserved=b['reserved'],
        full_reservation_retained=True,current_source_checked=False,current_pool_checked=False,
        settlement_verified=False,full_prefix_accounting_verified=False,full_cost='UNKNOWN',
        verification_cost_charged=False,authority_granted=False,automatic_retry=False)
