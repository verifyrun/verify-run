"""Check only supplied selected proposal bytes; no filesystem or capability calls."""
from vfy import child_ledger as m, service_attempt as service

def check(pool,checker,inputs):
    q=pool._request(inputs['request']);p=service.evidence(inputs['preview'])
    m.need(m.sha(inputs['preview'])==q['preview_sha256'] and p.get('schema')=='engineer.service-observation/1'
        and p.get('root')==q['attempt_root'] and p.get('limits')==q['resources'],'PROPOSAL_PREVIEW_MISMATCH')
    s=checker.selection
    m.need(p.get('test_selection_sha256')==m.sha(inputs['selection']) and p.get('test_runner_sha256')==s['runner_sha256'],'PROPOSAL_SELECTION_MISMATCH')
    for name in ('source','examiner','environment'):
        m.need(type(p.get(name)) is dict and m.digest(p[name])==s[name+'_sha256'],'PROPOSAL_CAPTURE_MISMATCH')
    for name in ('adapter_sha256','capture_sha256'):
        m.need(p.get(name)==s[name] and p.get(name)==pool.policy[name],'PROPOSAL_CODE_MISMATCH')
    m.need(p.get('labels')==s['labels'],'PROPOSAL_LABELS_MISMATCH')
    m.need(all(q['resources'][k]<=pool.policy['resource_capacities'][k] for k in service.RESOURCES),'PROPOSED_RESOURCE_CEILING')
    approval=m.load.load_json_bytes(inputs['approval'])
    m.need(m.authenticate(approval,pool.policy['approval_trust'])==pool._approval_body(inputs['request'],q['preview_sha256']),'PROPOSAL_APPROVAL_MISMATCH')
    # An archived snapshot proves neither current state nor future freshness.
    record=m.load.load_json_bytes(inputs['snapshot'])
    for e in record['body']['entries']:
        prior=pool._request(bytes.fromhex(e['request_raw_hex']))
        m.need(all(prior[k]!=q[k] for k in ('attempt_id','attempt_root','preview_sha256')),'PROPOSAL_ALREADY_PRESENT_IN_SELECTED_SNAPSHOT')
    w=m.load.load_json_bytes(inputs['workflow'])
    m.need(w.get('schema')=='vfy.service-workflow/1' and w.get('scope')=='DISPOSABLE_DEVELOPMENT_ONLY'
        and w.get('labels')==p['labels'] and w.get('observation_limits')==q['resources'],'PROPOSAL_WORKFLOW_SELECTION_MISMATCH')
    binding=p.get('task_successor_binding')
    m.need(type(binding) is dict and set(binding)=={'schema','task_sha256','revision','predecessor_observation_sha256','authority_granted','automatic_retry'}
        and binding['schema']=='vfy.service-test-task-binding/1' and binding['task_sha256']==m.sha(inputs['task'])
        and type(binding['revision']) is int and 1<=binding['revision']<=64
        and binding['authority_granted'] is False and binding['automatic_retry'] is False,'PROPOSAL_TASK_MISMATCH')
    pred=binding['predecessor_observation_sha256']
    m.need((binding['revision']==1 and pred is None) or (binding['revision']>1 and m.hex64(pred)),'PROPOSAL_TASK_PREDECESSOR_INVALID')
    context=m.load.load_json_bytes(inputs['platform_context'])
    m.need(type(context) is dict and len(inputs['platform_context'])<=65536,'BOUNDED_CALLER_CONTEXT_REQUIRED')
    return dict(schema='vfy.service-proposal-preflight/1',state='SELECTED_PROPOSAL_BYTES_VERIFIED',
        refs={k:m.sha(v) for k,v in inputs.items()},task_binding=binding,proposed_resources=q['resources'],
        selected_case_ids=s['case_ids'],selected_requirements=list(checker.requirements),
        workflow_validation='SELECTED_FIELDS_ONLY_NOT_FULL_WORKFLOW_ADMISSION',
        platform_context='OPAQUE_SELECTED_BYTES_NOT_AUTHENTICATED_PLATFORM_AUTHORITY',
        runtime_identity='NOT_AUTHENTICATED_BY_WORKFLOW_RUNTIME_ID',
        live_head_freshness='UNESTABLISHED',capacity_at_live_admission='UNESTABLISHED',
        current_source='UNESTABLISHED',semantic_coverage='UNESTABLISHED',
        admission_granted=False,dispatch_supported=False,authority_granted=False,automatic_retry=False)
