#!/usr/bin/env python3
"""Selected retained bytes only. No seed, live pool handle, session or action API."""
import base64,json,hashlib
from pathlib import Path
from vfy import child_ledger as m, service_tests
root=Path('/private/tmp/verify-service-s8ketd64')
base=Path('/private/tmp/verify-run-service-s8ketd64-accounting-20261016')
names=('ACCOUNTING.json','ACCOUNTING_ADMISSION.json','ACCOUNTING_CONSUMPTION.json','ACCOUNTING_RESULT.json','PREVIEW.json','START.json','RESULT.json','TEST_SELECTION.json','stdout.bin','stderr.bin')
paths=[root/n for n in names]+[base/n for n in ('PROFILE.json','REQUEST.json','APPROVAL.json','PREPARED.json','pool/state.json')]
before={str(p):m.sha(p.read_bytes()) for p in paths}
profile_raw=(base/'PROFILE.json').read_bytes()
assert m.sha(profile_raw)=='65d3404911aac21e9bd7c5908e8c870ce52d7f1e2cff299b5af64a93c910dbe6'
p=json.loads(profile_raw);inputs={k:base64.b64decode(v['base64'],validate=True) for k,v in p['inputs'].items()}
assert all(m.sha(inputs[k])==v['sha256'] for k,v in p['inputs'].items())
selected=dict(p['selection']);selected.pop('expected_snapshot_sha256')
records={name:(root/name).read_bytes() for name in names}
views=[];envelopes=[]
for name in ('ACCOUNTING_ADMISSION.json','ACCOUNTING_CONSUMPTION.json','ACCOUNTING_RESULT.json'):
    data=records[name]
    handle=service_tests.load_service_pool(snapshot_bytes=data,expected_snapshot_sha256=m.sha(data),
        expected_config_bytes=inputs['config'],predecessor_snapshot_bytes=inputs['predecessor'],policy_bytes=inputs['policy'],
        managed_legacy_snapshot_bytes=None,**selected)
    views.append(handle.verify_snapshot(data));envelopes.append(json.loads(data))
assert [e['body']['revision'] for e in envelopes]==[2,3,4]
initial=json.loads(inputs['snapshot'])
for prior,next_ in zip([initial]+envelopes,envelopes):assert next_['body']['previous']==prior['sha256']
assert records['ACCOUNTING_RESULT.json']==(base/'pool/state.json').read_bytes()
assert len(envelopes[-1]['body']['entries'])==1
request=(base/'REQUEST.json').read_bytes();approval=(base/'APPROVAL.json').read_bytes();q=json.loads(request)
assert m.sha(request)=='e8e5d33c0b30209a051f2160c8e9aa109444e99404d940e64642f177e00487ad'
assert m.sha(approval)=='506af56a6ee210c03835660911739c18768624962528c7c6ff3baa883cff8e8b'
binding=json.loads(records['ACCOUNTING.json'])
assert all(binding[k]==value for k,value in dict(request_sha256=m.sha(request),approval_sha256=m.sha(approval),preview_sha256=q['preview_sha256'],profile_sha256=m.sha(profile_raw)).items())
assert q['attempt_root']==str(root) and q['pool_root']==str(base/'pool')
assert m.sha(records['PREVIEW.json'])==q['preview_sha256']=='05666f73a27785b53b106a19a3387e1fa00611c395b88b663da53cf612d93dcc'
preview=json.loads(records['PREVIEW.json']);assert json.loads(records['START.json'])==dict(preview=q['preview_sha256'])
for record,state in zip(envelopes,('ADMITTED','CONSUMED','OBSERVED_EXIT_ZERO')):
    entry=record['body']['entries'][0]
    assert entry['state']==state and entry['request_raw_hex']==request.hex() and entry['approval_raw_hex']==approval.hex()
    if state!='ADMITTED':assert entry['start_sha256']==m.sha(records['START.json'])
result=json.loads(records['RESULT.json']);end=envelopes[-1]['body']['entries'][0]['result']
assert end['result_sha256']==m.sha(records['RESULT.json']) and end['exit']==result['exit']==0
assert result['state']=='PROCESS_OBSERVED' and result['startup_observed'] is True and result['inputs_unchanged'] is True and result['limit_failure'] is None
for stream in ('stdout','stderr'):
    assert end[stream+'_sha256']==result[stream+'_sha256']==m.sha(records[stream+'.bin'])
    assert end[stream+'_bytes']==len(records[stream+'.bin'])
assert views[-1]['used']==views[-1]['capacities']==dict(dispatch_slots=1,retained_output_bytes=1048576)
assert views[-1]['service_used']==views[-1]['service_capacities']==q['resources']==preview['limits']
report=json.loads(records['stdout.bin']);selection=json.loads(records['TEST_SELECTION.json'])
assert m.sha(records['TEST_SELECTION.json'])==preview['test_selection_sha256']
ids=[e['id'] for e in report['events']]
assert len(ids)==len(set(ids))==report['tests_run']==15 and set(ids)==set(selection['case_ids'])
assert report['schema']=='engineer.service-tests/1' and report['preview_sha256']==q['preview_sha256'] and report['completed'] is True and report['successful'] is True
assert all(e['outcome']=='success' for e in report['events'])
selection_bindings={k:selection[k]==preview[k] for k in ('adapter_sha256','capture_sha256')}
selection_bindings.update({k+'_sha256':selection[k+'_sha256']==m.sha(m.raw(preview[k])) for k in ('source','examiner','environment')})
selection_bindings['runner_sha256']=selection['runner_sha256']==preview['test_runner_sha256']
assert all(selection_bindings.values())
assert m.sha(records['TEST_SELECTION.json'])=='b71df825b0cce7c99d437c1ed928983a5991e2b6adc638faf7052ad6436e20f6'
assert m.sha(records['ACCOUNTING_RESULT.json'])=='7818392992a91ef80cbcfe59eca15add5861dfe426facc4c12f9f4e7e5df5f7c'
observation_path=Path('/private/tmp/verify-service-s8ketd64-selected-observation.json')
observation_raw=observation_path.read_bytes()
assert m.sha(observation_raw)=='8d55a886b8da79627f6e1551c7d6c88824da3f75729ca904d837ba92f9378648'
checker=service_tests.TestObservationChecker(handle,selection_bytes=records['TEST_SELECTION.json'],
    requirements_bytes=(base/'FROZEN_REQUIREMENTS.json').read_bytes(),
    runner_bytes=(root/'runner/verify_service_runner.py').read_bytes(),
    limits=dict(input_bytes=16777216,cases=4096,requirements=1024,retained_bytes=33554432))
args=dict(preview_bytes=records['PREVIEW.json'],start_bytes=records['START.json'],
    result_bytes=records['RESULT.json'],stdout_bytes=records['stdout.bin'],stderr_bytes=records['stderr.bin'],
    accounting_snapshot_bytes=records['ACCOUNTING_RESULT.json'],request_sha256=m.sha(request))
observed=checker.check(**args)
assert observed==json.loads(observation_raw)
assert observed['state']=='OBSERVED_SELECTED_CASES_SUCCESS' and observed['reason_codes']==[]
assert observed['semantic_acceptance']=='UNESTABLISHED' and observed['authority_granted'] is False
for key in ('preview_bytes','stdout_bytes','accounting_snapshot_bytes'):
    bad=dict(args);bad[key]+=b'changed'
    assert checker.check(**bad)['state']=='UNKNOWN'
assert observation_path.read_bytes()==observation_raw
assert before=={str(p):m.sha(p.read_bytes()) for p in paths}
print(json.dumps(dict(disposition='ACCEPTED_SCOPED_RETAINED_SERVICE_ACCOUNTING_AND_SELECTED_CASES',state='OBSERVED_EXIT_ZERO',
    revision_chain=[1,2,3,4],entries=1,usage=views[-1]['used'],service_charged=views[-1]['service_used'],
    output_payload_bytes=end['stdout_bytes']+end['stderr_bytes'],tests_reported_success=15,
    exact_case_set_matches=True,selection_identity_matches_current_preview=selection_bindings,
    retained_bytes_unchanged=True,owner_seed_read=False,live_capability_created=False,
    service_executed_by_review=False,review_cost_charged=False,full_cost='UNKNOWN',
    semantic_acceptance='UNESTABLISHED',source_freshness='NOT_CHECKED',hashes=before),indent=2))
