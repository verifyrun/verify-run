"""Independent stdlib-only public CLI consumer; retained bytes only, no service actions."""
import base64,hashlib,json,subprocess
from pathlib import Path
root=Path('/private/tmp/verify-service-s8ketd64');base=Path('/private/tmp/verify-run-service-s8ketd64-accounting-20261016')
artifact=Path('/private/tmp/verify-run-service-tests-cli-artifacts-20261016')
exe='/private/tmp/verify-run-service-tests-cli-env-20261016/bin/vfy'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def raw(obj):return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
def packed(b):return dict(base64=base64.b64encode(b).decode(),sha256=sha(b))
paths=dict(context=base/'CONSUMER_CONTEXT.json',snapshot=root/'ACCOUNTING_RESULT.json',
 selection=root/'TEST_SELECTION.json',requirements=base/'FROZEN_REQUIREMENTS.json',runner=root/'runner/verify_service_runner.py',
 preview=root/'PREVIEW.json',start=root/'START.json',result=root/'RESULT.json',stdout=root/'stdout.bin',stderr=root/'stderr.bin',request=base/'REQUEST.json')
data={k:p.read_bytes() for k,p in paths.items()}
assert sha(data['snapshot'])=='7818392992a91ef80cbcfe59eca15add5861dfe426facc4c12f9f4e7e5df5f7c'
assert sha(data['context'])=='3d4ad9057492867ca0643f15fad5d7c6874d884e309c055eb11ca6d6f9dbc49c'
assert sha(data['selection'])=='b71df825b0cce7c99d437c1ed928983a5991e2b6adc638faf7052ad6436e20f6'
selected=Path('/private/tmp/verify-service-s8ketd64-selected-observation.json').read_bytes()
assert sha(selected)=='8d55a886b8da79627f6e1551c7d6c88824da3f75729ca904d837ba92f9378648'
protected=list(paths.values())+list((base/'pool').rglob('*'))
before={str(p):sha(p.read_bytes()) for p in protected if p.is_file()}
q=dict(schema='vfy.check-service-tests-request/1',module_sha256='40b900a8a9d9d2d19a027542df2fa43ce9e6a6a099bca793d861af1c22204a83',
 inputs={k:packed(b) for k,b in data.items()},minimum_revision=4,
 limits=dict(input_bytes=16777216,output_bytes=1048576,cases=4096,requirements=1024))
def call(q):
 b=raw(q);p=subprocess.run([exe,'check-service-tests','--request-sha256',sha(b)],input=b,capture_output=True,timeout=30)
 assert len(p.stdout)<=q['limits']['output_bytes'] and not p.stderr
 result=json.loads(p.stdout);assert result['request_sha256']==sha(b)
 return p.returncode,result,p.stdout
code,response,stdout=call(q)
assert code==0 and response['result']==json.loads(selected)
with (artifact/'S8KETD64_REQUEST.json').open('xb') as f:f.write(raw(q))
with (artifact/'S8KETD64_RESPONSE.json').open('xb') as f:f.write(stdout)
controls={}
for key in data:
 bad=json.loads(raw(q));bad['inputs'][key]['sha256']='f'*64
 assert call(bad)[0]==12;controls[key+'_digest']='REFUSED'
bad=json.loads(raw(q));bad['inputs']['stdout']=packed(b'{}')
code,result,_=call(bad);assert code==0 and result['result']['state']=='UNKNOWN'
controls['rebound_uncertain_stdout']='UNKNOWN'
assert before=={str(p):sha(p.read_bytes()) for p in protected if p.is_file()}
old=Path('/private/tmp/verify-run-service-session-env-20261016/lib/python3.14/site-packages/vfy')
new=Path('/private/tmp/verify-run-service-tests-cli-env-20261016/lib/python3.14/site-packages/vfy')
identities={}
for name in ('child_ledger','service_tests','service_attempt','service_adoption','service_review','service_review_receipt','service_read_cli','service_accounting_cli'):
 assert (old/(name+'.py')).read_bytes()==(new/(name+'.py')).read_bytes()
 identities[name]=sha((new/(name+'.py')).read_bytes())
report=dict(state='INSTALLED_RETAINED_SELECTED_CASES_ACCEPTED',request_sha256=sha(raw(q)),
 response_sha256=sha(stdout),cases=15,exact_prior_observation_equal=True,controls=controls,
 evidence_and_pool_bytes_unchanged=True,service_executed=False,unchanged_modules=identities,
 cli_module_sha256=sha((new/'service_tests_cli.py').read_bytes()),scope='Historical process claims; semantic and fullcost unestablished')
with (artifact/'INSTALLED_VALIDATION.json').open('x') as f:json.dump(report,f,indent=2)
print(json.dumps(report,indent=2))
