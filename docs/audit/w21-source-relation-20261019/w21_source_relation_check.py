import json,subprocess,hashlib
from pathlib import Path
B=Path('/private/tmp/w21-public-synthetic-r2-20261019');O=Path('/private/tmp/w21-source-relation-evidence-20261019');O.mkdir(exist_ok=True)
raw=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
q=json.loads((B/'CURRENT_READER_REQUEST.json').read_text());q['schema']='vfy.service-source-relation-request/1';data=raw(q)
p=subprocess.run(['/private/tmp/w21-source-relation-installed-20261019/bin/python','-I','-m','vfy.service_source_relation_cli','--request-sha256',hashlib.sha256(data).hexdigest()],input=data,capture_output=True)
(O/'REQUEST.json').write_bytes(data);(O/'RESULT.json').write_bytes(p.stdout)
v=json.loads(p.stdout);assert p.returncode==0 and v['state']=='READ_COMPLETED',v
assert v['result']['source_relation']=='MISMATCH' and v['result']['state']=='UNKNOWN',v
assert v['diagnostic_sha256']==hashlib.sha256(raw({'request_sha256':v['request_sha256'],'result':v['result']})).hexdigest()
print('PASS genuine retained changed public copy, no producer replay',v['result']['source_relation'])
