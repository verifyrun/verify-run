import base64,copy,io,json
from pathlib import Path
from unittest.mock import patch
from vfy import service_source_relation_cli as c
from vfy import child_ledger as m
Q=json.loads(Path('/private/tmp/w21-source-relation-evidence-20261019/REQUEST.json').read_text());results=[]
def call(q):
 out=io.StringIO();raw=m.raw(q);code=c.run(request_sha256=m.sha(raw),stdin=io.BytesIO(raw),out=out);return code,json.loads(out.getvalue())
def unknown(label,q=Q):
 code,r=call(q);assert code==0 and r['result']['source_relation']=='UNKNOWN' and r['result']['diagnostic'] is None,(label,r);results.append(label)
q=copy.deepcopy(Q);q['limits']['read_calls']=1;unknown('read_budget_exhausted',q)
q=copy.deepcopy(Q);trust=json.loads(base64.b64decode(q['inputs']['trust']['base64']));trust={('wrong-'+k):v for k,v in trust.items()};raw=m.raw(trust);q['inputs']['trust']={'base64':base64.b64encode(raw).decode(),'sha256':m.sha(raw)};unknown('wrong_owner_trust',q)
original=c.legacy._ReadBudget.read
for filename in ('COMPLETE.json','INTENT.json'):
 def changed(self,path):
  if Path(path).name==filename:return b'{}'
  return original(self,path)
 with patch.object(c.legacy._ReadBudget,'read',changed):unknown('invalid_'+filename)
original_population=c._population;n=[0]
def racing(*a):
 p=original_population(*a);n[0]+=1
 if n[0]==2:p['.'][4]+=1
 return p
with patch.object(c,'_population',racing):unknown('detected_directory_race')
with patch.object(c,'_population',side_effect=PermissionError('controlled')):unknown('unreadable_population')
q=copy.deepcopy(Q);q['schema']='old-schema';code,r=call(q);assert code==12 and r['state']=='REFUSED';results.append('wrong_schema')
Path('/private/tmp/w21-source-relation-evidence-20261019/NEGATIVES.json').write_bytes(m.raw(dict(state='PASS',controls=results,scope='Read-only real retained inputs with explicit fault injection; no effects or source mutations')))
print('PASS',len(results),results)
