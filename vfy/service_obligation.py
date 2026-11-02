"""Immutable agent-proposed obligation, scoped review and discriminating observations.

No semantic discovery or arbitrary-text proof. Protected review policy is supplied
by the admitted workflow; uploaded requirements never select their own authority.
"""
from vfy import child_ledger as m,authorization,gate,rulebook,snapshot

SCHEMA='vfy.service-obligation/1'
FIELDS={'schema','edition','obligation_id','task_id','goal','finding','source_manifest','requirements',
        'requirement_paths','case_mapping','gain_cases','preservation_cases','exclusions','test_manifest',
        'checker_identity','analysis_handoff'}

def validate(o):
 m.need(type(o) is dict and set(o)==FIELDS and o['schema']==SCHEMA and o['edition']=='IMMUTABLE_SINGLE_EDITION')
 for k in ('obligation_id','task_id','goal'):m.need(type(o[k]) is str and 0<len(o[k].encode())<=8192)
 f=o['finding'];m.need(type(f) is dict and set(f)=={'origin','author_id','statement','evidence'} and f['origin']=='AGENT_PROPOSED_NOT_VERIFY_DISCOVERED')
 m.need(m.text(f['author_id']) and m.text(f['statement']) and type(f['evidence']) is list and 0<len(f['evidence'])<=128)
 for manifest in (o['source_manifest'],o['test_manifest']):
  m.need(type(manifest) is dict and 0<len(manifest)<=10000)
  for path,v in manifest.items():
   m.need(type(path) is str and path and not path.startswith('/') and all(p not in ('','.','..') for p in path.split('/')) and '\\' not in path)
   m.need(type(v) is dict and set(v)=={'sha256','bytes','executable'} and m.hex64(v['sha256']) and type(v['bytes']) is int and v['bytes']>=0 and type(v['executable']) is int and v['executable'] in {0,1,8,9,64,65,72,73})
 for e in f['evidence']:
  m.need(type(e) is dict and set(e)=={'path','sha256','start_line','end_line'})
  m.need(e['path'] in o['source_manifest'] and e['sha256']==o['source_manifest'][e['path']]['sha256'])
  m.need(type(e['start_line']) is int and type(e['end_line']) is int and 1<=e['start_line']<=e['end_line'])
 req=o['requirements'];paths=o['requirement_paths'];mapping=o['case_mapping']
 m.need(type(req) is dict and 0<len(req)<=64 and type(paths) is dict and type(mapping) is dict and set(req)==set(paths)==set(mapping))
 for rid,text in req.items():
  m.need(m.text(rid) and m.text(text) and type(paths[rid]) is list and bool(paths[rid]) and all(p in o['source_manifest'] for p in paths[rid]))
  m.need(type(mapping[rid]) is list and bool(mapping[rid]) and all(m.text(c) for c in mapping[rid]) and len(set(mapping[rid]))==len(mapping[rid]))
 all_cases=set().union(*(set(v) for v in mapping.values()))
 for k in ('gain_cases','preservation_cases'):
  v=o[k];m.need(type(v) is list and bool(v) and len(set(v))==len(v) and set(v)<=all_cases)
 m.need(not set(o['gain_cases'])&set(o['preservation_cases']) and set(o['gain_cases'])|set(o['preservation_cases'])==all_cases)
 m.need(type(o['exclusions']) is list and all(m.text(v) for v in o['exclusions']))
 m.need(type(o['checker_identity']) is dict and type(o['analysis_handoff']) is dict)
 return o

def action(o,evidence_digest):
 validate(o);m.need(m.hex64(evidence_digest))
 return dict(candidate_id=m.digest(o),kind='custom',action=dict(summary='Record independent scoped obligation examination',params=dict(schema='verify.obligation-review/1',obligation_sha256=m.digest(o),review_evidence_sha256=evidence_digest,disposition='ACCEPT_SCOPED_OBLIGATIONS')))

def review(o,request,profile,registry,now,consumed_nonces):
 validate(o)
 m.need(type(profile) is dict and set(profile)=={'schema','rulebook','rulebook_digest','reviewer_keys','author_public_keys','runtime_id'} and profile['schema']=='vfy.obligation-review-profile/1')
 m.need(type(request) is dict and set(request)=={'snapshot','authorization'})
 pinned=rulebook.load_rulebook_bytes(m.raw(profile['rulebook']),registry);m.need(pinned.digest==profile['rulebook_digest'])
 snap=snapshot.verify_snapshot_value(request['snapshot'],pinned,registry)
 a=action(o,snap.digest.removeprefix('sha256:'));result=gate.evaluate(pinned,a,snap.value(),registry)
 entries=profile['reviewer_keys'];m.need(type(entries) is list and bool(entries) and bool(profile['author_public_keys']))
 keys=authorization.build_key_registry([{**e,'public_key':bytes.fromhex(e['public_key'])} for e in entries])
 sig=request['authorization']['signature'];key=keys[(sig['key_id'],sig['key_version'])]
 m.need(key['public_key'] not in {bytes.fromhex(v) for v in profile['author_public_keys']},'Author cannot independently review own obligation')
 verified=authorization.verify_authorization(request['authorization'],pinned,a,snap,result,profile['runtime_id'],now,keys,registry,consumed_nonces=consumed_nonces)
 return dict(schema='vfy.obligation-review-observation/1',obligation_sha256=m.digest(o),authorization_sha256=m.digest(verified.value()),state='AUTHENTICATED_SCOPED_EXAMINATION',semantic_truth='CONDITIONAL_ON_INDEPENDENT_EXAMINER_NOT_AUTOMATIC_PROOF',author_identity='HOST_ASSERTED_ASSOCIATION_TO_PROTECTED_AUTHOR_KEYS',authority_granted=False,nonce_consumed=False)

def compare(o,*,baseline,candidate,baseline_preview,candidate_preview,baseline_selection,candidate_selection,requirements,original_manifest,task_id):
 validate(o)
 m.need(o['task_id']==task_id and o['source_manifest']==original_manifest==baseline_preview['source'],'Original source/task differs from frozen obligation')
 m.need(requirements=={'schema':'vfy.service-requirements/1','requirements':o['requirements']},'Frozen requirements differ')
 for p,s,c in ((baseline_preview,baseline_selection,baseline),(candidate_preview,candidate_selection,candidate)):
  m.need(p['examiner']==o['test_manifest'] and s['requirement_cases']==o['case_mapping'],'Test source or case mapping differs')
  m.need(c['checker_identity']==o['checker_identity'],'Checker runtime differs')
  m.need(c['state'] in ('OBSERVED_SELECTED_CASES_SUCCESS','OBSERVED_SELECTED_CASES_NON_SUCCESS'),'Observation incomplete or uncertain')
 same={k:v for k,v in baseline_selection.items() if k!='source_sha256'}
 m.need(same=={k:v for k,v in candidate_selection.items() if k!='source_sha256'},'Baseline and repair selected checks differ')
 before={e['id']:e['outcome'] for e in baseline['report']['events']};after={e['id']:e['outcome'] for e in candidate['report']['events']}
 m.need(any(before[c]=='failure' for c in o['gain_cases']),'No selected baseline counterexample')
 m.need(all(after[c]=='success' for c in o['gain_cases']),'Proposed repair did not pass gain cases')
 m.need(all(before[c]==after[c]=='success' for c in o['preservation_cases']),'Preservation not demonstrated')
 return dict(state='SELECTED_REPAIR_AND_PRESERVATION_OBSERVED',obligation_sha256=m.digest(o),baseline_sha256=m.digest(baseline),candidate_sha256=m.digest(candidate),discovery_origin=o['finding']['origin'],exclusions=o['exclusions'],full_semantic_coverage='UNKNOWN',authority_granted=False)
