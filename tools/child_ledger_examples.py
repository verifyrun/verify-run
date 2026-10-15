"""Generate selected synthetic protocol cases; no actual service or credential."""
import json,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from vfy import child_ledger as m

def main(out):
    out=Path(out).resolve();out.mkdir()
    seed=bytes(range(32)); key=Ed25519PrivateKey.from_private_bytes(seed)
    trust={'PUBLIC-FIXTURE-ONLY':{'public_key_hex':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),'producer_identity':m.producer()}}
    def write(p,v): p.write_bytes(m.raw(v))
    def rows(n,f): return [{'axis_id':'captured_console_bytes','unit':'byte','aggregation':'SUM','scope':'DIRECT_CHILD_CAPTURED_OUTPUT',f:n}]
    basis={'path':'synthetic-only-input','sha256':'1'*64}
    start={'state':'STARTED','automatic_retry':False,'task_key':'fixture-task','task_identity':{'subject_sha256':'2'*64},'operation_id':'fixture-parent','attempt_id':'fixture-parent-attempt','input_artifacts':[basis],'native_child_population':{'state':'DECLARED_BEFORE_DISPATCH','expected_child_ids':['settled','interrupted','performed-unsettled','unknown-service']}}
    sb=json.dumps(start,indent=2).encode();(out/'START.json').write_bytes(sb)
    budget={'schema':'vfy.child-resource-budget/1','budget_id':'fixture-dedicated-partition','task_key':start['task_key'],'task_identity':start['task_identity'],'parent_start_sha256':m.sha(sb),'resource_rows':rows('40','limit')}
    bb=m.raw(budget);(out/'budget.json').write_bytes(bb);write(out/'basis.json',basis);write(out/'public-trust-FIXTURE-ONLY.json',trust)
    l=m.Ledger.create(out/'ledger',sb,basis,bb,seed,'PUBLIC-FIXTURE-ONLY',trust)
    for child in start['native_child_population']['expected_child_ids']:
        r=l.reserve(child,'fixture-attempt-'+child,rows('7','reserved_amount'),'2026-10-06T00:00:00Z');rid=r['body']['reservation_id']
        if child=='interrupted': continue
        l.dispatch_record(rid,'2026-10-06T00:00:01Z')
        service='UNKNOWN' if child=='unknown-service' else 'PERFORMED'; measured=rows('0' if service=='UNKNOWN' else '4','measured_amount')
        p=out/(child+'.synthetic-observation.json');write(p,{'schema':'vfy.child-observation/1','reservation_id':rid,'service_performed':service,'resource_rows':measured})
        c=l.complete(rid,service,measured,{'path':str(p),'sha256':m.sha(p.read_bytes())},'2026-10-06T00:00:02Z')
        if child!='performed-unsettled': l.settle(rid,c['sha256'],'2026-10-06T00:00:03Z')
    selected=l.snapshot();(out/'selected-report.json').write_bytes(selected)
    write(out/'verification.json',m.verify_report(selected,trust,sb,basis,bb))
    write(out/'NOTICE.json',{'fixture_only':True,'actual_service_performed':False,'observation_meaning':'Synthetic protocol fields only, not actual runtime measurements. Public fixture seed is bytes(range(32)); never trust this issuer for real evidence.','authority_granted':False,'automatic_retry':False})
if __name__=='__main__':main(sys.argv[1])
