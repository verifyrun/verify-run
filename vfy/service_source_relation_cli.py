"""Versioned read-only source relation; no test execution or action authority.

A complete scan under the existing cooperative lock is not an atomic snapshot
against arbitrary noncooperating writers or an assertion about change time.
"""
import argparse
import os
import stat
import sys
import types
from pathlib import Path
from vfy import child_ledger as m
from vfy import service_read_cli as legacy
from vfy.service_current_read_cli import ADOPTION_SHA256

SCHEMA='vfy.service-source-relation-response/1'
COMMAND='inspect-service-source-relation'


def _population(root,limits):
    """Bounded metadata stability witness, not an adversarial ABA guarantee."""
    result={};directories=0;files=0
    def add(p):
        s=p.lstat()
        m.need(not stat.S_ISLNK(s.st_mode) and p==p.resolve())
        m.need(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode))
        if stat.S_ISREG(s.st_mode):m.need(s.st_nlink==1)
        result[p.relative_to(root).as_posix()]=[s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    add(root)
    def fail(error):raise error
    for parent,dirs,names in os.walk(root,followlinks=False,onerror=fail):
        directories+=len(dirs);files+=len(names)
        m.need(directories<=limits['files']*64 and files<=limits['files'])
        for name in dirs+names:add(Path(parent)/name)
    return result


def inspect(root,plan,trust,limits):
    path,source=legacy._module('service_adoption',ADOPTION_SHA256)
    runtime=types.ModuleType('_vfy_source_relation');runtime.__file__=str(path);runtime.__package__='vfy'
    exec(compile(source,str(path),'exec'),runtime.__dict__)
    reader=legacy._ReadBudget(limits);proxy=types.SimpleNamespace(**vars(m));proxy.read_file=reader.read;runtime.m=proxy
    runtime.identity=lambda:dict(profile='vfy.service-adoption/1',source_sha256=ADOPTION_SHA256)
    osp=types.SimpleNamespace(**vars(os))
    def fail(error):reader.failed=True;raise error
    def walk(top,**kwargs):kwargs['onerror']=fail;return os.walk(top,**kwargs)
    osp.walk=walk;runtime.os=osp
    result=dict(state='UNKNOWN',source_relation='UNKNOWN',diagnostic=None,
                service_execution=False,semantic_acceptance='UNESTABLISHED',**legacy.FLAGS)
    try:
        root=runtime._path(root)
        with runtime._locked(root,shared=True):
            base,candidate=runtime._plan(root,plan)
            intent_raw=reader.read(root/'INTENT.json');intent=m.load.load_json_bytes(intent_raw)
            m.need(intent['plan_sha256']==m.digest(plan) and intent['destination']==plan['destination'] and
                   intent['source_sha256']==m.digest(base) and all(intent[k] is False for k in legacy.FLAGS))
            receipt_raw=reader.read(root/'COMPLETE.json');receipt=m.load.load_json_bytes(receipt_raw)
            body=m.authenticate(receipt,trust)
            m.need(body['schema']=='vfy.service-adoption-completion/1' and body['state']=='OBSERVED_CANDIDATE' and
                   body['plan_sha256']==m.digest(plan) and body['intent_sha256']==m.sha(intent_raw) and
                   body['candidate_sha256']==m.digest(candidate) and body['destination']==plan['destination'] and
                   body['service_execution'] is False and all(body[k] is False for k in legacy.FLAGS))
            before=_population(root/'copy',plan['limits'])
            actual=runtime._scan(root/'copy',plan['limits'])
            after=_population(root/'copy',plan['limits'])
            m.need(not reader.failed and before==after,'Incomplete or changing source scan')
            # Recheck authenticated evidence bytes before returning an observation.
            m.need(reader.read(root/'INTENT.json')==intent_raw and reader.read(root/'COMPLETE.json')==receipt_raw)
            relation='MATCH' if actual==candidate else 'MISMATCH'
            diagnostic=dict(schema='vfy.authenticated-source-relation/1',plan_sha256=m.digest(plan),
                intent_sha256=m.sha(intent_raw),completion_sha256=m.digest(receipt),
                completion_bytes_sha256=m.sha(receipt_raw),expected_manifest_sha256=m.digest(candidate),
                observed_manifest_sha256=m.digest(actual),source_relation=relation,
                scope='COOPERATIVE_LOCK_BOUNDED_POINT_IN_TIME',change_time='UNKNOWN',change_cause='UNKNOWN')
            result.update(state='OBSERVED_CANDIDATE' if relation=='MATCH' else 'UNKNOWN',source_relation=relation,diagnostic=diagnostic)
    except Exception:
        pass # Invalid or incomplete evidence cannot become a confirmed mismatch.
    return result,reader.used,reader.failed


def run(*,request_sha256,stdin,out):
    response=dict(schema=SCHEMA,command=COMMAND,request_sha256=request_sha256,state='REFUSED',result=None,
        diagnostic_sha256=None,read_usage=None,read_incomplete=False,full_cost='UNKNOWN',read_cost_charged=False,**legacy.FLAGS)
    try:
        raw=stdin.read(legacy.MAX_STDIN+1)
        m.need(m.hex64(request_sha256) and type(raw) is bytes and len(raw)<=legacy.MAX_STDIN and m.sha(raw)==request_sha256)
        q=m.load.load_json_bytes(raw)
        m.need(type(q) is dict and set(q)=={'schema','inputs','module_sha256','root','limits'} and
               q['schema']=='vfy.service-source-relation-request/1' and q['module_sha256']==ADOPTION_SHA256)
        legacy._limits(q['limits'],{'read_bytes','read_calls'})
        m.need(q['limits']['read_bytes']<=64*1024*1024 and q['limits']['read_calls']<=10000)
        inputs=legacy._inputs(q['inputs'],('plan','trust'),q['limits']['input_bytes'])
        plan=m.load.load_json_bytes(inputs['plan']);trust=m.load.load_json_bytes(inputs['trust'])
        m.need(type(plan) is dict and type(trust) is dict and bool(trust) and type(q['root']) is str and
               len(q['root'])<=4096 and plan['fixture']['root']['path']==q['root'])
        result,used,incomplete=inspect(Path(q['root']),plan,trust,q['limits'])
        response.update(state='READ_COMPLETED',result=result,read_usage=used,read_incomplete=incomplete)
        response['diagnostic_sha256']=m.digest(dict(request_sha256=request_sha256,result=result))
        data=m.raw(response)+b'\n';m.need(len(data)<=q['limits']['output_bytes']);code=0
    except Exception as exc:
        response.update(state='REFUSED',result=None,diagnostic_sha256=None,error=type(exc).__name__)
        data=m.raw(response)+b'\n';code=12
        if len(data)>1024:data=m.raw(dict(schema=SCHEMA,state='REFUSED',error='INVALID_REQUEST',**legacy.FLAGS))+b'\n'
    try:out.write(data.decode('utf-8'))
    except (OSError,ValueError):return 1
    return code


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--request-sha256',required=True)
    args=parser.parse_args()
    return run(request_sha256=args.request_sha256,stdin=sys.stdin.buffer,out=sys.stdout)

if __name__=='__main__':raise SystemExit(main())
