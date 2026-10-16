"""Exact current-adoption read-only successor. Legacy reader remains unchanged."""
import os
import types
from pathlib import Path
from vfy import child_ledger as m
from vfy import service_read_cli as legacy

ADOPTION_SHA256='63eb7b87fdb841ac04d1062a0346de8c12a2259567ff290d30dc6c1db0bd6e7a'


def run(*,request_sha256,stdin,out):
    response=dict(schema='vfy.service-read-cli-response/2',command='reconcile-service-repair-current',
        request_sha256=request_sha256,state='REFUSED',result=None,read_usage=None,
        read_incomplete=False,full_cost='UNKNOWN',read_cost_charged=False,**legacy.FLAGS)
    try:
        raw=stdin.read(legacy.MAX_STDIN+1)
        m.need(m.hex64(request_sha256) and type(raw) is bytes and len(raw)<=legacy.MAX_STDIN and m.sha(raw)==request_sha256)
        q=m.load.load_json_bytes(raw)
        m.need(type(q) is dict and set(q)=={'schema','inputs','module_sha256','root','limits'} and
            q['schema']=='vfy.reconcile-service-repair-request/2' and q['module_sha256']==ADOPTION_SHA256)
        legacy._limits(q['limits'],{'read_bytes','read_calls'})
        m.need(q['limits']['read_bytes']<=64*1024*1024 and q['limits']['read_calls']<=10000)
        inputs=legacy._inputs(q['inputs'],('plan','trust'),q['limits']['input_bytes'])
        plan=m.load.load_json_bytes(inputs['plan']);trust=m.load.load_json_bytes(inputs['trust'])
        m.need(type(plan) is dict and type(trust) is dict and bool(trust) and type(q['root']) is str and
            len(q['root'])<=4096 and plan['fixture']['root']['path']==q['root'])
        path,source=legacy._module('service_adoption',ADOPTION_SHA256)
        runtime=types.ModuleType('_vfy_cli_current_reconciliation');runtime.__file__=str(path);runtime.__package__='vfy'
        exec(compile(source,str(path),'exec'),runtime.__dict__)
        reader=legacy._ReadBudget(q['limits']);proxy=types.SimpleNamespace(**vars(m));proxy.read_file=reader.read;runtime.m=proxy
        runtime.identity=lambda:dict(profile='vfy.service-adoption/1',source_sha256=ADOPTION_SHA256)
        osp=types.SimpleNamespace(**vars(os))
        def fail(error):reader.failed=True;raise error
        def walk(top,**kwargs):kwargs['onerror']=fail;return os.walk(top,**kwargs)
        osp.walk=walk;runtime.os=osp
        result=runtime.reconcile(Path(q['root']),plan,owner_trust=trust)
        response.update(state='READ_COMPLETED',result=legacy._unknown() if reader.failed else result,
            read_usage=reader.used,read_incomplete=reader.failed)
        data=m.raw(response)+b'\n';m.need(len(data)<=q['limits']['output_bytes']);code=0
    except Exception as exc:
        response.update(state='REFUSED',result=None,error=type(exc).__name__)
        data=m.raw(response)+b'\n';code=12
    try:out.write(data.decode('utf-8'))
    except (OSError,ValueError):return 1
    return code
