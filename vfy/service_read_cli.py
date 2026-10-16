"""Bounded public stdin/stdout service readers. No workspace or live accounting API."""
import base64
import os
import stat
import types
from pathlib import Path
from vfy import child_ledger as m, common_capacity as common

MAX_STDIN=16*1024*1024
MAX_INPUTS=8*1024*1024
MAX_STDOUT=65536
RECEIPT_SHA256='99c42d7d4ba0b00432a452fccaa744ef5b20f4a85f04d86375441f4b18a4d8cb'
ADOPTION_SHA256='0c98ad29c930d7a772ebe2203ab0c7a1c12f958ddaa4abb5f14e70d04826be66'
FLAGS=dict(authority_granted=False,automatic_retry=False)


def _module(name,expected):
    path=Path(__file__).resolve().with_name(name+'.py')
    raw=m.read_file(path)
    m.need(m.sha(raw)==expected,'Installed module does not match selected source.')
    return path,raw


def _inputs(value,names,limit):
    m.need(type(value) is dict and set(value)==set(names));result={};total=0
    for name in names:
        entry=value[name]
        m.need(type(entry) is dict and set(entry)=={'base64','sha256'} and type(entry['base64']) is str and m.hex64(entry['sha256']))
        m.need(len(entry['base64'])<=4*((m.MAX_BYTES+2)//3))
        raw=base64.b64decode(entry['base64'],validate=True)
        m.need(base64.b64encode(raw).decode('ascii')==entry['base64'] and len(raw)<=m.MAX_BYTES and m.sha(raw)==entry['sha256'])
        total+=len(raw);m.need(total<=limit);result[name]=raw
    return result


def _limits(value,extra):
    m.need(type(value) is dict and set(value)=={'input_bytes','output_bytes',*extra} and
           all(common.integer(v) and v>0 for v in value.values()))
    m.need(value['input_bytes']<=MAX_INPUTS and 1024<=value['output_bytes']<=MAX_STDOUT)


class _ReadBudget:
    def __init__(self,limits):self.limits=limits;self.used=dict(read_bytes=0,read_calls=0);self.failed=False
    def read(self,path):
        try:
            p=Path(path);m.need(p.is_absolute() and p==p.resolve())
            m.need(self.used['read_calls']<self.limits['read_calls'],'Read call limit exhausted.')
            self.used['read_calls']+=1
            fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                before=os.fstat(fd)
                m.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=m.MAX_BYTES)
                m.need(self.used['read_bytes']+before.st_size<=self.limits['read_bytes'],'Read payload limit exhausted.')
                self.used['read_bytes']+=before.st_size
                with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(before.st_size)
                after=os.fstat(fd)
                m.need(len(raw)==before.st_size and (before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns))
                return raw
            finally:os.close(fd)
        except Exception:self.failed=True;raise


def _unknown():
    return dict(state='UNKNOWN',content_state='UNKNOWN',intent_present=None,service_execution=False,
                semantic_acceptance='UNESTABLISHED',**FLAGS)


def _reconcile(root,plan,trust,limits):
    path,raw=_module('service_adoption',ADOPTION_SHA256)
    runtime=types.ModuleType('_vfy_cli_selected_reconciliation');runtime.__file__=str(path);runtime.__package__='vfy'
    exec(compile(raw,str(path),'exec'),runtime.__dict__)
    reader=_ReadBudget(limits)
    proxy=types.SimpleNamespace(**vars(m));proxy.read_file=reader.read;runtime.m=proxy
    # Identity describes the exact code just loaded; no additional self-file read.
    runtime.identity=lambda:dict(profile='vfy.service-adoption/1',source_sha256=ADOPTION_SHA256)
    os_proxy=types.SimpleNamespace(**vars(os))
    def fail(error):reader.failed=True;raise error
    def walk(top,**kwargs):kwargs['onerror']=fail;return os.walk(top,**kwargs)
    os_proxy.walk=walk;runtime.os=os_proxy
    result=runtime.reconcile(Path(root),plan,owner_trust=trust)
    if reader.failed:result=_unknown()
    return result,reader.used,reader.failed


def run(*,command,request_sha256,stdin,out):
    """Exactly one bounded JSON response; 0=read response, 12=refusal, 1=I/O failure."""
    mode='HISTORICAL_RECEIPT' if command=='verify-service-receipt' else 'SELECTED_READ_ONLY_RECONCILIATION'
    response=dict(schema='vfy.service-read-cli-response/1',command=command,request_sha256=request_sha256,
        state='REFUSED',mode=mode,result=None,read_usage=None,read_incomplete=False,error=None,
        full_cost='UNKNOWN',read_cost_charged=False,**FLAGS)
    limit=MAX_STDOUT
    try:
        m.need(command in ('verify-service-receipt','reconcile-service-repair') and m.hex64(request_sha256))
        raw=stdin.read(MAX_STDIN+1)
        m.need(type(raw) is bytes and len(raw)<=MAX_STDIN and m.sha(raw)==request_sha256,'Wrong or oversized selected stdin.')
        q=m.load.load_json_bytes(raw)
        if command=='verify-service-receipt':
            m.need(set(q)=={'schema','inputs','module_sha256','owner_issuer','limits'} and
                   q['schema']=='vfy.verify-service-receipt-request/1' and q['module_sha256']==RECEIPT_SHA256)
            _limits(q['limits'],{'trace_entries'});m.need(q['limits']['trace_entries']<=100000)
            limit=q['limits']['output_bytes'];inputs=_inputs(q['inputs'],('receipt','trace','request','ticket','policy','trust'),q['limits']['input_bytes'])
            path,source=_module('service_review_receipt',RECEIPT_SHA256)
            verifier=types.ModuleType('_vfy_cli_historical_receipt_verifier')
            verifier.__file__=str(path);verifier.__package__='vfy'
            exec(compile(source,str(path),'exec'),verifier.__dict__)
            response['result']=verifier.verify_receipt(**{k+'_bytes':v for k,v in inputs.items() if k!='trust'},
                owner_trust=m.load.load_json_bytes(inputs['trust']),expected_owner_issuer=q['owner_issuer'],
                limits=dict(input_bytes=q['limits']['input_bytes'],trace_entries=q['limits']['trace_entries']))
        else:
            m.need(set(q)=={'schema','inputs','module_sha256','root','limits'} and
                   q['schema']=='vfy.reconcile-service-repair-request/1' and q['module_sha256']==ADOPTION_SHA256)
            _limits(q['limits'],{'read_bytes','read_calls'})
            m.need(q['limits']['read_bytes']<=64*1024*1024 and q['limits']['read_calls']<=10000)
            limit=q['limits']['output_bytes'];inputs=_inputs(q['inputs'],('plan','trust'),q['limits']['input_bytes'])
            plan=m.load.load_json_bytes(inputs['plan']);trust=m.load.load_json_bytes(inputs['trust'])
            m.need(type(plan) is dict and type(trust) is dict and bool(trust) and type(q['root']) is str and
                   len(q['root'])<=4096 and plan['fixture']['root']['path']==q['root'])
            response['result'],response['read_usage'],response['read_incomplete']=_reconcile(q['root'],plan,trust,q['limits'])
        response['state']='READ_COMPLETED';data=m.raw(response)+b'\n'
        m.need(len(data)<=limit,'Selected stdout limit exceeded.')
        code=0
    except Exception as exc:
        # Do not echo malformed documents, source contents or unbounded exception text.
        response.update(state='REFUSED',result=None,error=type(exc).__name__)
        data=m.raw(response)+b'\n';code=12
        if len(data)>1024:
            data=m.raw(dict(schema='vfy.service-read-cli-response/1',state='REFUSED',error='INVALID_REQUEST',**FLAGS))+b'\n'
    try:out.write(data.decode('utf-8'))
    except (OSError,ValueError):return 1
    return code
