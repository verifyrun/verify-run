"""Read-only selected proposal checks. No admission, keys, or live store access."""
import types
from vfy import child_ledger as m, common_capacity as common
from vfy.service_read_cli import _inputs, _module

CHECKER_SHA256='40b900a8a9d9d2d19a027542df2fa43ce9e6a6a099bca793d861af1c22204a83'
MAX_STDIN=24*1024*1024
MAX_INPUTS=16*1024*1024
MAX_STDOUT=1024*1024
NAMES=('context','snapshot','selection','requirements','runner','preview','request','approval','workflow','task','platform_context')
FLAGS=dict(authority_granted=False,automatic_retry=False)


def run(*,request_sha256,stdin,out):
    response=dict(schema='vfy.service-proposal-preflight-response/1',command='preflight-service-proposal',
        request_sha256=request_sha256,state='REFUSED',mode='SELECTED_BYTES_ONLY_NOT_LIVE_ADMISSION',
        result=None,error=None,current_source_checked=False,read_cost_charged=False,
        full_cost='UNKNOWN',**FLAGS)
    try:
        m.need(m.hex64(request_sha256))
        raw=stdin.read(MAX_STDIN+1)
        m.need(type(raw) is bytes and len(raw)<=MAX_STDIN and m.sha(raw)==request_sha256)
        q=m.load.load_json_bytes(raw)
        m.need(type(q) is dict and set(q)=={'schema','module_sha256','inputs','minimum_revision','limits'}
            and q['schema']=='vfy.service-proposal-preflight-request/1' and q['module_sha256']==CHECKER_SHA256)
        limits=q['limits']
        m.need(type(limits) is dict and set(limits)=={'input_bytes','output_bytes','cases','requirements'}
            and all(common.integer(v) and v>0 for v in limits.values()))
        m.need(limits['input_bytes']<=MAX_INPUTS and 1024<=limits['output_bytes']<=MAX_STDOUT
            and limits['cases']<=4096 and limits['requirements']<=1024)
        m.need(common.integer(q['minimum_revision']) and q['minimum_revision']>=1)
        inputs=_inputs(q['inputs'],NAMES,limits['input_bytes'])
        c=m.load.load_json_bytes(inputs['context'])
        m.need(type(c) is dict and set(c)=={'pool_root','config_hex','owner_trust','child_trust','observer','head_hex','policy_hex'})
        decoded={}
        for name in ('config','head','policy'):
            value=c[name+'_hex']
            m.need(type(value) is str and len(value)<=2*m.MAX_BYTES)
            decoded[name]=bytes.fromhex(value)
            m.need(decoded[name].hex()==value)
        head=m.load.load_json_bytes(decoded['head'])
        m.need(head['body']['schema']=='vfy.common-capacity-state/1' and head['body']['entries']==[],
            'Only an explicitly selected empty common predecessor is supported.')
        path,source=_module('service_tests',CHECKER_SHA256)
        verifier=types.ModuleType('_vfy_cli_selected_service_tests')
        verifier.__file__=str(path);verifier.__package__='vfy'
        exec(compile(source,str(path),'exec'),verifier.__dict__)
        pool=verifier.load_service_pool(snapshot_bytes=inputs['snapshot'],
            expected_snapshot_sha256=m.sha(inputs['snapshot']),expected_pool_root=c['pool_root'],
            expected_config_bytes=decoded['config'],owner_trust=c['owner_trust'],child_trust=c['child_trust'],
            selected_observer=c['observer'],predecessor_snapshot_bytes=decoded['head'],
            policy_bytes=decoded['policy'],expected_child_trusts={},minimum_revision=q['minimum_revision'])
        checker=verifier.TestObservationChecker(pool,selection_bytes=inputs['selection'],
            requirements_bytes=inputs['requirements'],runner_bytes=inputs['runner'],
            limits=dict(input_bytes=limits['input_bytes'],cases=limits['cases'],
                requirements=limits['requirements'],retained_bytes=33554432))
        from vfy import service_proposal as proposal
        result=proposal.check(pool,checker,inputs)
        response.update(state='PROPOSAL_BYTES_VERIFIED_NOT_ADMITTED',result=result)
        data=m.raw(response)+b'\n'
        m.need(len(data)<=limits['output_bytes'],'Selected output bound exceeded.')
        code=0
    except Exception as exc:
        response.update(state='REFUSED',result=None,error=type(exc).__name__)
        data=m.raw(response)+b'\n';code=12
        if len(data)>1024:
            response['request_sha256']=None
            data=m.raw(response)+b'\n'
    try:out.write(data.decode('utf-8'))
    except (OSError,ValueError):return 1
    return code
