"""One selected development CHECK through an existing live Run pool.

The trusted host holds its current caller/task authority lock while invoking this
command. A profile pins that host selection; it does not authenticate a remote
caller. No application adoption, retry, or reusable admission ticket is returned.
"""
import importlib
import io
import os
import stat
import sys
import time
from pathlib import Path
from vfy import child_ledger as m, service_accounting_cli as accounting
from vfy import service_proposal_cli as proposal_cli
from vfy.service_read_cli import _inputs

FORMAT='vfy.check-execution-profile/1'

def load_adapter(selected):
    m.need(type(selected) is dict and set(selected)=={'root','files'})
    root=Path(selected['root']);m.need(root.is_absolute() and root==root.resolve() and root.name=='engineer')
    files=selected['files'];m.need(type(files) is dict and 1<=len(files)<=5000)
    actual={};total=0
    for path in root.rglob('*'):
        m.need(not path.is_symlink(),'Linked supplier member refused')
        if path.is_file():
            m.need(path.suffix not in ('.pyc','.so','.dylib'),'Unselected supplier executable refused')
            if path.suffix=='.py':
                raw=accounting.bounded_file(path,8*1024*1024);total+=len(raw)
                m.need(total<=64*1024*1024,'Supplier byte bound exceeded')
                actual[str(path.relative_to(root))]=m.sha(raw)
    m.need(actual==files,'Installed supplier closure changed')
    m.need(not any(n=='engineer' or n.startswith('engineer.') for n in sys.modules),'Supplier already loaded')
    sys.path.insert(0,str(root.parent));sys.dont_write_bytecode=True
    try: adapter=importlib.import_module('engineer.change.service_observation')
    finally:sys.path.remove(str(root.parent))
    m.need(Path(adapter.__file__)==root/'change/service_observation.py')
    return adapter

def run(*,profile,profile_sha256,request_sha256,authorization_monotonic_ns,stdin,out,now,monotonic_ns=time.monotonic_ns):
    result=dict(schema='vfy.check-execution-result/1',state='REFUSED_BEFORE_ADMISSION',
        profile_sha256=profile_sha256,proposal_sha256=request_sha256,accounting=None,
        platform_context_sha256=None,authorization_monotonic_ns=str(authorization_monotonic_ns),launch_deadline_monotonic_ns=None,automatic_retry=False,application_adoption=False,
        semantic_acceptance='UNESTABLISHED',error=None)
    ticket=None;pool=None
    try:
        raw=accounting.bounded_file(profile,proposal_cli.MAX_STDIN)
        m.need(m.sha(raw)==profile_sha256)
        p=m.load.load_json_bytes(raw)
        m.need(type(p) is dict and set(p)=={'schema','accounting_profile','accounting_profile_sha256','proposal_sha256','platform_context_sha256','engineer_package','launch_window_seconds'} and p['schema']==FORMAT)
        m.need(type(p['launch_window_seconds']) is int and 1<=p['launch_window_seconds']<=30)
        m.need(type(authorization_monotonic_ns) is int and 0<=authorization_monotonic_ns<=2**63-1)
        deadline=authorization_monotonic_ns+p['launch_window_seconds']*1000000000
        result['launch_deadline_monotonic_ns']=str(deadline)
        def fresh():
            current=monotonic_ns()
            m.need(authorization_monotonic_ns<=current<=deadline,'One-shot launch window expired')
        fresh()
        m.need(m.hex64(request_sha256) and request_sha256==p['proposal_sha256'])
        data=stdin.read(proposal_cli.MAX_STDIN+1)
        check=io.StringIO();m.need(proposal_cli.run(request_sha256=request_sha256,stdin=io.BytesIO(data),out=check)==0,'Proposal refused')
        q=m.load.load_json_bytes(data);inputs=_inputs(q['inputs'],proposal_cli.NAMES,q['limits']['input_bytes'])
        m.need(m.sha(inputs['platform_context'])==p['platform_context_sha256'])
        result['platform_context_sha256']=p['platform_context_sha256']
        adapter=load_adapter(p['engineer_package'])
        request=m.load.load_json_bytes(inputs['request']);preview=m.load.load_json_bytes(inputs['preview'])
        m.need(request['resources']==adapter.LIMITS,'Executor resource ceilings differ')
        with accounting.selected_pool(p['accounting_profile'],p['accounting_profile_sha256']) as (pool,seconds):
            m.need(seconds>=request['resources']['wall_seconds']+5,'Accounting session ceiling too short')
            m.need(pool.snapshot()==inputs['snapshot'],'Selected proposal head changed')
            m.need(pool.policy_bytes==bytes.fromhex(m.load.load_json_bytes(inputs['context'])['policy_hex']))
            m.need(accounting.bounded_file(profile,proposal_cli.MAX_STDIN)==raw,'Host selection changed')
            root=Path(request['attempt_root'])
            m.need(root.is_absolute() and root==root.resolve() and root.is_dir(),'Noncanonical attempt root')
            m.need(accounting.bounded_file(root/'PREVIEW.json',m.MAX_BYTES)==inputs['preview'],'Preview changed')
            fd=os.open(root/'ACCOUNTING.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            import fcntl
            try:
                m.need(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink==1)
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                m.need(not os.path.lexists(root/'START.json') and not os.path.lexists(root/'ACCOUNTING.json'),'Attempt already used')
                fresh()
                ticket=pool.admit(request_bytes=inputs['request'],preview_bytes=inputs['preview'],approval_bytes=inputs['approval'],recorded_at=now())
                result['state']='ADMITTED_NOT_EXECUTED'
                def consume(start):
                    fresh()
                    m.need(accounting.bounded_file(profile,proposal_cli.MAX_STDIN)==raw,'Host selection changed')
                    pool.consume(ticket,request_bytes=inputs['request'],preview_bytes=inputs['preview'],start_bytes=start,recorded_at=now())
                    result['state']='CONSUMED_OUTCOME_UNKNOWN'
                def before_launch():
                    fresh()
                    m.need(accounting.bounded_file(profile,proposal_cli.MAX_STDIN)==raw,'Host selection changed')
                adapter._execute(root,request['preview_sha256'],_consume=consume,_before_launch=before_launch)
                settled=pool.settle(ticket,result_bytes=accounting.bounded_file(root/'RESULT.json',m.MAX_BYTES),stdout_bytes=accounting.bounded_file(root/'stdout.bin',request['resources']['output_bytes']),stderr_bytes=accounting.bounded_file(root/'stderr.bin',request['resources']['output_bytes']),recorded_at=now())
                result.update(state='CHECK_SETTLED',accounting=settled)
            except BaseException:
                if ticket is not None:
                    try:pool.mark_unknown(ticket,reason='selected check interrupted or refused; no retry',recorded_at=now())
                    except Exception:pass
                    result['state']='UNKNOWN_NO_RETRY'
                raise
            finally:
                pool._live.clear();os.close(fd)
        code=0
    except Exception as exc:
        result['error']=type(exc).__name__;code=12
    out.write((m.raw(result)+b'\n').decode());return code

def status(*,profile,profile_sha256,request_sha256,stdin,out):
    """Authenticate retained exact attempt state; absence never authorizes retry."""
    from vfy import service_tests
    response=dict(schema='vfy.check-execution-status/1',state='REFUSED',automatic_retry=False,accounting=None,error=None)
    try:
        raw=accounting.bounded_file(profile,proposal_cli.MAX_STDIN);m.need(m.sha(raw)==profile_sha256)
        p=m.load.load_json_bytes(raw);m.need(p['schema']==FORMAT and p['proposal_sha256']==request_sha256)
        data=stdin.read(proposal_cli.MAX_STDIN+1);m.need(len(data)<=proposal_cli.MAX_STDIN and m.sha(data)==request_sha256)
        q=m.load.load_json_bytes(data);inputs=_inputs(q['inputs'],proposal_cli.NAMES,proposal_cli.MAX_INPUTS)
        spraw=accounting.bounded_file(p['accounting_profile'],proposal_cli.MAX_STDIN);m.need(m.sha(spraw)==p['accounting_profile_sha256'])
        sp=m.load.load_json_bytes(spraw);parts=_inputs(sp['inputs'],('snapshot','config','predecessor','policy','managed_legacy'),proposal_cli.MAX_INPUTS)
        selection=dict(sp['selection'])
        m.need(not os.path.lexists(Path(selection['expected_pool_root'])/'pending.json'),'Unresolved pending publication')
        snapshot=accounting.bounded_file(Path(selection['expected_pool_root'])/'state.json',m.MAX_BYTES)
        selection['expected_snapshot_sha256']=m.sha(snapshot)
        pool=service_tests.load_service_pool(**selection,snapshot_bytes=snapshot,expected_config_bytes=parts['config'],predecessor_snapshot_bytes=parts['predecessor'],policy_bytes=parts['policy'],managed_legacy_snapshot_bytes=parts['managed_legacy'] or None)
        pool.verify_snapshot(snapshot);record=m.load.load_json_bytes(snapshot)
        entries=[e for e in record['body']['entries'] if e['request_sha256']==m.sha(inputs['request'])]
        m.need(len(entries)<=1)
        response.update(state=entries[0]['state'] if entries else 'ABSENT_NOT_RETRY_PERMISSION',accounting=record,profile_sha256=profile_sha256,proposal_sha256=request_sha256)
        code=0
    except Exception as exc:response['error']=type(exc).__name__;code=12
    out.write((m.raw(response)+b'\n').decode());return code
