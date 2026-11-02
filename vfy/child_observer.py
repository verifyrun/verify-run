"""Development-only measured verifier adapter, reusing runner._launch.

Protected local filesystem/toolchain premise. No native permission or arbitrary command.
CPU allocation is NOT hard enforcement; timeout/leader exit is NOT a stopped proof.
"""
import json
import math
import os
import signal
import subprocess
import tempfile
import time
from fractions import Fraction
from pathlib import Path
from vfy import child_ledger as m, runner

PROFILE = 'vfy.measured-local-verifier/1'
FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures/child-ledger/measured'


def identity():
    return {'profile':PROFILE,'source_sha256':m.sha(Path(__file__).read_bytes()),
            'runner_sha256':m.sha(Path(runner.__file__).read_bytes()),
            'verifier_code_sha256':m.sha((FIXTURES/'verifier-code.txt').read_bytes()),
            'verifier_pins_sha256':m.sha((FIXTURES/'verifier-pins.json').read_bytes()),
            'runtime_pin_sha256':m.sha((FIXTURES/'runtime.json').read_bytes())}


class _ObservedPopen(subprocess.Popen):
    """Reap this PID once via wait4; never a host-wide CHILDREN delta."""
    usage = None
    def _try_wait(self, wait_flags):
        try:
            pid,status,usage = os.wait4(self.pid,wait_flags)
            if pid: self.usage=usage
            return pid,status
        except ChildProcessError:
            return self.pid,0  # No usage => UNKNOWN, never zero measurement.
    def _internal_poll(self, _deadstate=None, **unused):
        if self.returncode is None and self._waitpid_lock.acquire(False):
            try:
                pid,status=self._try_wait(os.WNOHANG)
                if pid==self.pid:self._handle_exitstatus(status)
            finally:self._waitpid_lock.release()
        return self.returncode


class _Acquisition:
    output_limit=131072  # Two separately capped streams, <=262144 captured bytes.
    def __init__(self,stdin,interrupt):
        self.stdin=stdin;self.interrupt=interrupt;self.process=None;self.before=None
    def spawn(self,*args,**kwargs):
        self.before=time.monotonic_ns()
        self.process=_ObservedPopen(*args,**kwargs)
        if self.interrupt:
            try:os.kill(self.process.pid,signal.SIGSTOP)
            except ProcessLookupError:pass
        return self.process


def inspect_request(ledger, request_bytes, input_bytes, selected_observer):
    """No allocation/dispatch. Exact read-only correspondence; selected observer is external."""
    m.need(selected_observer==identity(),'Observer source mismatch.')
    q=m.load.load_json_bytes(request_bytes)
    signed={k:v for k,v in q.items() if k!='identity_sha256'}
    request_identity=m.sha(json.dumps(signed,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode())
    m.need(q['identity_sha256']==request_identity)
    m.need(q['schema']=='engineer.child-dispatch-request/1' and q['authority_granted'] is False and q['automatic_retry'] is False)
    m.need(q['state']=='INTENT_ONLY_RESERVATION_AND_DISPATCH_NOT_ESTABLISHED')
    sb,basis,bb=ledger.expected;parent=m.parent_binding(sb,basis)
    m.need(m.read_file(Path(q['parent_start']['path']))==sb)
    m.need(q['parent_start']['sha256']==m.sha(sb))
    m.need(q['task_key']==parent['task_key'] and q['task_identity']==parent['task_identity'])
    m.need(q['operation_id']==parent['parent_binding']['operation_id'] and q['attempt_id']==parent['parent_binding']['attempt_id'])
    m.need(q['child_id'] in parent['expected_child_ids'])
    m.need(type(input_bytes) is bytes and len(input_bytes)<=m.MAX_BYTES and len(input_bytes)==q['input_bytes'] and m.sha(input_bytes)==q['input_sha256'])
    argv=q['argv'];m.need(type(argv) is list and len(argv)==5 and argv[1:4]==['-I','-B','-c'])
    m.need(argv[4]==(FIXTURES/'verifier-code.txt').read_text() and q['environment']=={})
    m.need(q['executable']==m.load.load_json_bytes((FIXTURES/'runtime.json').read_bytes()),
           'Interpreter not independently selected by this reviewed profile.')
    executable=Path(argv[0]);resolved=executable.resolve(strict=True)
    m.need(executable.is_absolute() and q['executable']=={'path':str(executable),'resolved_path':str(resolved),'sha256':m.sha(m.read_file(resolved))})
    directory=Path(q['cwd']);m.need(directory.is_absolute() and directory==directory.resolve() and directory.is_dir())
    # Parse the existing pinned-loader payload, never manufacture verifier input.
    payload=m.load.load_json_bytes(input_bytes)
    pins=m.load.load_json_bytes((FIXTURES/'verifier-pins.json').read_bytes())
    m.need(payload['pins']==pins)
    root=Path(payload['root']);m.need(root.is_absolute() and root==root.resolve())
    for name,digest in pins.items():m.need(m.sha(m.read_file(root/name))==digest)
    rows=m.load.load_json_bytes(bb)['resource_rows']
    m.need(set(m.axes(rows,'limit'))==set(m.AXES),'Three declared accounting axes required.')
    m.need(hasattr(os,'wait4'),'Per-PID wait4 unavailable; refuse before reservation.')
    return q


def dispatch_development(ledger, request_bytes, input_bytes, *, selected_observer,
                         recorded_at, interrupt=False, timeout_seconds=30, common_owner=None):
    """One owner-approved local development verifier request; no automatic replay.

    selected_observer is independently pinned reviewed source. Ledger key stays in parent.
    Explicit development scope is separate from action authorization and native custody.
    """
    m.need(type(interrupt) is bool and type(timeout_seconds) is int and 1<=timeout_seconds<=30)
    m.need(common_owner is not None or not (ledger.root/'common-owner.json').exists(),
           'Common-pool partition requires common dispatch; legacy path refused.')
    q=inspect_request(ledger,request_bytes,input_bytes,selected_observer)
    common_ticket=None
    if common_owner is not None:
        from vfy.common_capacity import CapacityOwner
        m.need(type(common_owner) is CapacityOwner and common_owner.observer==selected_observer)
        common_ticket=common_owner.reserve(ledger,request_bytes)
    reservations=[]
    values={'captured_console_bytes':'262144','local_process_cpu_seconds':'10','local_wall_observations_seconds':'30'}
    for name,(unit,aggregation,scope) in m.AXES.items():
        reservations.append({'axis_id':name,'unit':unit,'aggregation':aggregation,'scope':scope,'reserved_amount':values[name]})
    # Durable reservation and signed exact request/source binding both precede Popen.
    r=ledger.reserve(q['child_id'],q['attempt_id']+':'+q['child_id'],reservations,recorded_at)
    rid=r['body']['reservation_id']
    bind={'schema':'vfy.measured-dispatch-binding/1','request_sha256':m.sha(request_bytes),
          'request_identity':q['identity_sha256'],'reservation_sha256':r['sha256'],
          'observer':selected_observer,'input_sha256':m.sha(input_bytes),'argv':q['argv'],
          'executable':q['executable'],'cwd':q['cwd'],'environment':{},'interrupt_requested':interrupt,
          'timeout_seconds':timeout_seconds,'authority_granted':False,'automatic_retry':False}
    if common_ticket is not None:bind['common_reservation_sha256']=common_ticket['sha256']
    binding_record=m.envelope(bind,ledger.key,ledger.issuer)
    m.fresh(ledger.root/(rid+'.binding.json'),m.raw(binding_record))
    if common_ticket is not None:common_owner.bind_dispatch(common_ticket,r,binding_record)
    ledger.dispatch_record(rid,recorded_at)
    # Recheck protected artifacts after publication. Refusal leaves UNKNOWN hold, no retry.
    inspect_request(ledger,request_bytes,input_bytes,selected_observer)
    with tempfile.TemporaryFile() as stdin:
        stdin.write(input_bytes);stdin.seek(0)
        acquisition=_Acquisition(stdin,interrupt)
        out=runner._launch(q['argv'],Path(q['cwd']),{},timeout_seconds,measurement=acquisition)
        after=time.monotonic_ns()
    usage=None if acquisition.process is None else acquisition.process.usage
    cpu='UNKNOWN'
    if usage is not None and all(math.isfinite(v) and v>=0 for v in (usage.ru_utime,usage.ru_stime)):
        cpu=str(Fraction.from_float(usage.ru_utime)+Fraction.from_float(usage.ru_stime))
    wall='UNKNOWN' if acquisition.before is None else str(Fraction(after-acquisition.before,10**9))
    captured=len(out['stdout'])+len(out['stderr'])
    performed=(out['started'] and out['exit_status']==0 and not out['timed_out'] and not out['truncated'] and not interrupt and cpu!='UNKNOWN')
    # The job meaning is this exact verifier result, not arbitrary application success.
    if performed:
        try:performed=m.load.load_json_bytes(out['stdout']).get('state')=='VERIFIED_SELECTED_SNAPSHOT_NOT_FRESHNESS'
        except Exception:performed=False
    service='PERFORMED' if performed else 'UNKNOWN'
    measured={'captured_console_bytes':str(captured),'local_process_cpu_seconds':cpu,'local_wall_observations_seconds':wall}
    rows=[{'axis_id':name,'unit':unit,'aggregation':aggregation,'scope':scope,'measured_amount':measured[name]} for name,(unit,aggregation,scope) in m.AXES.items()]
    observation={'schema':'vfy.child-observation/1','reservation_id':rid,'service_performed':service,'resource_rows':rows}
    obs_path=ledger.root/(rid+'.observation.json');m.fresh(obs_path,m.raw(observation))
    completion=ledger.complete(rid,service,rows,{'path':str(obs_path),'sha256':m.sha(m.raw(observation))},recorded_at)
    settlement=ledger.settle(rid,completion['sha256'],recorded_at)
    facts={'schema':'vfy.measured-child-acquisition/1','binding_sha256':m.sha((ledger.root/(rid+'.binding.json')).read_bytes()),
           'observer':selected_observer,'completion_sha256':completion['sha256'],'settlement_sha256':settlement['sha256'],
           'observation_sha256':m.sha(m.raw(observation)),'stdout_sha256':m.sha(out['stdout']),
           'stderr_sha256':m.sha(out['stderr']),'captured_bytes':captured,'output_truncated':out['truncated'],
           'started':out['started'],'exit_status':out['exit_status'],'signal_number':out['signal_number'],
           'timed_out':out['timed_out'],'service_performed':service,'scope':'REVIEWED_VERIFIER_DIRECT_CHILD_ONLY_NOT_STOPPED_PROOF',
           'cpu_convention':'Exact rational representation of OS wait4 ru_utime+ru_stime binary values; OS resolution/attribution limits apply. No float rounding or global RUSAGE_CHILDREN delta.',
           'wall_convention':'monotonic_ns interval immediately before Popen through runner cleanup, includes observation overhead; not global elapsed time.',
           'limits':'CPU reservation is accounting only, not hard quota; captured bytes are retained bytes not emitted total; descendant lifetime, host/provider/financial costs UNKNOWN.',
           'authority_granted':False,'automatic_retry':False}
    acquisition_record=m.envelope(facts,ledger.key,ledger.issuer)
    m.fresh(ledger.root/(rid+'.acquisition.json'),m.raw(acquisition_record))
    result={'reservation':r,'completion':completion,'settlement':settlement,'acquisition':acquisition_record,'report_bytes':ledger.snapshot(),'stdout':out['stdout'],'stderr':out['stderr']}
    if common_ticket is not None:
        result['common_reservation']=common_ticket
        result['common_settlement']=common_owner.settle(common_ticket,result)
        result['common_snapshot_bytes']=common_owner.snapshot()
    return result
