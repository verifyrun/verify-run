"""Extract reviewed function AST; only stubbed I/O, no Engineer imports or effects."""
import ast,json,tempfile,types
from pathlib import Path
source=Path('/private/tmp/verify-engineer-continuation-20261013/engineer/change/service_observation.py').read_text()
node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='execute_accounted')
# Strip the two imports and supply deterministic interfaces; actual function body retained.
node.body=[n for n in node.body if not isinstance(n,(ast.Import,ast.ImportFrom))]
events=[]
class Session:
    def __init__(self,*a):pass
    def exchange(self,*a):return {}
    def close(self):raise TimeoutError('synthetic shutdown timeout')
def execute(*a,**k):raise ValueError('original observation failure')
with tempfile.TemporaryDirectory() as d:
    root=Path(d);(root/'PREVIEW.json').write_bytes(b'{}')
    env=dict(Path=Path,load=lambda p:({},'preview'),Session=Session,sha=lambda b:'digest',
        canonical=lambda v:b'{}',durable=lambda *a:None,_execute=execute,
        fcntl=types.SimpleNamespace(flock=lambda *a:None,LOCK_EX=1,LOCK_NB=2),
        os=types.SimpleNamespace(open=lambda *a:123,close=lambda fd:events.append(('closed',fd)),
            O_CREAT=1,O_RDWR=2,O_NOFOLLOW=4))
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<reviewed-execute_accounted>','exec'),env)
    try:env['execute_accounted'](root,'preview',profile='not-opened',profile_sha256='a'*64,request_bytes=b'{}',approval_bytes=b'{}')
    except Exception as exc:result=dict(exception=type(exc).__name__,message=str(exc),caller_lock_closed=bool(events),scope='AST_EXTRACTED_FUNCTION_STUBBED_IO_NO_ENGINEER_OR_SERVICE_EXECUTION')
    assert result['exception']=='TimeoutError' and result['caller_lock_closed'] is False
    print(json.dumps(result,indent=2))
