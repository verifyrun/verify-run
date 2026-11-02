"""Disposable authority fixtures, not live Engineer operations."""
import copy, fcntl, hashlib, json, os, pathlib, sys, unittest
from unittest.mock import patch
from vfy import canon, custody, gate, runner, snapshot
from vfy.errors import VerifyError
from tests.test_execution import _case, _Sandbox, _build, _run, _registry, _receipt_registry, _key_registry, EXEC_DIR

WORKER = '''import os,json
v=json.loads(os.environ['VFY_CUSTODY_HANDOFF']);s=os.fstat(v['fd'])
assert s.st_ino==v['binding']['lease']['inode']
assert s.st_dev==v['binding']['lease']['device']
assert 'AMBIENT_CUSTODY_SENTINEL' not in os.environ
try:os.fstat(200);extra=True
except OSError:extra=False
print(json.dumps({'operation':v['binding']['operation_id'],'source':v['binding']['source_id'],'capability':v['binding']['worker_data']['capability'],'extra':extra}))
'''
H=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

class Custody(unittest.TestCase):
    def setUp(self):
        self.case=_case(EXEC_DIR/'accept_exit_zero.json')
        self.case['rulebook_ref']='fixtures/custody/file-rulebook.yaml'
        self.sb=_Sandbox(self.case['tree']);self.addCleanup(self.sb.__exit__,None,None,None)
        self.registry=_registry(); self.root=self.sb.root.resolve()
        self.worker=self.root/'probe.py';self.worker.write_text(WORKER)
        self.lease=self.root/'lease';self.lease.write_bytes(b'')
        self.fd=os.open(self.lease,os.O_RDONLY);self.addCleanup(os.close,self.fd)
        fcntl.flock(self.fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        self.argv=[str(pathlib.Path(sys.executable).resolve()),'-I','-B',str(self.worker)]
        st=os.fstat(self.fd)
        self.binding={'version':1,'operation_id':'1'*64,'source_id':'2'*64,'argv':self.argv,'lease':{'device':st.st_dev,'inode':st.st_ino},'worker_files':{self.argv[0]:H(self.argv[0]),str(self.worker):H(self.worker)},'worker_data':{'capability':'bounded-test-token'},'coverage':'guarded-intents-v1'}
        self.intent=self.root/'intent.json'
        self.intent.write_bytes(canon.canonical_bytes({'schema':'vfy.custody-intent/1','binding_sha256':custody.digest(self.binding),'state':'PENDING'}))
        self.e={'binding':self.binding,'intent_path':str(self.intent),'intent_sha256':H(self.intent),'fd':self.fd}
        self.case['candidate']['action']['argv']=self.argv
        self.case['candidate']['action']['params']={'run_custody_sha256':custody.commitment(self.e)}
        self.built=_build(self.case,self.sb,self.registry)

    def prepared(self):
        c=custody.Handoff(self.e);self.addCleanup(c.close);return c

    def execute(self,c):
        return _run(self.case,self.sb,self.registry,*self.built,custody=c)

    def no_spend(self):
        self.assertFalse(self.sb.store.is_consumed(self.case['authorization']['nonce']))
        self.assertFalse(pathlib.Path(str(self.intent)+'.terminal.json').exists())

    def test_exact_bound_worker_and_receipt_replay_no_extra_fd(self):
        extra=fcntl.fcntl(self.fd,fcntl.F_DUPFD,200);self.assertEqual(extra,200);os.set_inheritable(extra,True);self.addCleanup(os.close,extra)
        with patch.dict(os.environ,{'AMBIENT_CUSTODY_SENTINEL':'must-not-reach'}):r=self.execute(self.prepared())
        self.assertEqual(r.exit_status,0,r.stderr)
        self.assertEqual(json.loads(r.stdout),{'operation':'1'*64,'source':'2'*64,'capability':'bounded-test-token','extra':False})
        terminal=json.loads(pathlib.Path(str(self.intent)+'.terminal.json').read_bytes())
        self.assertEqual(terminal['scope'],'DIRECT_CHILD_ONLY');self.assertEqual(terminal['returncode'],0)
        stored=self.sb.store.get_record(self.case['receipt_id'],receipt_keys=_receipt_registry(self.case),registry=self.registry,authorization_keys=_key_registry(self.case),verification_time=self.case['verification_time'])
        self.assertEqual(stored.receipt()['execution']['exit_status'],0)
        from vfy import receipt
        pinned,candidate,frozen,result,authorization=self.built
        replay=receipt.replay_receipt(stored.receipt(),(pathlib.Path(__file__).parents[1]/self.case['rulebook_ref']).read_bytes(),candidate,frozen.value(),_receipt_registry(self.case),self.registry,authorization=authorization.value(),authorization_keys=_key_registry(self.case),verification_time=self.case['verification_time'])
        self.assertIsNotNone(replay)
        with self.assertRaises(VerifyError): self.execute(self.prepared())

    def test_closed_and_mismatched_fd_refuse(self):
        e=copy.deepcopy(self.e);e['fd']=999999
        with self.assertRaises(VerifyError):custody.Handoff(e)
        other=self.root/'other';other.write_bytes(b'');fd=os.open(other,os.O_RDONLY)
        try:
            e['fd']=fd
            with self.assertRaises(VerifyError):custody.Handoff(e)
        finally:os.close(fd)
        self.no_spend()

    def test_changed_operation_source_intent_and_unlisted_fields(self):
        for field in ['operation_id','source_id']:
            e=copy.deepcopy(self.e);e['binding'][field]='3'*64
            with self.subTest(field=field),self.assertRaises(VerifyError):custody.Handoff(e)
        e=copy.deepcopy(self.e);e['binding']['ambient_fds']=[self.fd]
        with self.assertRaises(VerifyError):custody.Handoff(e)
        self.intent.write_bytes(b'{}')
        with self.assertRaises(VerifyError):custody.Handoff(self.e)
        self.no_spend()

    def test_changed_worker_after_preparation_refuses_before_consume(self):
        c=self.prepared();self.worker.write_text('raise SystemExit(0)')
        with self.assertRaises(VerifyError):self.execute(c)
        self.no_spend()

    def test_missing_custody_on_bound_authorization_refuses(self):
        with self.assertRaises(VerifyError):_run(self.case,self.sb,self.registry,*self.built)
        self.no_spend()

    def test_changed_signed_candidate_refuses(self):
        c=self.prepared();self.built[1]['action']['params']['run_custody_sha256']='0'*64
        with self.assertRaises(VerifyError):self.execute(c)
        self.no_spend()

    def test_two_prepared_dispatches_only_one_claim(self):
        first=self.prepared();second=self.prepared();first.claim('auth-one')
        with self.assertRaises(VerifyError):second.claim('auth-two')
        with self.assertRaises(VerifyError):self.execute(second)
        self.no_spend()

    def test_command_provider_refused_before_consume(self):
        self.case['rulebook_ref']='templates/pipeline-gate.yaml'
        self.built=_build(self.case,self.sb,self.registry)
        with self.assertRaises(VerifyError):self.execute(self.prepared())
        self.no_spend()

    def test_environment_collision_refused(self):
        c=self.prepared()
        with self.assertRaises(VerifyError):_run(self.case,self.sb,self.registry,*self.built,custody=c,environment={custody.ENV:'unbound'})
        self.no_spend()

    def test_terminal_write_failure_preserves_signed_receipt(self):
        c=self.prepared();original=os.open
        def fail(path,*a,**kw):
            if str(path).endswith('.terminal.json'):raise OSError('test-only unavailable terminal')
            return original(path,*a,**kw)
        with patch('vfy.custody.os.open',side_effect=fail):r=self.execute(c)
        self.assertEqual(r.exit_status,0);self.assertIsNotNone(r.receipt)
        self.assertFalse(pathlib.Path(str(self.intent)+'.terminal.json').exists())

    def test_cli_path_and_provider_preflight(self):
        import io
        from vfy import cli, workflow, resources
        for command_provider in (True, False):
            root=self.root/('provider-workspace' if command_provider else 'file-workspace')
            root.mkdir()
            ws=workflow.initialize(root,'pipeline-gate',resources.schema_dir(),resources.template_dir(),workflow.Identifiers())
            if not command_provider:
                rule=(pathlib.Path(__file__).parents[1]/'fixtures/custody/file-rulebook.yaml').read_bytes()
                (root/'rulebook.yaml').write_bytes(rule)
                (root/'ci').mkdir();(root/'ci/last-test-result.sh').write_bytes(b'"passed"')
            envelope=self.root/('provider-envelope.json' if command_provider else 'file-envelope.json')
            envelope.write_bytes(canon.canonical_bytes(self.e))
            out,err=io.StringIO(),io.StringIO()
            with patch('vfy.workflow.evidence.acquire_command',side_effect=AssertionError('provider must not run')):
                rc=cli.main(['--workspace',str(root),'--json','--execution-report','run','--custody-handoff',str(envelope),'--identity','branch=main','--',*self.argv],out=out,err=err)
            if command_provider:
                self.assertNotEqual(rc,0)
                self.assertEqual(json.loads(out.getvalue())['error'],'execution_configuration_invalid')
                self.assertFalse(list((root/'.vfy/consumed').iterdir()))
            else:
                self.assertEqual(rc,0,err.getvalue())
                result=json.loads(out.getvalue())
                self.assertEqual(result['execution_report']['nonce_consumption'],'consumed')
                self.assertFalse(result['execution_report']['automatic_retry_permitted'])

if __name__=='__main__':unittest.main()
