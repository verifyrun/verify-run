"""Real CLI process interruption on fresh disposable authority, never retained effects."""
import base64
import json
import os
import select
import signal
import subprocess
import sys
import unittest
from tests import test_service_workflow as fixture_setup
from vfy import child_ledger as m, service_workflow as w


class WorkflowProcessRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_setup.WorkflowTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.command = ([os.environ['VFY_WORKFLOW_TEST_EXECUTABLE']]
            if 'VFY_WORKFLOW_TEST_EXECUTABLE' in os.environ else
            [sys.executable, '-B', '-c', 'from vfy.cli import main; raise SystemExit(main())'])
        self.root = self.f.old.f.f.f.pool.root
        self.sequence = 0

    def args(self, operation, head):
        return self.command + ['service-workflow', operation, '--profile', str(self.f.path),
            '--profile-sha256', m.sha(self.f.path.read_bytes()), '--expected-head', head]

    def current(self):
        raw = (self.root / 'state.json').read_bytes()
        return m.sha(raw), json.loads(raw)['body']

    def reply(self, proc):
        self.assertTrue(select.select([proc.stdout], [], [], 10)[0], 'bounded CLI response missing')
        return json.loads(proc.stdout.readline())

    def launch(self):
        proc = subprocess.Popen(self.args('session', self.f.old.initial), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, proc)
        opened = self.reply(proc)
        self.assertEqual(opened['state'], 'WORKFLOW_RESERVED')
        self.session_id = opened['session_id']
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()

    def send(self, proc, operation, inputs):
        self.sequence += 1
        frame = dict(schema='vfy.service-workflow-frame/1', session_id=self.session_id,
            sequence=self.sequence, operation=operation, inputs={k: dict(
                base64=base64.b64encode(v).decode(), sha256=m.sha(v)) for k, v in inputs.items()})
        proc.stdin.write(m.raw(frame) + b'\n'); proc.stdin.flush()
        return self.reply(proc)

    def check_recovery(self, proc, expected):
        self.assertIsNone(proc.poll(), "workflow exited before the interruption")
        proc.kill(); proc.wait(timeout=10)
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        head, before = self.current()
        self.assertEqual(before['phase'], expected)
        result = subprocess.run(self.args('recover', head), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response['state'], expected)
        self.assertFalse(response['construction_resumed'])
        self.assertFalse(response['automatic_retry'])
        self.assertFalse(response['authority_granted'])
        new_head, after = self.current()
        self.assertTrue(after['recovery_used'])
        self.assertEqual(before['reservation'], after['reservation'])
        self.assertEqual(before['completion'], after['completion'])
        for operation in ('recover', 'session', 'adopt'):
            retry = subprocess.run(self.args(operation, new_head), input=b'{}', capture_output=True, timeout=10)
            self.assertEqual(retry.returncode, 12, (operation, retry.stdout))
            self.assertEqual(self.current()[0], new_head)

    def test_kill_after_reservation_preserves_hold_and_refuses_resume(self):
        self.check_recovery(self.launch(), 'WORKFLOW_RESERVED')

    def exercise_admission(self, consume):
        from tests.test_service_attempt import ServiceTests
        proc = self.launch()
        f = self.f.old.f.f.o.f
        request, preview = ServiceTests.action(f, 'fresh-process-workflow')
        request['attempt_id'] = self.f.profile['attempt_id']
        acquisition = dict(used=dict.fromkeys(w.ACQUISITION, 0), root=request['attempt_root'],
            preview_sha256=m.sha(preview))
        self.assertEqual(self.send(proc, 'ACQUIRED', dict(acquisition=m.raw(acquisition)))['state'], 'OBSERVATION_PREPARED')
        self.assertEqual(self.send(proc, 'ADMIT', dict(request=m.raw(request), preview=preview,
            approval=f.approval(request, preview)))['state'], 'ADMITTED')
        if consume:
            self.assertEqual(self.send(proc, 'CONSUME', dict(start=f.start((request, preview))))['state'], 'CONSUMED')
        self.check_recovery(proc, 'OBSERVATION_CONSUMED' if consume else 'OBSERVATION_ADMITTED')

    def test_kill_after_admission_preserves_hold_and_refuses_resume(self):
        self.exercise_admission(False)

    def test_kill_after_consume_preserves_hold_and_refuses_resume(self):
        self.exercise_admission(True)
