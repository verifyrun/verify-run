"""Fresh disposable accounting only; no service execution or retained C7 access."""
import base64
import json
import os
import select
import subprocess
import sys
import unittest
from pathlib import Path
from vfy import child_ledger as m, service_attempt as service, service_accounting_cli as cli
from tests.test_service_attempt import ServiceTests


def embedded(raw):
    return {'base64': base64.b64encode(raw).decode(), 'sha256': m.sha(raw)}


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.f = ServiceTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)
        self.profile = self.make_profile()
        self.proc = None

    def make_profile(self):
        f = self.f
        seed = f.base / 'owner.seed'
        seed.write_bytes(bytes(range(32,64)))
        seed.chmod(0o600)
        snapshot = f.pool.snapshot()
        return dict(schema='vfy.service-accounting-profile/1', scope='DISPOSABLE_DEVELOPMENT_ONLY',
            inputs={k:embedded(v) for k,v in dict(snapshot=snapshot, config=f.old.config_bytes,
                predecessor=f.head, policy=f.kw['policy_bytes'], managed_legacy=b'').items()},
            selection=dict(expected_snapshot_sha256=m.sha(snapshot), expected_pool_root=str(f.old.root),
                owner_trust=f.old.trust, child_trust=f.old.child_trust, selected_observer=f.old.observer,
                expected_child_trusts={}, minimum_revision=1, selected_callback_identity=None,
                selected_managed_identity=None), key_file=str(seed), session_seconds=5,
            service_identity=service.identity())

    def launch(self, profile=None):
        path=self.f.base/('profile-'+os.urandom(4).hex()+'.json')
        raw=m.raw(profile or self.profile);path.write_bytes(raw)
        # Installed checks select the actual console; source tests exercise public -m entry.
        command=([os.environ['VFY_SESSION_TEST_EXECUTABLE']] if 'VFY_SESSION_TEST_EXECUTABLE' in os.environ
                 else [sys.executable,'-B','-c','from vfy.cli import main; raise SystemExit(main())'])
        proc=subprocess.Popen(command+['service-accounting-session','--profile',str(path),
            '--profile-sha256',m.sha(raw)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.addCleanup(self.stop,proc)
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:proc.kill()
        proc.wait(timeout=5)
        for stream in (proc.stdin,proc.stdout,proc.stderr):stream.close()

    def reply(self,proc):
        self.assertTrue(select.select([proc.stdout],[],[],7)[0], 'no bounded reply')
        raw=proc.stdout.readline(cli.MAX_OUTPUT+1)
        self.assertLessEqual(len(raw),cli.MAX_OUTPUT)
        self.assertTrue(raw.endswith(b'\n'),raw)
        reply=json.loads(raw)
        self.assertIs(reply['authority_granted'],False)
        self.assertIs(reply['automatic_retry'],False)
        return reply

    def begin(self):
        self.proc=self.launch();self.open=self.reply(self.proc)
        self.assertEqual(self.open['state'],'OPEN')
        self.sequence=0

    def send(self,op,inputs,**change):
        self.sequence+=1
        q=dict(schema='vfy.service-accounting-frame/1',session_id=self.open['session_id'],
            sequence=self.sequence,operation=op,inputs={k:embedded(v) for k,v in inputs.items()})
        q.update(change);raw=m.raw(q)+b'\n'
        self.proc.stdin.write(raw);self.proc.stdin.flush()
        r=self.reply(self.proc)
        if r['state']!='REFUSED':
            self.assertEqual(r['request_sha256'],m.sha(raw));self.assertEqual(r['sequence'],self.sequence)
        return r

    def admit(self):
        self.a=self.f.action()
        q,p=self.a
        return self.send('ADMIT',dict(request=m.raw(q),preview=p,approval=self.f.approval(q,p)))

    def test_actual_process_complete_and_reopen_refuses(self):
        self.begin();self.assertEqual(self.admit()['state'],'ADMITTED')
        r=self.send('CONSUME',dict(start=self.f.start(self.a)))
        self.assertEqual(r['state'],'CONSUMED')
        result=self.f.result(self.a);result.pop('recorded_at')
        r=self.send('SETTLE',{k.removesuffix('_bytes'):v for k,v in result.items()})
        self.assertEqual(r['state'],'SETTLED')
        self.assertEqual(r['record']['body']['entries'][0]['state'],'OBSERVED_EXIT_ZERO')
        self.assertEqual(self.proc.wait(timeout=5),0)
        self.assertEqual(self.reply(self.launch())['state'],'REFUSED')
        self.assertEqual(self.f.pool.verify_snapshot(self.f.pool.snapshot())['used']['dispatch_slots'],1)

    def test_wrong_start_burns_capability(self):
        self.begin();self.admit();self.f.start(self.a)
        self.assertEqual(self.send('CONSUME',dict(start=b'{}'))['state'],'REFUSED')
        self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'][0]['state'],'UNKNOWN')

    def test_wrong_session_or_sequence_never_admits(self):
        for change in ({'session_id':'0'*64},{'sequence':2},{'schema':'future/2'}):
            self.begin()
            self.assertEqual(self.send('ADMIT',{},**change)['state'],'REFUSED')
            self.proc.wait(timeout=5)
            self.assertEqual(self.f.state()['entries'],[])

    def test_concurrent_existing_lock_refuses_second_session(self):
        self.begin()
        other=self.launch()
        self.assertEqual(self.reply(other)['state'],'REFUSED')
        self.assertEqual(other.wait(timeout=5),12)
        self.assertEqual(self.admit()['state'],'ADMITTED')
        self.assertEqual(self.send('UNKNOWN',{})['state'],'UNKNOWN_HOLD_RETAINED')

    def test_kill_after_admit_no_restored_capability(self):
        self.begin();self.admit();self.proc.kill();self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'][0]['state'],'ADMITTED')
        self.assertEqual(self.reply(self.launch())['state'],'REFUSED')
        # Even an owner-selected updated head does not admit or consume an old attempt.
        fresh=self.make_profile();self.profile=fresh
        self.begin()
        self.assertEqual(self.send('CONSUME',dict(start=b'{}'))['state'],'REFUSED')
        self.proc.wait(timeout=5)
        self.assertEqual(self.f.pool.verify_snapshot(self.f.pool.snapshot())['used']['dispatch_slots'],1)

    def test_kill_after_consume_retains_hold(self):
        self.begin();self.admit();self.send('CONSUME',dict(start=self.f.start(self.a)))
        self.proc.kill();self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'][0]['state'],'CONSUMED')
        self.assertEqual(self.reply(self.launch())['state'],'REFUSED')

    def test_eof_marks_unknown_and_keeps_all_resources(self):
        self.begin();self.admit();self.proc.stdin.close()
        self.assertEqual(self.reply(self.proc)['state'],'REFUSED')
        self.proc.wait(timeout=5)
        view=self.f.pool.verify_snapshot(self.f.pool.snapshot())
        self.assertEqual(view['service_used'],self.a[0]['resources'])
        self.assertEqual(self.f.state()['entries'][0]['state'],'UNKNOWN')

    def test_changed_preview_refuses(self):
        self.begin();self.admit();start=self.f.start(self.a)
        (Path(self.a[0]['attempt_root'])/'PREVIEW.json').write_bytes(b'{}')
        self.assertEqual(self.send('CONSUME',dict(start=start))['state'],'REFUSED')
        self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'][0]['state'],'UNKNOWN')

    def test_tampered_result_refuses_and_unknown(self):
        self.begin();self.admit();self.send('CONSUME',dict(start=self.f.start(self.a)))
        data=self.f.result(self.a);data.pop('recorded_at');data['stdout_bytes']=b'forged'
        self.assertEqual(self.send('SETTLE',{k.removesuffix('_bytes'):v for k,v in data.items()})['state'],'REFUSED')
        self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'][0]['state'],'UNKNOWN')

    def test_bad_key_and_identity_refuse_without_writes(self):
        before=self.f.pool.snapshot()
        Path(self.profile['key_file']).chmod(0o644)
        self.assertEqual(self.reply(self.launch())['state'],'REFUSED')
        Path(self.profile['key_file']).chmod(0o600)
        wrong=dict(self.profile,service_identity={})
        self.assertEqual(self.reply(self.launch(wrong))['state'],'REFUSED')
        self.assertEqual(self.f.pool.snapshot(),before)

    def test_shared_exhaustion_never_creates_replacement_pool(self):
        for i in range(3):self.f.admit(self.f.action('held'+str(i)))
        self.profile=self.make_profile();self.begin()
        self.assertEqual(self.admit()['state'],'REFUSED')
        self.proc.wait(timeout=5)
        self.assertEqual(len(self.f.state()['entries']),3)

    def test_timeout_retains_admitted_hold(self):
        self.profile['session_seconds']=1
        self.begin();self.admit()
        self.assertIn(self.proc.wait(timeout=4),(1,12))
        self.assertEqual(self.f.state()['entries'][0]['state'],'UNKNOWN')

    def test_wrong_approval_no_admission(self):
        self.begin();a=self.f.action();q,p=a
        bad=json.loads(self.f.approval(q,p));bad['signature']='0'*128
        r=self.send('ADMIT',dict(request=m.raw(q),preview=p,approval=m.raw(bad)))
        self.assertEqual(r['state'],'REFUSED');self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'],[])

    def test_lost_consume_ack_never_refunds(self):
        self.begin();self.admit();start=self.f.start(self.a)
        self.proc.stdout.close()  # No reader for the consumption acknowledgement.
        q=dict(schema='vfy.service-accounting-frame/1',session_id=self.open['session_id'],
            sequence=2,operation='CONSUME',inputs={'start':embedded(start)})
        self.proc.stdin.write(m.raw(q)+b'\n');self.proc.stdin.flush()
        self.assertEqual(self.proc.wait(timeout=5),1)
        entry=self.f.state()['entries'][0]
        self.assertEqual(entry['start_sha256'],m.sha(start))
        self.assertEqual(entry['state'],'UNKNOWN')
        self.assertEqual(self.reply(self.launch())['state'],'REFUSED')

    def test_duplicate_consumption_refused(self):
        self.begin();self.admit();start=self.f.start(self.a)
        self.send('CONSUME',dict(start=start))
        self.assertEqual(self.send('CONSUME',dict(start=start))['state'],'REFUSED')
        self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'][0]['state'],'UNKNOWN')

    def test_changed_head_refuses_before_keyed_mutation(self):
        self.f.admit(self.f.action('outside'))
        before=self.f.pool.snapshot()
        self.assertEqual(self.reply(self.launch())['state'],'REFUSED')
        self.assertEqual(self.f.pool.snapshot(),before)

    def test_managed_predecessor_usage_preserved(self):
        from tests.test_managed_capacity import fixture
        from vfy import managed_capacity as managed
        root=self.f.base/'managed';root.mkdir()
        old,owner,grant,kw=fixture(root)
        owner.apply_grant(m.raw(grant),recorded_at='SYNTHETIC')
        self.f.bind(owner)
        self.profile=self.make_profile()
        self.profile['inputs']['managed_legacy']=embedded(owner.legacy_bytes)
        self.profile['selection'].update(expected_child_trusts=kw['expected_child_trusts'],
            selected_callback_identity=owner.callback,selected_managed_identity=managed.identity())
        self.begin();self.admit();r=self.send('UNKNOWN',{})
        self.assertEqual(r['state'],'UNKNOWN_HOLD_RETAINED')
        self.proc.wait(timeout=5)
        self.assertEqual(self.f.pool.verify_snapshot(self.f.pool.snapshot())['used'],
            {'dispatch_slots':2,'retained_output_bytes':262244,'managed_receipt_bytes':0})

    def test_oversized_frame_refused_before_admission(self):
        self.begin()
        raw=b'x'*(cli.MAX_STDIN+1)
        try:self.proc.stdin.write(raw);self.proc.stdin.flush()
        except BrokenPipeError:pass
        self.assertEqual(self.reply(self.proc)['state'],'REFUSED')
        self.proc.wait(timeout=5)
        self.assertEqual(self.f.state()['entries'],[])


if __name__=='__main__':unittest.main()
