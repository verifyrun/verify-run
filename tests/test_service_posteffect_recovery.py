"""Disposable managed-copy effects; retained customer actions are never replayed."""
import json
import os
import select
import signal
import subprocess
import sys
import unittest
from tests import test_service_lifecycle as fixtures
from vfy import service_lifecycle as lifecycle, child_ledger as m

class PostEffectRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.f=fixtures.LifecycleTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
 def test_process_death_after_first_replace_retains_unknown_and_consumption(self):
  f=self.f
  ready=lifecycle.prepare(f.ledger(f.initial),f.payload)
  request=f.authorization_request(ready['plan'])
  child='''import json,sys,time
from vfy import service_lifecycle as l, service_adoption as a
p=json.loads(sys.stdin.readline())
def pause(stage):
 if stage=='after_replace':
  print('REPLACED',flush=True)
  time.sleep(60)
a._fault=pause
l.adopt(l.Ledger(p['profile'],p['digest'],p['head']),p['request'])
'''
  proc=subprocess.Popen([sys.executable,'-B','-c',child],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   proc.stdin.write(m.raw(dict(profile=str(f.path),digest=m.sha(f.path.read_bytes()),head=ready['head_sha256'],request=request))+b'\n');proc.stdin.flush()
   self.assertTrue(select.select([proc.stdout],[],[],15)[0])
   self.assertEqual(proc.stdout.readline(),b'REPLACED\n')
   self.assertIsNone(proc.poll());proc.kill();proc.wait(timeout=10)
   self.assertEqual(proc.returncode,-signal.SIGKILL)
   root=f.f.f.f.pool.root
   before=json.loads((root/'state.json').read_bytes())['body']
   self.assertEqual(before['phase'],'ADOPTING');self.assertIsNone(before['completion'])
   self.assertTrue(f.f.f.nonces.is_consumed('fresh-paid-nonce'))
   managed=__import__('pathlib').Path(before['managed_root'])
   changed=ready['plan']['changed_paths'][0]
   self.assertEqual((managed/'copy'/changed).read_bytes(),f.f.f.candidate[changed])
   recover='''import json,sys
from vfy import service_lifecycle as l
p=json.loads(sys.stdin.readline()); print(json.dumps(l.recover(l.Ledger(p['profile'],p['digest'],p['head']))))
'''
   reply=subprocess.run([sys.executable,'-B','-c',recover],input=m.raw(dict(profile=str(f.path),digest=m.sha(f.path.read_bytes()),head=f.current()))+b'\n',capture_output=True,timeout=15)
   self.assertEqual(reply.returncode,0,reply.stderr)
   result=json.loads(reply.stdout)
   self.assertEqual(result['state'],'ADOPTING');self.assertIsNone(result['completion'])
   self.assertFalse(result['automatic_retry']);self.assertFalse(result['authority_granted'])
   after=(root/'state.json').read_bytes();body=json.loads(after)['body']
   self.assertEqual(body['reserved'],before['reserved']);self.assertTrue(body['recovery_used'])
   with self.assertRaises(Exception): lifecycle.adopt(f.ledger(f.current()),request)
   with self.assertRaises(Exception): lifecycle.recover(f.ledger(f.current()))
   self.assertEqual(after,(root/'state.json').read_bytes())
   self.assertEqual((f.f.f.original/'app/a.py').read_bytes(),b'base a')
  finally:
   if proc.poll() is None:proc.kill()
   proc.wait(timeout=10)
   for stream in (proc.stdin,proc.stdout,proc.stderr):stream.close()
