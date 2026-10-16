"""Disposable authority; tests do not run retained customer attempts."""
import unittest
from unittest.mock import patch
from tests import test_service_lifecycle as prior
from vfy import service_workflow as w,child_ledger as m

class WorkflowTests(unittest.TestCase):
 def setUp(self):
  self.old=prior.LifecycleTests();self.old.setUp();self.addCleanup(self.old.doCleanups)
  p=self.old.profile
  self.profile={k:v for k,v in p.items() if k not in {'payload_sha256','checker'}}
  self.profile.update(schema=w.FORMAT,labels=['synthetic'],paths={k:str(self.old.f.f.original) for k in w.PATHS},
   acquisition_limits=dict(read_bytes=1000000,read_files=100,write_bytes=1000000,write_files=100),
   observation_limits=dict(wall_seconds=60,cpu_seconds=40,output_bytes=100,file_bytes=200,descriptors=128))
  self.path=self.old.path;self.path.write_bytes(m.raw(self.profile))
 def ledger(self,head=None):return w.Ledger(self.path,m.sha(self.path.read_bytes()),head or self.old.initial)
 def test_reserve_before_acquisition(self):
  with self.ledger().locked() as l:
   l.start();self.assertEqual(l.body['phase'],'WORKFLOW_RESERVED')
   self.assertEqual(l.body['acquisition_used']['read_bytes'],0)
 def test_stale_head(self):
  with self.assertRaises(Exception):
   with self.ledger('0'*64).locked() as l:l.start()
 def test_duplicate_reservation_refused(self):
  with self.ledger().locked() as l:l.start();head=m.sha(l.current)
  with self.assertRaises(Exception):
   with self.ledger(head).locked() as l:l.start()
 def action(self,l):
  from tests.test_service_attempt import ServiceTests
  f=self.old.f.f.o.f
  q,preview=ServiceTests.action(f,'fresh-workflow')
  q['attempt_id']=self.profile['attempt_id']
  l.acquired(dict.fromkeys(w.ACQUISITION,0),q['attempt_root'],m.sha(preview))
  return f,q,preview
 def test_nested_admission_keeps_outer_head(self):
  with self.ledger().locked() as l:
   l.start();f,q,preview=self.action(l);pool=w.NestedServicePool(l)
   t=pool.admit(request_bytes=m.raw(q),preview_bytes=preview,approval_bytes=f.approval(q,preview),recorded_at='TEST')
   outer=m.load.load_json_bytes((l.root/'state.json').read_bytes())
   self.assertEqual(outer['body']['schema'],w.FORMAT)
   self.assertEqual(l.body['phase'],'OBSERVATION_ADMITTED')
   self.assertNotEqual((l.root/'state.json').read_bytes(),m.raw(t))
 def test_crash_between_nested_sign_and_outer_publish(self):
  with self.ledger().locked() as l:
   l.start();f,q,preview=self.action(l);before=l.current;pool=w.NestedServicePool(l)
   with patch.object(w,'fault',side_effect=OSError('interrupted')):
    with self.assertRaises(OSError):pool.admit(request_bytes=m.raw(q),preview_bytes=preview,approval_bytes=f.approval(q,preview),recorded_at='TEST')
   self.assertEqual(before,(l.root/'state.json').read_bytes())
   self.assertFalse(pool._live)
 def test_insufficient_complete_hold(self):
  self.profile['acquisition_limits']['write_bytes']=8000000;self.path.write_bytes(m.raw(self.profile))
  with self.ledger().locked() as l:
   before=l.current
   with self.assertRaises(Exception):l.start()
   self.assertEqual(before,(l.root/'state.json').read_bytes())
