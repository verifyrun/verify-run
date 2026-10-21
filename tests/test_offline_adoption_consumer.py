import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('offline',Path(__file__).parents[1]/'tools/verify_adoption_offline.py')
consumer=importlib.util.module_from_spec(spec);spec.loader.exec_module(consumer)
class ConsumerControls(unittest.TestCase):
 def setUp(self):
  self.policy=b'{"independent":"example selection, not real trust"}'
  self.pin=hashlib.sha256(self.policy).hexdigest()
  self.inputs={k:{'base64':'e30=','sha256':'0'*64} for k in ['plan','preparation','intent','completion']}
 def test_exact_separate_policy_is_selected(self):
  q=json.loads(consumer.request(json.dumps(self.inputs).encode(),self.policy,self.pin,'a'*64))
  self.assertEqual(q['inputs'],self.inputs);self.assertEqual(q['policy'],json.loads(self.policy))
 def test_wrong_policy_digest_and_uploaded_policy_refuse(self):
  with self.assertRaises(ValueError):consumer.request(json.dumps(self.inputs).encode(),self.policy,'0'*64,'a'*64)
  with self.assertRaises(ValueError):consumer.request(json.dumps(dict(self.inputs,policy={})).encode(),self.policy,self.pin,'a'*64)
 def test_bounds(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'input';p.write_bytes(b'12345')
   with self.assertRaises(ValueError):consumer.bounded(p,4)
  with self.assertRaises(ValueError):consumer.request(json.dumps(dict(self.inputs,intent='x'*consumer.history.MAX_BYTES)).encode(),self.policy,self.pin,'a'*64)
