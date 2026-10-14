"""The public child fixture must execute a real byte check, including refusal."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tests.child_observer_fixture import CODE, SNAPSHOT

class PublicChildFixtureTests(unittest.TestCase):
    def test_real_child_checks_snapshot_and_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'snapshot.json'
            path.write_bytes(SNAPSHOT)
            payload = json.dumps({'root': root, 'pins': {'snapshot.json': hashlib.sha256(SNAPSHOT).hexdigest()}})
            def run():
                return subprocess.run([sys.executable, '-I', '-B', '-c', CODE], input=payload, text=True, capture_output=True, timeout=10)
            good = run()
            self.assertEqual(good.returncode, 0)
            self.assertEqual(json.loads(good.stdout)['state'], 'VERIFIED_SELECTED_SNAPSHOT_NOT_FRESHNESS')
            path.write_bytes(SNAPSHOT + b'changed')
            bad = run()
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, '')
