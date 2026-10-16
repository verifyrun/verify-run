"""Keyless prelaunch selection check; never admits, consumes or executes."""
import json
import sys
from pathlib import Path
from vfy import child_ledger as m, service_tests as st

base,attempt=map(Path,sys.argv[1:])
c=json.loads((base/'CONSUMER_CONTEXT.json').read_bytes())
snapshot=(base/'SELECTED_HEAD.json').read_bytes()
pool=st.load_service_pool(snapshot_bytes=snapshot,expected_snapshot_sha256=m.sha(snapshot),
    expected_pool_root=c['pool_root'],expected_config_bytes=bytes.fromhex(c['config_hex']),
    owner_trust=c['owner_trust'],child_trust=c['child_trust'],selected_observer=c['observer'],
    predecessor_snapshot_bytes=bytes.fromhex(c['head_hex']),policy_bytes=bytes.fromhex(c['policy_hex']),
    expected_child_trusts={},minimum_revision=1)
raw=(attempt/'TEST_SELECTION.json').read_bytes()
checker=st.TestObservationChecker(pool,selection_bytes=raw,
    requirements_bytes=(base/'FROZEN_REQUIREMENTS.json').read_bytes(),
    runner_bytes=(attempt/'runner/verify_service_runner.py').read_bytes(),
    limits=dict(input_bytes=16777216,cases=4096,requirements=1024,retained_bytes=33554432))
p=json.loads((attempt/'PREVIEW.json').read_bytes());q=checker.selection
assert p['test_selection_sha256']==m.sha(raw)
assert p['test_runner_sha256']==q['runner_sha256']
for field in ('source','examiner','environment'):
    assert m.digest(p[field])==q[field+'_sha256']
for field in ('adapter_sha256','capture_sha256'):
    assert p[field]==q[field]==pool.policy[field]
assert p['labels']==q['labels']
assert not (attempt/'START.json').exists() and not (attempt/'ACCOUNTING.json').exists()
assert json.loads(snapshot)['body']['entries']==[]
try: pool.consume(None)
except m.Refused: pass
else: raise AssertionError('Read-only pool acquired live capability')
print(json.dumps(dict(state='PRELAUNCH_SELECTION_BOUND_NOT_EXECUTED',checker_identity=st.identity(),
    cases=len(q['case_ids']),requirements=len(checker.requirements),selection_sha256=m.sha(raw),
    scope='No completed observation or semantic acceptance; no admission or consumption'),sort_keys=True))
