"""Public synthetic snapshot workload for capacity tests, not retained private evidence.

The child really checks pinned bytes and returns failure on mismatch. Its selected
profile exists only inside each test; it is not an installed production profile.
"""
import json
import sys
import uuid
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from vfy import child_ledger as m, child_observer as obs

SNAPSHOT = b'{"fixture":"public-capacity-snapshot","value":7}\n'
CODE = '''import hashlib,json,pathlib,sys
p=json.load(sys.stdin)
for name,digest in p['pins'].items():
    if hashlib.sha256((pathlib.Path(p['root'])/name).read_bytes()).hexdigest()!=digest:
        raise SystemExit(1)
print(json.dumps({'state':'VERIFIED_SELECTED_SNAPSHOT_NOT_FRESHNESS'}))
'''


def install_profile(test, base):
    root = base / 'public-observer-profile'
    root.mkdir()
    executable = Path(sys.executable).absolute()
    runtime = {'path':str(executable), 'resolved_path':str(executable.resolve()),
               'sha256':m.sha(executable.resolve().read_bytes())}
    (root/'verifier-code.txt').write_text(CODE)
    (root/'verifier-pins.json').write_bytes(m.raw({'snapshot.json':m.sha(SNAPSHOT)}))
    (root/'runtime.json').write_bytes(m.raw(runtime))
    selected = patch.object(obs, 'FIXTURES', root)
    selected.start()
    test.addCleanup(selected.stop)


def setup(base, seed=bytes(range(32))):
    base = Path(base).resolve()
    base.mkdir()
    (base/'snapshot.json').write_bytes(SNAPSHOT)
    event = 'PUBLIC-TEST-' + uuid.uuid4().hex
    purpose = base/'purpose.txt'
    purpose.write_bytes(b'public synthetic capacity control')
    basis = {'path':str(purpose), 'sha256':m.sha(purpose.read_bytes())}
    start = {'state':'STARTED', 'automatic_retry':False, 'task_key':event,
             'task_identity':{'subject_sha256':basis['sha256'], 'task_id':event, 'repository':str(base)},
             'operation_id':event, 'attempt_id':event, 'input_artifacts':[basis],
             'native_child_population':{'state':'DECLARED_BEFORE_DISPATCH', 'expected_child_ids':['verifier-job']}}
    sb = m.raw(start)
    parent = base/'START.json'
    parent.write_bytes(sb)
    limits = {'captured_console_bytes':'786432', 'local_process_cpu_seconds':'30',
              'local_wall_observations_seconds':'90'}
    rows = [{'axis_id':name,'unit':unit,'aggregation':aggregation,'scope':scope,'limit':limits[name]}
            for name,(unit,aggregation,scope) in m.AXES.items()]
    budget = m.raw({'schema':'vfy.child-resource-budget/1','budget_id':event,
                   'task_key':event,'task_identity':start['task_identity'],
                   'parent_start_sha256':m.sha(sb),'resource_rows':rows})
    key = Ed25519PrivateKey.from_private_bytes(seed)  # Public fixture seed only.
    issuer = 'PUBLIC_LOCAL_DEVELOPMENT_ONLY'
    trust = {issuer:{'public_key_hex':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
                     'producer_identity':m.producer()}}
    ledger = m.Ledger.create(base/'ledger',sb,basis,budget,seed,issuer,trust)
    runtime = json.loads((obs.FIXTURES/'runtime.json').read_bytes())
    payload = m.raw({'root':str(base), 'pins':json.loads((obs.FIXTURES/'verifier-pins.json').read_bytes())})
    request = {'schema':'engineer.child-dispatch-request/1',
               'state':'INTENT_ONLY_RESERVATION_AND_DISPATCH_NOT_ESTABLISHED',
               'authority_granted':False,'automatic_retry':False,
               'task_key':event,'task_identity':start['task_identity'],
               'operation_id':event,'attempt_id':event,'child_id':'verifier-job',
               'parent_start':{'path':str(parent),'sha256':m.sha(sb)},
               'input_bytes':len(payload),'input_sha256':m.sha(payload),
               'argv':[runtime['path'],'-I','-B','-c',CODE], 'executable':runtime,
               'cwd':str(base),'environment':{}}
    request['identity_sha256'] = m.sha(json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode())
    return ledger,m.raw(request),payload
