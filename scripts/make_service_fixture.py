#!/usr/bin/env python3
"""Fresh SYNTHETIC no-launch signed fixture; never select an existing/live pool.

python -I make_service_fixture.py INSTALLED_ROOT NEW_OUTPUT_ROOT
Requires installed cryptography. Fixed keys are public TEST keys, not authority.
No adapter/executor runs; consumed accounting is deliberately closed UNKNOWN.
"""
import json
from pathlib import Path
import sys

installed, output = map(Path, sys.argv[1:])
installed = installed.resolve(strict=True)
output = output.absolute()
if output != output.resolve() or output.exists():
    raise SystemExit('Require a new canonical SYNTHETIC output root')
sys.path.insert(0,str(installed))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from vfy import child_ledger as m, common_capacity as common, service_attempt as service

assert Path(service.__file__).resolve().is_relative_to(installed)
output.mkdir(mode=0o700)
def trust(seed, name):
    key=Ed25519PrivateKey.from_private_bytes(seed)
    return key,{name:{'public_key_hex':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),
                      'producer_identity':m.producer()}}
seed=bytes(range(32,64));_,owner_trust=trust(seed,'SYNTHETIC_OWNER')
_,child_trust=trust(bytes(range(32)),'SYNTHETIC_CHILD')
approver,approval_trust=trust(bytes(range(64,96)),'SYNTHETIC_APPROVER')
config=m.raw(dict(schema=common.PROFILE,pool_id='FRESH_SYNTHETIC_NO_LAUNCH',owner_issuer='SYNTHETIC_OWNER',
    capacities=dict(dispatch_slots=1,retained_output_bytes=100),scope='REVIEWED_LOCAL_VERIFIER_ONLY'))
owner=common.CapacityOwner.create(output/'pool',config,seed,'SYNTHETIC_OWNER',owner_trust,
    child_trust=child_trust,selected_observer={'profile':'SYNTHETIC_NO_OBSERVER_CLAIM'})
head=owner.snapshot()
limits=dict(wall_seconds=1,cpu_seconds=1,output_bytes=100,file_bytes=100,descriptors=10)
policy=m.raw(dict(schema='vfy.service-policy/1',pool_root=str(owner.root),config_sha256=m.sha(config),
    predecessor_sha256=m.sha(head),service_identity=service.identity(),approval_trust=approval_trust,
    adapter_sha256=m.sha(b'SYNTHETIC_NO_ADAPTER'),capture_sha256=m.sha(b'SYNTHETIC_NO_CAPTURE'),
    resource_capacities=limits,**service.FLAGS))
pool=service.ServicePool.attach(owner,predecessor_snapshot_bytes=head,policy_bytes=policy)
attempt=output/'attempt';attempt.mkdir()
preview=m.raw(dict(schema='engineer.service-observation/1',root=str(attempt),limits=limits,
    adapter_sha256=m.sha(b'SYNTHETIC_NO_ADAPTER'),capture_sha256=m.sha(b'SYNTHETIC_NO_CAPTURE'),
    source={},examiner={},environment={},labels=['SYNTHETIC_NO_LAUNCH'],policy='NO_EXECUTION',scope='SYNTHETIC'))
m.fresh(attempt/'PREVIEW.json',preview)
request=m.raw(dict(schema=service.PROFILE,attempt_id='SYNTHETIC_NO_LAUNCH',attempt_root=str(attempt),
    pool_root=str(owner.root),policy_sha256=m.sha(policy),preview_sha256=m.sha(preview),resources=limits,**service.FLAGS))
approval=m.raw(m.envelope(dict(schema='vfy.service-approval/1',request_sha256=m.sha(request),
    preview_sha256=m.sha(preview),policy_sha256=m.sha(policy),**service.FLAGS),approver,'SYNTHETIC_APPROVER'))
ticket=pool.admit(request_bytes=request,preview_bytes=preview,approval_bytes=approval,recorded_at='SYNTHETIC')
start=m.raw({'preview':m.sha(preview)});m.fresh(attempt/'START.json',start)
consumed=pool.consume(ticket,request_bytes=request,preview_bytes=preview,start_bytes=start,recorded_at='SYNTHETIC')
unknown=pool.mark_unknown(ticket,reason='Deliberate synthetic no-launch fixture; no executor invoked',recorded_at='SYNTHETIC')
artifacts={'CONFIG.json':config,'PREDECESSOR.json':head,'POLICY.json':policy,'REQUEST.json':request,
    'APPROVAL.json':approval,'ADMISSION.json':m.raw(ticket),'CONSUMPTION.json':m.raw(consumed),
    'UNKNOWN.json':m.raw(unknown),'VIEW.json':m.raw(pool.verify_snapshot(pool.snapshot())),
    'SELECTED_TRUST.json':m.raw({'owner':owner_trust,'child':child_trust,'approval':approval_trust})}
for name,data in artifacts.items():m.fresh(output/name,data)
print(json.dumps({'root':str(output),'state':'SYNTHETIC_NO_LAUNCH_UNKNOWN','service_identity':service.identity(),
    'artifacts':{name:m.sha(data) for name,data in artifacts.items()}},sort_keys=True))
