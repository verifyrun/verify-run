#!/usr/bin/env python3
"""Run-owner preparation only: NEW disposable service pool, no admission/execution.
No Engineer imports. Invoke with installed Run Python and independently selected
PREVIEW path/hash and a nonexistent destination. Never reuse a prior pool.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from vfy import child_ledger as m, common_capacity as common, service_attempt as service
from vfy.service_accounting_cli import selected_pool


def embedded(data):return dict(base64=base64.b64encode(data).decode(),sha256=m.sha(data))
def public(key):return dict(public_key_hex=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),producer_identity=m.producer())
def ref(path):return dict(path=str(path),sha256=m.sha(path.read_bytes()))


def main():
    preview_path,expected,destination=sys.argv[1:]
    preview_path=Path(preview_path);raw=m.read_file(preview_path)
    m.need(m.hex64(expected) and m.sha(raw)==expected)
    p=service.evidence(raw);attempt=preview_path.parent
    m.need(preview_path.name=='PREVIEW.json' and p['schema']=='engineer.service-observation/1'
        and p['root']==str(attempt) and attempt==attempt.resolve())
    service.resources(p['limits'],positive=True)
    m.need(not any(os.path.lexists(attempt/n) for n in ('START.json','ACCOUNTING.json')))
    root=Path(destination)
    m.need(root.is_absolute() and root==root.resolve() and not root.exists())
    root.mkdir(mode=0o700);m.sync_dir(root.parent)
    owner_seed=os.urandom(32);owner_key=Ed25519PrivateKey.from_private_bytes(owner_seed)
    child_key=Ed25519PrivateKey.generate();approval_key=Ed25519PrivateKey.generate()
    owner_trust={'DISPOSABLE_SERVICE_OWNER_71KBDB5S':public(owner_key)}
    child_trust={'DISPOSABLE_UNUSED_CHILD_71KBDB5S':public(child_key)}
    approval_trust={'DISPOSABLE_SERVICE_APPROVER_71KBDB5S':public(approval_key)}
    # Explicit empty predecessor: no measured-child acceptance or dispatch claimed.
    observer={'scope':'NO_CHILD_DISPATCH_SELECTED','service_identity':service.identity()}
    config=m.raw(dict(schema=common.PROFILE,pool_id='DISPOSABLE_SERVICE_71KBDB5S',
        owner_issuer=next(iter(owner_trust)),capacities=dict(dispatch_slots=1,
        retained_output_bytes=p['limits']['output_bytes']),scope='REVIEWED_LOCAL_VERIFIER_ONLY'))
    owner=common.CapacityOwner.create(root/'pool',config,owner_seed,next(iter(owner_trust)),owner_trust,
        child_trust=child_trust,selected_observer=observer)
    predecessor=owner.snapshot()
    policy=m.raw(dict(schema='vfy.service-policy/1',pool_root=str(owner.root),config_sha256=m.sha(config),
        predecessor_sha256=m.sha(predecessor),service_identity=service.identity(),approval_trust=approval_trust,
        adapter_sha256=p['adapter_sha256'],capture_sha256=p['capture_sha256'],
        resource_capacities=p['limits'],**service.FLAGS))
    pool=service.ServicePool.attach(owner,predecessor_snapshot_bytes=predecessor,policy_bytes=policy)
    snapshot=pool.snapshot()
    request=m.raw(dict(schema=service.PROFILE,attempt_id='SERVICE_71KBDB5S_ONCE',attempt_root=str(attempt),
        pool_root=str(owner.root),policy_sha256=m.sha(policy),preview_sha256=expected,resources=p['limits'],**service.FLAGS))
    approval=m.raw(m.envelope(pool._approval_body(request,expected),approval_key,next(iter(approval_trust))))
    seed_path=root/'owner.seed';m.fresh(seed_path,owner_seed);seed_path.chmod(0o600)
    profile=m.raw(dict(schema='vfy.service-accounting-profile/1',scope='DISPOSABLE_DEVELOPMENT_ONLY',
        inputs={k:embedded(v) for k,v in dict(snapshot=snapshot,config=config,predecessor=predecessor,
            policy=policy,managed_legacy=b'').items()},
        selection=dict(expected_snapshot_sha256=m.sha(snapshot),expected_pool_root=str(owner.root),
            owner_trust=owner_trust,child_trust=child_trust,selected_observer=observer,expected_child_trusts={},
            minimum_revision=1,selected_callback_identity=None,selected_managed_identity=None),
        key_file=str(seed_path),session_seconds=300,service_identity=service.identity()))
    items={'PROFILE.json':profile,'REQUEST.json':request,'APPROVAL.json':approval,'POLICY.json':policy,
        'CONFIG.json':config,'PREDECESSOR.json':predecessor,'SELECTED_HEAD.json':snapshot}
    for name,data in items.items():m.fresh(root/name,data)
    # Exact installed loading, authentication and correspondence only; no admit/consume.
    with selected_pool(root/'PROFILE.json',m.sha(profile)) as (loaded,seconds):
        m.need(seconds==300 and loaded.snapshot()==snapshot)
        m.need(m.authenticate(m.load.load_json_bytes(approval),loaded.policy['approval_trust'])==loaded._approval_body(request,expected))
        loaded._request(request);loaded._preview(m.load.load_json_bytes(request),raw)
        view=loaded.verify_snapshot(snapshot)
        m.need(view['used']==dict(dispatch_slots=0,retained_output_bytes=0))
    m.need(pool.snapshot()==snapshot and m.read_file(preview_path)==raw)
    m.need(not any(os.path.lexists(attempt/n) for n in ('START.json','ACCOUNTING.json')))
    result=dict(schema='vfy.disposable-service-session-prepared/1',state='PREPARED_NOT_ADMITTED',
        preview=ref(preview_path),files={name:ref(root/name) for name in items},
        resources=p['limits'],session_seconds=300,usage=view['used'],
        owner_trust=owner_trust,approval_trust=approval_trust,run_service_identity=service.identity(),
        executable=str(Path(sys.executable).parent/'vfy'),
        scope='EXPLICIT_NEW_DISPOSABLE_ACCOUNTING_ONLY_NOT_EFFECT_OR_PRODUCTION_AUTHORITY',
        excluded_from_backup=['owner.seed','live pool'],**service.FLAGS)
    m.fresh(root/'PREPARED.json',m.raw(result)+b'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
