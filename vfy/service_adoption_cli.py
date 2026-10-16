"""Bounded, explicit development adoption transport; existing Run semantics only.

No action signer, pool provisioning, replacement evaluator or automatic retry.
The independently selected profile supplies current action trust and predecessor.
"""
from datetime import datetime, timezone
from pathlib import Path
from vfy import authorization, canon, gate, resources, rulebook, schema, snapshot, store
from vfy import child_ledger as m, service_adoption as adoption
from vfy.service_accounting_cli import bounded_file, selected_pool
from vfy.service_read_cli import MAX_STDIN


def adopt_selected(request_raw, expected_request, profile_path, expected_profile):
    m.need(len(request_raw) <= MAX_STDIN and m.hex64(expected_request)
           and m.sha(request_raw) == expected_request)
    raw = bounded_file(profile_path, MAX_STDIN)
    m.need(m.hex64(expected_profile) and m.sha(raw) == expected_profile)
    profile = m.load.load_json_bytes(raw)
    m.need(type(profile) is dict and set(profile) == {'schema', 'scope',
        'service_profile', 'service_profile_sha256', 'adoption_policy', 'action_key'})
    m.need(profile['schema'] == 'vfy.service-adoption-entry-profile/1'
           and profile['scope'] == 'DISPOSABLE_DEVELOPMENT_ONLY')
    request = m.load.load_json_bytes(request_raw)
    m.need(type(request) is dict and set(request) == {'schema', 'root', 'plan',
        'rulebook', 'snapshot', 'result', 'authorization'})
    m.need(request['schema'] == 'vfy.service-adoption-entry-request/1')
    registry = schema.build_registry([m.load.load_json_bytes(p.read_bytes())
        for p in sorted(resources.schema_dir().glob('*.schema.json'))])
    pinned = rulebook.load_rulebook_bytes(m.raw(request['rulebook']), registry)
    frozen = snapshot.verify_snapshot_value(request['snapshot'], pinned, registry)
    action = adoption.action_for(request['plan'])
    result = gate.evaluate(pinned, action, frozen.value(), registry)
    m.need(result.value() == request['result'], 'Selected result differs from Run evaluation.')
    key = profile['action_key']
    m.need(type(key) is dict and set(key) == {'key_id', 'key_version', 'public_key_hex', 'status'})
    keys = authorization.build_key_registry([dict(key_id=key['key_id'],
        key_version=key['key_version'], public_key=bytes.fromhex(key['public_key_hex']),
        status=key['status'])])
    policy = profile['adoption_policy']
    m.need(policy['action_key'] == {k: key[k] for k in ('key_id', 'key_version', 'public_key_hex')})
    nonce_root = Path(policy['authorization_store_root'])
    m.need(nonce_root.is_absolute() and nonce_root == nonce_root.resolve()
           and nonce_root.is_dir() and not nonce_root.is_symlink())
    nonces = store.LocalStore(nonce_root)
    now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    auth = request['authorization']
    consumed = {auth['nonce']} if nonces.is_consumed(auth['nonce']) else set()
    authorization.verify_authorization(auth, pinned, action, frozen, result,
        policy['runtime_id'], now, keys, registry, consumed_nonces=consumed)
    # Existing selector retains the one allocator lock and refuses stale heads.
    with selected_pool(profile['service_profile'], profile['service_profile_sha256']) as (service, _):
        head = service.snapshot()
        pool = adoption.AdoptionPool.attach(service, expected_snapshot_bytes=head,
            policy_bytes=m.raw(policy))
        ticket = pool.reserve(request['plan'], recorded_at=now)
        receipt = adoption.adopt(request['root'], request['plan'], pool=pool,
            ticket=ticket, pinned=pinned, snapshot=frozen, result=result,
            authorization=auth, runtime_id=policy['runtime_id'],
            verification_time=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            authorization_keys=keys, registry=registry, authorization_store=nonces)
    return {'schema': 'vfy.service-adoption-entry-response/1',
        'request_sha256': expected_request, 'profile_sha256': expected_profile,
        'receipt': receipt, 'automatic_retry': False,
        'service_execution': False, 'semantic_acceptance': 'UNESTABLISHED'}
