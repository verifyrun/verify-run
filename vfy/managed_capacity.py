"""Opt-in additive pool epoch for a trusted fixed local JSON receipt writer.

Not an executor, authority, sandbox, freshness oracle or hostile-owner defense.
Caller holds Engineer's managed-state lock through prepare/write/COMPLETE/settle.
Existing byte-identical common_capacity and child_ledger authenticate legacy data.
"""
import json
import os
from pathlib import Path
from vfy import child_ledger as m, common_capacity as legacy

PROFILE = 'vfy.managed-capacity/1'
EFFECT = 'managed-json-receipt/1'
HOLD = 4096
FLAGS = {'authority_granted': False, 'automatic_retry': False}


def identity():
    return {'profile': PROFILE, 'source_sha256': m.sha(Path(__file__).read_bytes())}


def engineer_json(data):
    """Opaque Engineer evidence: strict JSON, int64 metadata, never signed as Run values."""
    m.need(type(data) is bytes and len(data) <= m.MAX_BYTES)
    text = m.load._decode_utf8(data)
    m.load._reject_excess_depth(text)
    return json.loads(text, object_pairs_hook=m.load._object_from_pairs,
                      parse_int=m._start_integer, parse_float=m.load._reject_float,
                      parse_constant=m.load._reject_non_json_constant)


def sealed(data):
    value = engineer_json(data)
    unsigned = {k: v for k, v in value.items() if k != 'identity_sha256'}
    encoded = json.dumps(unsigned, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    m.need(value.get('identity_sha256') == m.sha(encoded), 'Engineer evidence identity mismatch.')
    return value


def path(value):
    m.need(m.text(value))
    p = Path(value)
    m.need(p.is_absolute() and p == p.resolve(), 'Noncanonical or symlink path.')
    return p


def ref(value):
    m.need(type(value) is dict and set(value) == {'path', 'sha256'} and m.hex64(value['sha256']))
    return m.read_file(path(value['path']))


def checked_ref(value):
    data = ref(value)
    m.need(m.sha(data) == value['sha256'], 'Selected file changed.')
    return data


class ManagedCapacityOwner(legacy.CapacityOwner):
    def __init__(self, root, owner_seed, owner_issuer, owner_trust, *, expected_config_bytes,
                 child_trust, selected_observer, legacy_snapshot_bytes, expected_child_trusts,
                 selected_callback_identity):
        super().__init__(root, owner_seed, owner_issuer, owner_trust,
                         expected_config_bytes=expected_config_bytes, child_trust=child_trust,
                         selected_observer=selected_observer)
        self.legacy_bytes = legacy_snapshot_bytes
        self.legacy_record = m.load.load_json_bytes(legacy_snapshot_bytes)
        self.legacy_trusts = expected_child_trusts
        self.legacy_view = legacy.verify_capacity_snapshot(
            legacy_snapshot_bytes, owner_trust, expected_config_bytes, expected_pool_root=str(self.root),
            expected_child_trusts=expected_child_trusts, selected_observer=selected_observer)
        m.need(type(selected_callback_identity) is dict and set(selected_callback_identity) ==
               {'id', 'code_sha256', 'adapter_source_sha256', 'python'})
        m.need(selected_callback_identity['id'] == EFFECT and
               all(m.hex64(selected_callback_identity[k]) for k in ('code_sha256', 'adapter_source_sha256')) and
               m.text(selected_callback_identity['python']))
        self.callback = selected_callback_identity
        self._live = {}

    def _validate_record(self, record):
        b = m.authenticate(record, self.trust)
        m.need(record['issuer_identity'] == self.issuer)
        m.need(set(b) == {'schema','pool_root','config_sha256','owner_profile','legacy_raw_hex',
                         'callback_identity','revision','previous','grants','managed_entries', *FLAGS})
        m.need(b['schema'] == PROFILE and b['owner_profile'] == identity() and
               b['pool_root'] == str(self.root) and b['config_sha256'] == m.sha(self.config_bytes) and
               b['callback_identity'] == self.callback and b['automatic_retry'] is False)
        m.need(b['legacy_raw_hex'] == self.legacy_bytes.hex(), 'Legacy prefix must remain byte-exact.')
        legacy.verify_capacity_snapshot(self.legacy_bytes, self.trust, self.config_bytes,
            expected_pool_root=str(self.root), expected_child_trusts=self.legacy_trusts,
            selected_observer=self.observer)
        seen = set()
        for g in b['grants']:
            self._grant_shape(g['request'])
            m.need(g['request']['grant_id'] not in seen); seen.add(g['request']['grant_id'])
            m.need(m.text(g['recorded_at']))
        m.need(len(b['grants']) == 1, 'This bounded epoch accepts exactly one head-bound additive grant.')
        head = b['grants'][0]['request']['expected_head']
        m.need(head == {'raw_sha256': m.sha(self.legacy_bytes), 'envelope_sha256': self.legacy_record['sha256'],
                        'revision': self.legacy_view['revision']})
        events = 1
        seen = set(); claims = {k:set() for k in ('capture_identity','managed_attempt','destination')}
        for e in b['managed_entries']:
            m.need(set(e) == {'key','binding','recorded_at','consumption','settlement','retained_bytes'})
            q = e['binding']; self._binding_shape(q)
            m.need(legacy.integer(e['retained_bytes']))
            m.need(e['key'] == self._effect_key(q) and e['key'] not in seen); seen.add(e['key'])
            for field, values in claims.items():
                m.need(q[field] not in values, 'Duplicate capture or attempt destination.'); values.add(q[field])
            m.need(m.text(e['recorded_at']))
            events += 1
            if e['consumption'] is not None:
                m.need(e['consumption'] == {'receipt_sha256': q['receipt_sha256']}); events += 1
            s = e['settlement']
            if s is None:
                m.need(e['retained_bytes'] == HOLD)
            else:
                m.need(set(s) == {'state','recorded_at','reason','callback_sha256','complete_sha256'})
                m.need(m.text(s['recorded_at']))
                if s['state'] == 'KNOWN_LOCAL_MANAGED_RECEIPT':
                    m.need(e['consumption'] is not None and s['reason'] is None and
                           s['callback_sha256'] == q['receipt_sha256'] and s['complete_sha256'] == q['complete_sha256'] and
                           e['retained_bytes'] == q['receipt_bytes'])
                else:
                    m.need(s['state'] == 'UNKNOWN_HOLD_RETAINED' and m.text(s['reason']) and
                           s['callback_sha256'] is None and s['complete_sha256'] is None and e['retained_bytes'] == HOLD)
                events += 1
        m.need(type(b['revision']) is int and b['revision'] == self.legacy_view['revision'] + events)
        m.need(m.hex64(b['previous']))
        used = self.usage(b); capacities = self.capacities(b)
        m.need(all(legacy.integer(v) and v <= capacities[k] for k,v in used.items()))
        return record

    def usage(self, b):
        old = self.legacy_view['used']
        return {'dispatch_slots': old['dispatch_slots'] + len(b['managed_entries']),
                'retained_output_bytes': old['retained_output_bytes'],
                'managed_receipt_bytes': sum(e['retained_bytes'] for e in b['managed_entries'])}

    def capacities(self, b):
        base = dict(self.config['capacities'], managed_receipt_bytes=0)
        for g in b['grants']:
            for k,v in g['request']['additions'].items():
                base[k] += v
                m.need(legacy.integer(base[k]), 'Capacity overflow.')
        return base

    def _grant_shape(self, q):
        m.need(set(q) == {'schema','grant_id','pool_root','config_sha256','owner_issuer','expected_head',
                         'additions','profile_extension','retained_byte_dimension','scope',*FLAGS})
        m.need(q['schema'] == 'vfy.local-capacity-grant-request/1' and m.text(q['grant_id']) and
               q['pool_root'] == str(self.root) and q['config_sha256'] == m.sha(self.config_bytes) and q['owner_issuer'] == self.issuer)
        m.need(q['additions'] == {'dispatch_slots': 3, 'managed_receipt_bytes': 12288} and
               all(type(v) is int for v in q['additions'].values()))
        m.need(q['profile_extension'] == EFFECT and q['retained_byte_dimension'] == 'managed_receipt_bytes' and
               q['scope'] == 'EXPLICIT_NONFINANCIAL_LOCAL_DEVELOPMENT_GRANT_NOT_ACTION_AUTHORITY' and
               all(q[k] is False for k in FLAGS))

    def apply_grant(self, grant_request_bytes, *, recorded_at):
        q = m.load.load_json_bytes(grant_request_bytes); self._grant_shape(q); m.need(m.text(recorded_at))
        with self.locked():
            current = m.read_file(self.root/'state.json')
            m.need(current == self.legacy_bytes, 'Grant head changed or already used; read state, never retry.')
            m.need(q['expected_head'] == {'raw_sha256': m.sha(current), 'envelope_sha256': self.legacy_record['sha256'],
                                         'revision': self.legacy_view['revision']})
            b = dict(schema=PROFILE, pool_root=str(self.root), config_sha256=m.sha(self.config_bytes),
                     owner_profile=identity(), legacy_raw_hex=current.hex(), callback_identity=self.callback,
                     revision=self.legacy_view['revision']+1, previous=self.legacy_record['sha256'],
                     grants=[{'request': q, 'recorded_at': recorded_at}], managed_entries=[], **FLAGS)
            return self._publish(b)

    def _publish(self, b):
        record = m.envelope(b, self.key, self.issuer); self._validate_record(record)
        data = m.raw(record); m.need(len(data) <= m.MAX_BYTES)
        m.fresh(self.root/'pending.json', data)
        os.replace(self.root/'pending.json', self.root/'state.json'); m.sync_dir(self.root)
        return record

    def _change(self, fn):
        with self.locked():
            old = self._load(); b = old['body']; result = fn(b)
            b['revision'] += 1; b['previous'] = old['sha256']; record = self._publish(b)
            return result, record

    def _binding_shape(self, q):
        m.need(set(q) == {'task_key','task_identity','operation_id','attempt_id','parent_start','basis','child_id',
                         'capture','capture_identity','managed_state','managed_attempt','destination','callback_identity',
                         'receipt_sha256','receipt_bytes','complete_sha256','complete_bytes','source_refs',
                         'binding_ref','binding_basis','recorded_request_sha256'})
        m.need(set(q['task_identity']) == {'repository','subject_sha256','task_id'} and
               all(m.text(v) for v in q['task_identity'].values()) and m.hex64(q['task_identity']['subject_sha256']))
        m.need(q['child_id'] == 'managed-json-callback' and q['callback_identity'] == self.callback)
        m.need(all(m.hex64(q[k]) for k in ('task_key','capture_identity','receipt_sha256','complete_sha256','recorded_request_sha256')))
        m.need(type(q['receipt_bytes']) is int and 0 < q['receipt_bytes'] <= HOLD and
               type(q['complete_bytes']) is int and 0 < q['complete_bytes'] <= m.MAX_BYTES)
        state = path(q['managed_state']); attempt = path(q['managed_attempt'])
        m.need(attempt.parent == state and path(q['destination']) == attempt/'CALLBACK.json' and
               path(q['capture']['path']) == attempt/'CAPTURE.json')

    @staticmethod
    def _effect_key(q):
        # Deliberately excludes parent operation/attempt/raw START: new CLI cannot resend capture.
        return m.digest({'managed_state': q['managed_state'], 'managed_attempt': q['managed_attempt'],
                         'capture_identity': q['capture_identity'], 'destination': q['destination'], 'profile': EFFECT})

    def _check_files(self, q):
        checked_ref(q['parent_start']); checked_ref(q['basis']); checked_ref(q['capture'])
        checked_ref(q['binding_ref']); checked_ref(q['binding_basis'])
        for r in q['source_refs']: checked_ref(r)
        path(q['destination']); path(q['managed_attempt'])

    def inspect_managed_request(self, request_bytes, parent_start_bytes, capture_bytes,
                                expected_receipt_bytes, expected_complete_bytes):
        """Read-only exact correspondence; does not authenticate actual CLI origin or admit."""
        q = m.load.load_json_bytes(request_bytes)
        m.need(q.pop('schema', None) == 'vfy.managed-dispatch-request/1' and
               q.pop('authority_granted', None) is False and q.pop('automatic_retry', None) is False)
        q['recorded_request_sha256'] = m.sha(request_bytes); self._binding_shape(q)
        self._check_files(q)
        m.need(m.read_file(path(q['parent_start']['path'])) == parent_start_bytes and m.sha(parent_start_bytes) == q['parent_start']['sha256'])
        p = m.parent_binding(parent_start_bytes, q['basis'])
        m.need(p['task_key'] == q['task_key'] and p['task_identity'] == q['task_identity'] and
               p['parent_binding']['operation_id'] == q['operation_id'] and
               p['parent_binding']['attempt_id'] == q['attempt_id'] and q['child_id'] in p['expected_child_ids'])
        m.need(m.sha(capture_bytes) == q['capture']['sha256'])
        c = sealed(capture_bytes); r = sealed(expected_receipt_bytes); done = sealed(expected_complete_bytes)
        m.need('installed_runtime' not in c and 'installed_runtime' not in done, 'This epoch selects source-mode callback only.')
        m.need(c['kind'] == 'CAPTURE' and c['identity_sha256'] == q['capture_identity'] and c['callback'] == self.callback and
               c['common_capacity_binding'] == q['binding_ref'] and c['repository'] == q['task_identity']['repository'] and
               c['contract']['task_id'] == q['task_identity']['task_id'])
        m.need(c['snapshot']['observation']['task'] ==
               {'inspection_sha256':q['basis']['sha256'], 'task_id':q['task_identity']['task_id'],
                'task_subject_identity_sha256':q['task_identity']['subject_sha256']})
        m.need(q['basis'] == c['refs']['inspection'])
        m.need(len(q['source_refs']) == len(c['refs'])+1 and
               all(r in q['source_refs'] for r in c['refs'].values()) and
               sum(r['sha256'] == self.callback['adapter_source_sha256'] for r in q['source_refs']) == 1)
        binding = m.load.load_json_bytes(checked_ref(q['binding_ref']))
        m.need(binding['pool_root'] == str(self.root) and binding['config']['sha256'] == m.sha(self.config_bytes) and
               binding['owner'] == {'owner_issuer':self.issuer, 'public_key_hex':self.trust[self.issuer]['public_key_hex']} and
               binding['state_root'] == q['managed_state'] and binding['schema'] == 'engineer.managed-task-capacity-binding/1' and
               binding['effect_profile'] == EFFECT and all(binding[k] is False for k in FLAGS) and
               binding['task'] == {'inspection_sha256':q['binding_basis']['sha256'], 'task_id':q['task_identity']['task_id'],
                                   'task_subject_identity_sha256':q['task_identity']['subject_sha256']})
        m.need(checked_ref(binding['config']) == self.config_bytes)
        # Original immutable state anchor and current inspection are distinct evidence.
        # Both must describe exactly the same task/subject/repository; the current one
        # remains independently bound by actual parent START and capture observation.
        for basis_ref in (q['binding_basis'], q['basis']):
            inspection = engineer_json(checked_ref(basis_ref))
            subject = inspection['task_source_binding']
            m.need(inspection['repository'] == q['task_identity']['repository'] and
                   type(subject['task_id']) is str and subject['task_id'] == q['task_identity']['task_id'] and
                   type(subject['task_subject_identity_sha256']) is str and
                   subject['task_subject_identity_sha256'] == q['task_identity']['subject_sha256'])
        m.need(r['schema'] == c['schema'] == done['schema'] == 'engineer.managed-local-execution/1')
        m.need(r['kind'] == 'LOCAL_CALLBACK_RECEIPT' and r['capture_id'] == q['capture_identity'] and
               r['callback_id'] == EFFECT and r['destination_label'] == c['contract']['destination'] and json.dumps(r['payload'],sort_keys=True,separators=(',',':')) == json.dumps(c['snapshot']['payload'],sort_keys=True,separators=(',',':')))
        m.need(done['kind'] == 'COMPLETE' and done['capture_id'] == q['capture_identity'] and done['callback'] == self.callback and
               done['receipt_sha256'] == r['identity_sha256'] and done['observed_guard_result'] is True and
               type(done['callback_calls']) is int and done['callback_calls'] == 1 and
               m.raw(done['observed_guard_arguments']) == m.raw([c['snapshot']['values'][k] for k in c['criterion']['parameters']]) and
               done['local_effect'] == 'MANAGED_JSON_RECEIPT_ONLY' and done['external_effects'] == 'UNKNOWN')
        m.need(set(r) == {'schema','kind','capture_id','callback_id','destination_label','payload','identity_sha256'})
        m.need(set(done) == {'schema','kind','capture_id','callback','receipt_sha256','observed_guard_arguments',
                             'observed_guard_result','callback_calls','local_effect','external_effects','identity_sha256'})
        for prefix, data in (('receipt', expected_receipt_bytes), ('complete', expected_complete_bytes)):
            m.need(m.sha(data) == q[prefix+'_sha256'] and len(data) == q[prefix+'_bytes'])
        for name in ('START.json','CALLBACK.json','COMPLETE.json'):
            m.need(not os.path.lexists(path(q['managed_attempt'])/name), 'Managed attempt already started or has evidence; no resend.')
        return q

    def prepare_managed(self, request_bytes, parent_start_bytes, capture_bytes,
                        expected_receipt_bytes, expected_complete_bytes, *, recorded_at):
        m.need(m.text(recorded_at))
        q = self.inspect_managed_request(request_bytes, parent_start_bytes, capture_bytes, expected_receipt_bytes, expected_complete_bytes)
        key = self._effect_key(q)
        def change(b):
            m.need(not any(any(e['binding'][field] == q[field] for field in ('capture_identity','managed_attempt','destination'))
                           for e in b['managed_entries']), 'Capture or attempt already held/consumed; no resend.')
            u = self.usage(b); limits = self.capacities(b)
            m.need(u['dispatch_slots']+1 <= limits['dispatch_slots'] and u['managed_receipt_bytes']+HOLD <= limits['managed_receipt_bytes'], 'Capacity exhausted.')
            b['managed_entries'].append(dict(key=key, binding=q, recorded_at=recorded_at, consumption=None, settlement=None, retained_bytes=HOLD))
        self._change(change)
        token = object(); self._live[key] = token
        return ManagedGuard(self, key, token)

    def guard(self, key):
        # Recovery handle cannot create an entry, reset consumption or retry an UNKNOWN.
        with self.locked(): self._entry(self._load()['body'], key)
        return ManagedGuard(self, key)

    @staticmethod
    def _entry(b, key):
        found = [e for e in b['managed_entries'] if e['key'] == key]
        m.need(len(found) == 1); return found[0]

    # Legacy mutation APIs deliberately unavailable after additive epoch.
    def reserve(self, *a, **k): raise m.Refused('Use selected managed epoch protocol.')
    def bind_dispatch(self, *a, **k): raise m.Refused('Legacy entries are immutable in managed epoch.')
    def settle(self, *a, **k): raise m.Refused('Legacy entries are immutable in managed epoch.')


class ManagedGuard:
    def __init__(self, owner, key, token=None):
        self.owner, self.key, self._token = owner, key, token

    def before_callback(self, *, capture_bytes, callback_identity, destination, receipt_bytes):
        m.need(self._token is not None and self.owner._live.get(self.key) is self._token,
               'Recovery handle cannot dispatch; retain UNKNOWN.')
        # A failed attempted consumption cannot become a fresh attempt with altered inputs.
        self.owner._live.pop(self.key)
        def change(b):
            e = self.owner._entry(b, self.key); q = e['binding']
            m.need(e['consumption'] is None and e['settlement'] is None, 'Already consumed/UNKNOWN; no retry.')
            self.owner._check_files(q)
            start = sealed(m.read_file(path(q['managed_attempt'])/'START.json'))
            m.need(start == {'schema':'engineer.managed-local-execution/1', 'kind':'START',
                             'capture_id':q['capture_identity'], 'identity_sha256':start['identity_sha256']})
            m.need(m.sha(capture_bytes) == q['capture']['sha256'] and callback_identity == q['callback_identity'] and
                   destination == q['destination'] and m.sha(receipt_bytes) == q['receipt_sha256'] and len(receipt_bytes) == q['receipt_bytes'])
            m.need(not os.path.lexists(path(destination)), 'Receipt destination exists; no overwrite.')
            e['consumption'] = {'receipt_sha256': q['receipt_sha256']}
        return self.owner._change(change)[1]

    def settle(self, *, callback_bytes, complete_bytes, recorded_at):
        m.need(m.text(recorded_at))
        def change(b):
            e = self.owner._entry(b, self.key); q = e['binding']
            m.need(e['consumption'] is not None and e['settlement'] is None, 'No one-use consumption or already settled.')
            m.need(m.sha(callback_bytes) == q['receipt_sha256'] and len(callback_bytes) == q['receipt_bytes'] and
                   m.sha(complete_bytes) == q['complete_sha256'] and len(complete_bytes) == q['complete_bytes'])
            m.need(m.read_file(path(q['destination'])) == callback_bytes and
                   m.read_file(path(q['managed_attempt'])/'COMPLETE.json') == complete_bytes)
            e['retained_bytes'] = len(callback_bytes)
            e['settlement'] = dict(state='KNOWN_LOCAL_MANAGED_RECEIPT', recorded_at=recorded_at, reason=None,
                                   callback_sha256=m.sha(callback_bytes), complete_sha256=m.sha(complete_bytes))
        return self.owner._change(change)[1]

    def mark_unknown(self, *, reason, recorded_at):
        m.need(m.text(reason) and m.text(recorded_at))
        def change(b):
            e = self.owner._entry(b, self.key); m.need(e['settlement'] is None)
            e['settlement'] = dict(state='UNKNOWN_HOLD_RETAINED', recorded_at=recorded_at, reason=reason,
                                   callback_sha256=None, complete_sha256=None)
        return self.owner._change(change)[1]


def verify_managed_snapshot(snapshot_bytes, owner_trust, expected_config_bytes, *, expected_pool_root,
                            legacy_snapshot_bytes, expected_child_trusts, selected_observer,
                            selected_callback_identity, selected_managed_identity, minimum_revision=0):
    """Public selected-byte correspondence, never freshness, effects or admission authority."""
    m.need(selected_managed_identity == identity())
    view = object.__new__(ManagedCapacityOwner)
    view.root = path(expected_pool_root); view.trust = owner_trust
    view.config_bytes = expected_config_bytes; view.config = m.load.load_json_bytes(expected_config_bytes)
    view.issuer = view.config['owner_issuer']; view.observer = selected_observer
    view.legacy_bytes = legacy_snapshot_bytes; view.legacy_record = m.load.load_json_bytes(legacy_snapshot_bytes)
    view.legacy_trusts = expected_child_trusts; view.callback = selected_callback_identity
    view.legacy_view = legacy.verify_capacity_snapshot(legacy_snapshot_bytes, owner_trust, expected_config_bytes,
        expected_pool_root=expected_pool_root, expected_child_trusts=expected_child_trusts, selected_observer=selected_observer)
    record = view._validate_record(m.load.load_json_bytes(snapshot_bytes)); b = record['body']
    m.need(legacy.integer(minimum_revision) and b['revision'] >= minimum_revision)
    return dict(state='VERIFIED_SELECTED_MANAGED_CAPACITY_NOT_FRESHNESS', revision=b['revision'],
                used=view.usage(b), capacities=view.capacities(b), legacy_raw_sha256=m.sha(legacy_snapshot_bytes),
                full_lifecycle_accounting='UNKNOWN', **FLAGS)
