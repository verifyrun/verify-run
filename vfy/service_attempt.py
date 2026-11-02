"""Selected shared-pool service accounting. No executor or action authority.

See docs/SERVICE_ATTEMPT_CONTRACT.md for trust, enforcement and recovery bounds.
Old allocators are retained byte-exact and frozen at a validated predecessor head.
"""
import json
import math
import os
import threading
from pathlib import Path

from vfy import child_ledger as m, common_capacity as common, managed_capacity as managed

PROFILE = 'vfy.service-attempt/1'
RESOURCES = ('wall_seconds', 'cpu_seconds', 'output_bytes', 'file_bytes', 'descriptors')
FLAGS = {'authority_granted': False, 'automatic_retry': False}
STATES = {'ADMITTED', 'CONSUMED', 'UNKNOWN', 'OBSERVED_EXIT_ZERO',
          'OBSERVED_EXIT_NONZERO', 'OBSERVED_SIGNAL'}


def identity():
    return {'profile': PROFILE, 'source_sha256': m.sha(Path(__file__).read_bytes())}


def evidence(data):
    """Bounded opaque Engineer JSON, allowing finite wall measurements, no duplicates."""
    m.need(type(data) is bytes and len(data) <= m.MAX_BYTES)
    text = m.load._decode_utf8(data)
    m.load._reject_excess_depth(text)
    def finite(token):
        value = float(token)
        m.need(math.isfinite(value), 'Nonfinite evidence number.')
        return value
    value = json.loads(text, object_pairs_hook=m.load._object_from_pairs,
        parse_int=m._start_integer, parse_float=finite,
        parse_constant=m.load._reject_non_json_constant)
    m.need(type(value) is dict)
    return value


def resources(value, *, positive=False):
    m.need(type(value) is dict and set(value) == set(RESOURCES))
    m.need(all(common.integer(v) and (not positive or v > 0) for v in value.values()))


class ServicePool:
    def __init__(self, predecessor, *, predecessor_snapshot_bytes, policy_bytes):
        m.need(type(predecessor) in (common.CapacityOwner, managed.ManagedCapacityOwner),
               'Select a supported existing shared owner, not a replacement store.')
        self.owner = predecessor
        self.root = predecessor.root
        self.head = predecessor_snapshot_bytes
        self.prior = predecessor._validate_record(m.load.load_json_bytes(self.head))
        self.base_used = predecessor.usage(self.prior['body'])
        self.caps = (predecessor.capacities(self.prior['body'])
                     if type(predecessor) is managed.ManagedCapacityOwner
                     else dict(predecessor.config['capacities']))
        self.policy_bytes = policy_bytes
        self.policy = m.load.load_json_bytes(policy_bytes)
        p = self.policy
        m.need(set(p) == {'schema','pool_root','config_sha256','predecessor_sha256',
            'service_identity','approval_trust','adapter_sha256','capture_sha256',
            'resource_capacities',*FLAGS})
        m.need(p['schema'] == 'vfy.service-policy/1' and p['pool_root'] == str(self.root)
            and p['config_sha256'] == m.sha(predecessor.config_bytes)
            and p['predecessor_sha256'] == m.sha(self.head) and p['service_identity'] == identity()
            and all(p[k] is False for k in FLAGS))
        resources(p['resource_capacities'])
        m.need(all(m.hex64(p[k]) for k in ('adapter_sha256','capture_sha256')))
        trust = p['approval_trust']
        excluded = {v['public_key_hex'] for v in predecessor.trust.values()}
        excluded.update(v['public_key_hex'] for v in predecessor.child_trust.values())
        m.need(type(trust) is dict and bool(trust))
        for issuer, entry in trust.items():
            m.need(m.text(issuer) and type(entry) is dict and
                set(entry) == {'public_key_hex','producer_identity'} and
                m.hex64(entry['public_key_hex']) and entry['public_key_hex'] not in excluded and
                entry['producer_identity'] == m.producer(), 'Select independent approval trust.')
        self._live = set()
        self._cap_lock = threading.Lock()

    @classmethod
    def attach(cls, predecessor, *, predecessor_snapshot_bytes, policy_bytes):
        o = cls(predecessor, predecessor_snapshot_bytes=predecessor_snapshot_bytes, policy_bytes=policy_bytes)
        with predecessor.locked():
            m.need(m.read_file(o.root/'state.json') == o.head,
                   'Selected shared head changed; no reset, reattach or implicit grant.')
            b = dict(schema=PROFILE, pool_root=str(o.root), policy_sha256=m.sha(policy_bytes),
                service_identity=identity(), predecessor_raw_hex=o.head.hex(), entries=[],
                revision=o.prior['body']['revision']+1, previous=o.prior['sha256'], **FLAGS)
            o._publish(b)
        return o

    def _approval_body(self, qbytes, preview_sha):
        return dict(schema='vfy.service-approval/1',request_sha256=m.sha(qbytes),
            preview_sha256=preview_sha,policy_sha256=m.sha(self.policy_bytes),**FLAGS)

    def _request(self, data):
        q = m.load.load_json_bytes(data)
        m.need(set(q) == {'schema','attempt_id','attempt_root','pool_root','policy_sha256',
            'preview_sha256','resources',*FLAGS})
        m.need(q['schema'] == PROFILE and m.text(q['attempt_id']) and q['pool_root'] == str(self.root)
            and q['policy_sha256'] == m.sha(self.policy_bytes) and m.hex64(q['preview_sha256'])
            and all(q[k] is False for k in FLAGS))
        # Shape validation is filesystem-independent; live checks below reject aliases.
        m.need(m.text(q['attempt_root']) and Path(q['attempt_root']).is_absolute())
        resources(q['resources'],positive=True)
        return q

    def _preview(self, q, raw):
        p = evidence(raw)
        m.need(m.sha(raw) == q['preview_sha256'] and p.get('schema') == 'engineer.service-observation/1'
            and p.get('root') == q['attempt_root'] and p.get('limits') == q['resources']
            and p.get('adapter_sha256') == self.policy['adapter_sha256']
            and p.get('capture_sha256') == self.policy['capture_sha256'])
        m.need(all(k in p for k in ('source','examiner','environment','labels','policy','scope')))
        root = managed.path(q['attempt_root'])
        m.need(root.is_dir() and m.read_file(root/'PREVIEW.json') == raw, 'PREVIEW changed.')
        return root

    def _totals(self, b):
        used = dict(self.base_used)
        service = dict.fromkeys(RESOURCES,0)
        for e in b['entries']:
            q = self._request(bytes.fromhex(e['request_raw_hex']))
            used['dispatch_slots'] += 1
            used['retained_output_bytes'] += q['resources']['output_bytes']
            for k in RESOURCES: service[k] += q['resources'][k]
        m.need(all(common.integer(v) and v <= self.caps[k] for k,v in used.items()),
               'Existing shared capacity exhausted; no dispatch.')
        m.need(all(common.integer(v) and v <= self.policy['resource_capacities'][k]
                   for k,v in service.items()), 'Selected service resource capacity exhausted.')
        return used, service

    def _validate(self, record):
        b = m.authenticate(record, self.owner.trust)
        m.need(record['issuer_identity'] == self.owner.issuer)
        m.need(set(b) == {'schema','pool_root','policy_sha256','service_identity',
            'predecessor_raw_hex','entries','revision','previous',*FLAGS})
        m.need(b['schema'] == PROFILE and b['pool_root'] == str(self.root)
            and b['policy_sha256'] == m.sha(self.policy_bytes) and b['service_identity'] == identity()
            and b['predecessor_raw_hex'] == self.head.hex() and all(b[k] is False for k in FLAGS)
            and common.integer(b['revision']) and m.hex64(b['previous']))
        seen = {k:set() for k in ('attempt_id','attempt_root','preview_sha256')}
        events = 1
        m.need(type(b['entries']) is list)
        for e in b['entries']:
            m.need(set(e) == {'request_raw_hex','request_sha256','approval_raw_hex','approval_sha256',
                'recorded_at','consumed_at','start_sha256','state','unknown','result'})
            raw = bytes.fromhex(e['request_raw_hex']); q = self._request(raw)
            m.need(e['request_sha256'] == m.sha(raw) and m.text(e['recorded_at']) and e['state'] in STATES)
            for k in seen:
                m.need(q[k] not in seen[k], 'Attempt, root or PREVIEW already charged; no replay.')
                seen[k].add(q[k])
            approval = bytes.fromhex(e['approval_raw_hex'])
            m.need(e['approval_sha256'] == m.sha(approval))
            m.need(m.authenticate(m.load.load_json_bytes(approval),self.policy['approval_trust']) ==
                self._approval_body(raw,q['preview_sha256']))
            events += 1
            if e['start_sha256'] is not None:
                m.need(m.hex64(e['start_sha256']) and m.text(e['consumed_at'])); events += 1
            else: m.need(e['consumed_at'] is None)
            if e['unknown'] is not None:
                m.need(set(e['unknown']) == {'reason','recorded_at'} and
                    all(m.text(v) for v in e['unknown'].values())); events += 1
            if e['result'] is not None:
                r = e['result']; events += 1
                m.need(e['start_sha256'] is not None and set(r) == {'result_sha256','stdout_sha256',
                    'stderr_sha256','stdout_bytes','stderr_bytes','exit','classification','recorded_at'})
                m.need(all(m.hex64(r[k]) for k in ('result_sha256','stdout_sha256','stderr_sha256'))
                    and all(common.integer(r[k]) for k in ('stdout_bytes','stderr_bytes'))
                    and r['stdout_bytes']+r['stderr_bytes'] <= q['resources']['output_bytes']
                    and (r['exit'] is None or type(r['exit']) is int and abs(r['exit']) <= m.canon.MAX_SAFE_INTEGER)
                    and r['classification'] in STATES-{'ADMITTED','CONSUMED'} and m.text(r['recorded_at']))
                if r['classification'] != 'UNKNOWN':
                    code = r['exit']
                    m.need(code is not None and r['classification'] ==
                        ('OBSERVED_EXIT_ZERO' if code == 0 else 'OBSERVED_EXIT_NONZERO' if code > 0 else 'OBSERVED_SIGNAL'))
            expected = ('UNKNOWN' if e['unknown'] is not None else e['result']['classification']
                if e['result'] is not None else 'CONSUMED' if e['start_sha256'] is not None else 'ADMITTED')
            m.need(e['state'] == expected)
        m.need(b['revision'] == self.prior['body']['revision'] + events)
        self._totals(b)
        return record

    def _publish(self, b):
        record = m.envelope(b,self.owner.key,self.owner.issuer)
        self._validate(record)
        data = m.raw(record); m.need(len(data) <= m.MAX_BYTES)
        m.fresh(self.root/'pending.json',data)
        os.replace(self.root/'pending.json',self.root/'state.json'); m.sync_dir(self.root)
        return record

    def _change(self, fn):
        with self.owner.locked():
            old = self._validate(m.load.load_json_bytes(m.read_file(self.root/'state.json')))
            b = old['body']; fn(b)
            b['revision'] += 1; b['previous'] = old['sha256']
            return self._publish(b)

    def snapshot(self):
        with self.owner.locked():
            data = m.read_file(self.root/'state.json')
            self.verify_snapshot(data)
            return data

    def verify_snapshot(self, data):
        b = self._validate(m.load.load_json_bytes(data))['body']
        used, service = self._totals(b)
        return dict(state='VERIFIED_SELECTED_SERVICE_ACCOUNTING_NOT_FRESHNESS',revision=b['revision'],
            used=used,capacities=self.caps,service_used=service,
            service_capacities=self.policy['resource_capacities'],full_lifecycle='UNKNOWN',**FLAGS)

    def admit(self, *, request_bytes, preview_bytes, approval_bytes, recorded_at):
        m.need(m.text(recorded_at))
        q = self._request(request_bytes)
        approval = m.load.load_json_bytes(approval_bytes)
        m.need(m.authenticate(approval,self.policy['approval_trust']) ==
               self._approval_body(request_bytes,q['preview_sha256']))
        key = m.sha(request_bytes)
        def change(b):
            root = self._preview(q,preview_bytes)
            m.need(not os.path.lexists(root/'START.json'), 'START already exists; never re-admit.')
            b['entries'].append(dict(request_raw_hex=request_bytes.hex(),request_sha256=key,
                approval_raw_hex=approval_bytes.hex(),approval_sha256=m.sha(approval_bytes),
                recorded_at=recorded_at,consumed_at=None,start_sha256=None,state='ADMITTED',unknown=None,result=None))
        with self._cap_lock:
            ticket = self._change(change)
            self._live.add(key)
        return ticket

    def _key(self, ticket):
        b = self._validate(ticket)['body']
        m.need(bool(b['entries']) and b['entries'][-1]['state'] == 'ADMITTED', 'Expected admission ticket.')
        return b['entries'][-1]['request_sha256']

    @staticmethod
    def _entry(b, key):
        entries = [e for e in b['entries'] if e['request_sha256'] == key]
        m.need(len(entries) == 1)
        return entries[0]

    def consume(self, ticket, *, request_bytes, preview_bytes, start_bytes, recorded_at):
        key = self._key(ticket)
        with self._cap_lock:
            m.need(key in self._live, 'No live admission capability; UNKNOWN, no launch or replay.')
            self._live.remove(key)
            try:
                def change(b):
                    e = self._entry(b,key)
                    m.need(e['state'] == 'ADMITTED' and m.text(recorded_at) and
                        request_bytes.hex() == e['request_raw_hex'])
                    q = self._request(request_bytes); root = self._preview(q,preview_bytes)
                    m.need(evidence(start_bytes) == {'preview':q['preview_sha256']} and
                        m.read_file(root/'START.json') == start_bytes, 'Exact durable caller START required.')
                    e.update(start_sha256=m.sha(start_bytes),consumed_at=recorded_at,state='CONSUMED')
                return self._change(change)
            except Exception:
                # Even failed correspondence burns this live capability. Storage ambiguity
                # stays blocked by pending.json; never replace the original failure.
                try: self.mark_unknown(ticket,reason='consume failed; no launch',recorded_at='CONSUME_FAILURE')
                except Exception: pass
                raise

    def mark_unknown(self, ticket, *, reason, recorded_at):
        key = self._key(ticket)
        m.need(m.text(reason) and m.text(recorded_at))
        def change(b):
            e = self._entry(b,key)
            m.need(e['result'] is None and e['unknown'] is None)
            e.update(unknown=dict(reason=reason,recorded_at=recorded_at),state='UNKNOWN')
        return self._change(change)

    def settle(self, ticket, *, result_bytes, stdout_bytes, stderr_bytes, recorded_at):
        key = self._key(ticket)
        m.need(m.text(recorded_at))
        def change(b):
            e = self._entry(b,key)
            m.need(e['start_sha256'] is not None and e['result'] is None)
            q = self._request(bytes.fromhex(e['request_raw_hex'])); root = managed.path(q['attempt_root'])
            m.need(m.sha(m.read_file(root/'START.json')) == e['start_sha256'] and
                m.sha(m.read_file(root/'PREVIEW.json')) == q['preview_sha256'])
            r = evidence(result_bytes)
            m.need(r.get('preview') == q['preview_sha256'] and m.read_file(root/'RESULT.json') == result_bytes)
            for name, data in (('stdout',stdout_bytes),('stderr',stderr_bytes)):
                m.need(type(data) is bytes and len(data) <= m.MAX_BYTES and
                    r.get(name+'_sha256') == m.sha(data) and m.read_file(root/(name+'.bin')) == data)
            m.need(len(stdout_bytes)+len(stderr_bytes) <= q['resources']['output_bytes'])
            code = r.get('exit')
            m.need(code is None or type(code) is int and abs(code) <= m.canon.MAX_SAFE_INTEGER)
            classification = 'UNKNOWN'
            if r.get('state') == 'PROCESS_OBSERVED' and r.get('limit_failure') is None and code is not None:
                classification = 'OBSERVED_EXIT_ZERO' if code == 0 else 'OBSERVED_EXIT_NONZERO' if code > 0 else 'OBSERVED_SIGNAL'
            e['result'] = dict(result_sha256=m.sha(result_bytes),stdout_sha256=m.sha(stdout_bytes),
                stderr_sha256=m.sha(stderr_bytes),stdout_bytes=len(stdout_bytes),stderr_bytes=len(stderr_bytes),
                exit=code,classification=classification,recorded_at=recorded_at)
            e['state'] = 'UNKNOWN' if e['unknown'] is not None else classification
        return self._change(change)
