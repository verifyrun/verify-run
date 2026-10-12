"""Local child-budget producer. No launcher, payment, provider, or action permission.

Privileged local API: callers supply actual producer observations, never estimates.
The protected ledger owns holds; an observer/adapter still owns measurement truth.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
from fractions import Fraction
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from vfy import __version__, canon, load

SCHEMA = 'engineer.resource-child-ledger/2'
DOMAIN = b'verify-run.child-ledger.v1\0'
MAX_BYTES = 4 * 1024 * 1024
AXES = {
    'local_process_cpu_seconds': ('second', 'SUM', 'DIRECT_CHILD_PROCESS_CPU'),
    'local_wall_observations_seconds': ('second', 'SUM', 'CHILD_INTERVAL_SUM_NOT_PARENT_ELAPSED'),
    'captured_console_bytes': ('byte', 'SUM', 'DIRECT_CHILD_CAPTURED_OUTPUT'),
}
UNKNOWN_DIMENSIONS = ['provider', 'host', 'storage', 'memory', 'overlap', 'financial', 'undeclared_axes']

class Refused(ValueError):
    pass

def need(v, message='Child ledger input or correspondence refused; retain UNKNOWN.'):
    if not v:
        raise Refused(message)

def raw(v):
    return canon.canonical_bytes(v)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def digest(v):
    return sha(raw(v))

def text(v):
    return type(v) is str and 0 < len(v) <= 4096

def hex64(v):
    return type(v) is str and re.fullmatch('[0-9a-f]{64}', v) is not None

def amount(v):
    need(type(v) is str and len(v) <= 64 and re.fullmatch(r'(0|[1-9][0-9]*)(/[1-9][0-9]*)?', v))
    q = Fraction(v)
    need(str(q) == v)
    return q

def axes(rows, field):
    need(type(rows) is list and 0 < len(rows) <= len(AXES))
    result = {}
    for r in rows:
        need(type(r) is dict and set(r) == ({'axis_id','unit','aggregation','scope',field,'measured_amount'} if field == 'settled_amount_or_UNKNOWN' else {'axis_id','unit','aggregation','scope',field}))
        name = r['axis_id']
        need(name in AXES and name not in result)
        need((r['unit'], r['aggregation'], r['scope']) == AXES[name])
        result[name] = None if r[field] == 'UNKNOWN' else amount(r[field])
    return result

def producer():
    return {'component':'verify-run', 'version':__version__,
            'source_sha256':sha(Path(__file__).read_bytes()), 'source_identity_scope':'child_ledger.py'}

def envelope(body, key, issuer):
    message = {'issuer_identity':issuer,'producer_identity':producer(),'body':body}
    signature = key.sign(DOMAIN + raw(message)).hex()
    record = dict(message, signature=signature)
    return dict(record, sha256=digest(record))

def authenticate(record, trust):
    need(type(record) is dict and set(record) == {'issuer_identity','producer_identity','body','signature','sha256'})
    message = {k:record[k] for k in ('issuer_identity','producer_identity','body')}
    unsigned = dict(message, signature=record['signature'])
    need(digest(unsigned) == record['sha256'])
    entry = trust.get(record['issuer_identity'])
    need(type(entry) is dict and entry.get('producer_identity') == record['producer_identity'], 'Untrusted issuer or producer; UNKNOWN.')
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry['public_key_hex'])).verify(bytes.fromhex(record['signature']), DOMAIN + raw(message))
    except Exception:
        raise Refused('Signature verification failed; UNKNOWN.') from None
    need(record['body'].get('authority_granted') is False)
    return record['body']

# Only this decoder admits wide START metadata; signed values use raw()/load unchanged.
START_NS_FIELDS = frozenset(('started_wall_ns', 'started_process_ns'))
MAX_START_NS = 2 ** 63 - 1

def _start_integer(token):
    # Bound conversion before int(), independent of the interpreter digit-limit setting.
    need(len(token) <= 20 and token != '-0', 'Invalid START integer encoding.')
    value = int(token)
    need(-(2 ** 63) <= value <= MAX_START_NS, 'START integer overflow.')
    return value

def decode_parent_start(data):
    """vfy.parent-start-numeric/1: exact int64 only at two metadata paths.

    No timestamp substitution or projected identity: hash the original input bytes.
    All other values retain the global canonical domain; floats are never accepted.
    """
    need(type(data) is bytes and len(data) <= MAX_BYTES)
    decoded = load._decode_utf8(data)
    load._reject_excess_depth(decoded)
    try:
        value = json.loads(decoded, object_pairs_hook=load._object_from_pairs,
                           parse_int=_start_integer, parse_float=load._reject_float,
                           parse_constant=load._reject_non_json_constant)
    except json.JSONDecodeError:
        raise Refused('Malformed parent START JSON.') from None
    need(type(value) is dict, 'Parent START must be an object.')
    for name, item in value.items():
        canon.canonicalize(name)  # Including escaped-surrogate refusal for object keys.
        if name in START_NS_FIELDS:
            need(type(item) is int and 0 <= item <= MAX_START_NS,
                 'START nanoseconds must be exact nonnegative signed-64 integers.')
        else:
            # Includes nested lookalike timestamp names and every copied identity field.
            canon.canonicalize(item)
    return value

def parent_binding(start_bytes, basis):
    s = decode_parent_start(start_bytes)
    need(s.get('state') == 'STARTED' and s.get('automatic_retry') is False)
    need(all(text(s.get(k)) for k in ('task_key','operation_id','attempt_id')))
    identity = s.get('task_identity')
    need(type(identity) is dict and hex64(identity.get('subject_sha256')))
    pop = s.get('native_child_population', {})
    ids = pop.get('expected_child_ids')
    need(pop.get('state') == 'DECLARED_BEFORE_DISPATCH' and type(ids) is list and 0 < len(ids) <= 128)
    need(all(text(x) for x in ids) and len(ids) == len(set(ids)))
    need(type(basis) is dict and set(basis) == {'path','sha256'} and text(basis['path']) and hex64(basis['sha256']))
    need(any(type(r) is dict and all(r.get(k) == basis[k] for k in basis) for r in s.get('input_artifacts', [])))
    return {'task_key':s['task_key'],'task_identity':identity,
            'parent_binding':{'operation_id':s['operation_id'],'attempt_id':s['attempt_id'],'start_sha256':sha(start_bytes),'basis_artifact':basis},
            'expected_child_ids':ids}

def read_file(p):
    p = Path(p)
    need(p.is_absolute() and p == p.resolve())
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd); need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= MAX_BYTES)
        with os.fdopen(os.dup(fd),'rb') as f:
            b = f.read(MAX_BYTES + 1)
        need(len(b) <= MAX_BYTES)
        return b
    finally:
        os.close(fd)

def sync_dir(p):
    fd = os.open(p, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def fresh(path, b):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(b); f.flush(); os.fsync(f.fileno())
    sync_dir(path.parent)

def _usage(body):
    used = {r['axis_id']:Fraction(0) for r in body['budget']['resource_rows']}
    for c in body['children']:
        reservation = c['reservation']
        if reservation is None: continue
        held = axes(reservation['body']['resource_rows'],'reserved_amount')
        completion = c['completion']
        measured = axes(completion['body']['resource_rows'],'measured_amount') if completion else {}
        settlement = c['settlement']
        settled = axes(settlement['body']['resource_rows'],'settled_amount_or_UNKNOWN') if settlement else {}
        for name, reserved in held.items():
            # Unknown keeps the hold; an observed overrun cannot disappear from capacity.
            value = settled.get(name)
            used[name] += value if value is not None else max(reserved, measured.get(name) or Fraction(0))
    return used

class Ledger:
    """One exact parent/budget in one protected local store. No automatic discovery."""
    def __init__(self, root, private_seed, issuer_identity, trusted_issuers, *, expected_start_bytes, expected_basis, expected_budget_bytes):
        self.root = Path(root)
        need(self.root.is_absolute() and self.root == self.root.resolve() and self.root.is_dir())
        self.expected = (expected_start_bytes, expected_basis, expected_budget_bytes)
        self.key = Ed25519PrivateKey.from_private_bytes(private_seed)
        self.issuer = issuer_identity; self.trust = trusted_issuers
        public = self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        need(trusted_issuers.get(issuer_identity) == {'public_key_hex':public,'producer_identity':producer()}, 'Signer does not match independently configured trust.')

    @classmethod
    def create(cls, root, start_bytes, basis, budget_bytes, private_seed, issuer_identity, trusted_issuers):
        bound = parent_binding(start_bytes,basis); b = load.load_json_bytes(budget_bytes)
        need(set(b) == {'schema','budget_id','task_key','task_identity','parent_start_sha256','resource_rows'})
        need(b['schema'] == 'vfy.child-resource-budget/1' and text(b['budget_id']))
        need(b['task_key'] == bound['task_key'] and b['task_identity'] == bound['task_identity'] and b['parent_start_sha256'] == sha(start_bytes))
        limits = axes(b['resource_rows'],'limit'); need(all(v is not None for v in limits.values()))
        p = Path(root); need(p.is_absolute() and p == p.resolve() and not p.exists())
        p.mkdir(mode=0o700); sync_dir(p.parent)
        obj = cls(p,private_seed,issuer_identity,trusted_issuers, expected_start_bytes=start_bytes, expected_basis=basis, expected_budget_bytes=budget_bytes)
        body = dict(bound, schema=SCHEMA, revision=0, previous_snapshot_sha256=None,
                    budget=dict(b, budget_sha256=sha(budget_bytes), domain='THIS_LOCAL_LEDGER_ONLY'),
                    children=[{'child_id':c,'reservation':None,'dispatch':None,'completion':None,'settlement':None} for c in bound['expected_child_ids']],
                    unsupported_dimensions=UNKNOWN_DIMENSIONS, authority_granted=False, automatic_retry=False)
        fresh(p/'lock',b''); fresh(p/'state.json',raw(envelope(body,obj.key,obj.issuer)))
        return obj

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.root/'lock',os.O_RDWR | os.O_NOFOLLOW)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1)
            fcntl.flock(fd,fcntl.LOCK_EX)
            # Interrupted pre-publication state is quarantined, never silently discarded.
            need(not os.path.lexists(self.root/'pending.json'), 'Interrupted journal publication; UNKNOWN, no new allocation.')
            yield
        finally: os.close(fd)

    def snapshot(self):
        with self.locked():
            b = read_file(self.root/'state.json'); verify_report(b,self.trust,*self.expected)
            return b

    def _change(self, action):
        with self.locked():
            prior_bytes = read_file(self.root/'state.json')
            verify_report(prior_bytes,self.trust,*self.expected)
            prior = load.load_json_bytes(prior_bytes)
            body = authenticate(prior,self.trust)
            result = action(body)
            body['revision'] += 1; body['previous_snapshot_sha256'] = prior['sha256']
            payload = raw(envelope(body,self.key,self.issuer)); need(len(payload) <= MAX_BYTES)
            fresh(self.root/'pending.json',payload)
            os.replace(self.root/'pending.json',self.root/'state.json'); sync_dir(self.root)
            return result

    def _event(self, body, child, kind, at, fields):
        need(text(at))  # Owner-supplied recorded instant; never substituted with a retry time.
        bind = dict(task_key=body['task_key'],task_identity=body['task_identity'],
                    child_id=child['child_id'],attempt_id=child['attempt_id'],
                    parent_operation_id=body['parent_binding']['operation_id'],
                    parent_attempt_id=body['parent_binding']['attempt_id'],parent_start_sha256=body['parent_binding']['start_sha256'],
                    basis_artifact=body['parent_binding']['basis_artifact'],expected_child_ids=body['expected_child_ids'],
                    budget_id=body['budget']['budget_id'],budget_sha256=body['budget']['budget_sha256'])
        event_id = kind + '-' + digest(bind)
        return envelope(dict(bind,schema='vfy.child-'+kind+'/1',event_id=event_id,recorded_at=at,
                             authority_granted=False,automatic_retry=False,**fields),self.key,self.issuer)

    def reserve(self, child_id, attempt_id, resource_rows, issued_at):
        rows = load.load_json_bytes(raw(resource_rows)); requested = axes(rows,'reserved_amount')
        need(all(v is not None for v in requested.values()) and text(attempt_id))
        def change(body):
            child = next((c for c in body['children'] if c['child_id'] == child_id),None)
            need(child is not None and child['reservation'] is None, 'Missing, duplicate or already-reserved child; UNKNOWN/no redispatch.')
            need(all(c.get('attempt_id') != attempt_id for c in body['children']))
            limits = axes(body['budget']['resource_rows'],'limit'); used = _usage(body)
            need(set(requested) == set(limits))
            need(all(used[k] + requested[k] <= limits[k] for k in limits), 'Local budget unavailable; reservation refused.')
            child['attempt_id'] = attempt_id
            event = self._event(body,child,'reservation',issued_at,{'issued_at':issued_at,'resource_rows':rows,'state':'RESERVED_LOCAL_HOLD'})
            event['body']['reservation_id'] = event['body']['event_id']
            event = envelope(event['body'],self.key,self.issuer)
            child['reservation'] = event
            return event
        return self._change(change)

    def _child(self, body, reservation_id):
        found = [c for c in body['children'] if c['reservation'] and c['reservation']['body']['reservation_id'] == reservation_id]
        need(len(found) == 1); return found[0]

    def dispatch_record(self, reservation_id, at):
        def change(body):
            c = self._child(body,reservation_id); need(c['dispatch'] is None)
            c['dispatch'] = self._event(body,c,'dispatch',at,{'reservation_id':reservation_id,'reservation_sha256':c['reservation']['sha256'],'state':'INTENT_RECORDED_NOT_PROOF_OF_LAUNCH'})
            return c['dispatch']
        return self._change(change)

    def complete(self, reservation_id, service_performed, resource_rows, observation, at):
        rows = load.load_json_bytes(raw(resource_rows)); measured = axes(rows,'measured_amount')
        need(service_performed in ('PERFORMED','NOT_PERFORMED','UNKNOWN'))
        need(type(observation) is dict and set(observation) == {'path','sha256'} and text(observation['path']) and hex64(observation['sha256']))
        # Capture exact selected observer bytes. Their factual interpretation is the producer's responsibility.
        observation_bytes = read_file(observation['path'])
        need(sha(observation_bytes) == observation['sha256'])
        captured = load.load_json_bytes(observation_bytes)
        need(captured == {'schema':'vfy.child-observation/1','reservation_id':reservation_id,
                          'service_performed':service_performed,'resource_rows':rows})
        def change(body):
            c = self._child(body,reservation_id); need(c['dispatch'] is not None and c['completion'] is None)
            need(set(measured) == set(axes(c['reservation']['body']['resource_rows'],'reserved_amount')))
            c['completion'] = self._event(body,c,'completion',at,{'reservation_id':reservation_id,'reservation_sha256':c['reservation']['sha256'],
                'service_performed':service_performed,'resource_measured':'RECORDED_PRODUCER_OBSERVATION' if all(v is not None for v in measured.values()) else 'PARTIAL_OR_UNKNOWN',
                'financial_or_external_settlement':'UNKNOWN','observation':observation,
                'measurement_assurance':'TRUSTED_PRODUCER_OBSERVATION_INPUT_NOT_INDEPENDENTLY_MEASURED_BY_LEDGER','resource_rows':rows})
            return c['completion']
        return self._change(change)

    def settle(self, reservation_id, completion_sha256, settled_at):
        def change(body):
            c = self._child(body,reservation_id); need(c['completion'] is not None and c['settlement'] is None)
            need(c['completion']['sha256'] == completion_sha256)
            rows = [dict({k:r[k] for k in ('axis_id','unit','aggregation','scope')},measured_amount=r['measured_amount'],settled_amount_or_UNKNOWN=(r['measured_amount'] if c['completion']['body']['service_performed'] != 'UNKNOWN' else 'UNKNOWN')) for r in c['completion']['body']['resource_rows']]
            # Settlement consumes the observed cost once, releasing unused reservation only on known axes.
            settlement_rows = rows
            c['settlement'] = self._event(body,c,'settlement',settled_at,{'settled_at':settled_at,'settlement_id':'settlement-'+digest({'reservation':reservation_id,'completion':completion_sha256}),
                'reservation_id':reservation_id,'reservation_sha256':c['reservation']['sha256'],'completion_sha256':completion_sha256,
                'service_performed':c['completion']['body']['service_performed'],'resource_measured':c['completion']['body']['resource_measured'],
                'financial_or_external_settlement':'UNKNOWN','state':'LOCAL_RESOURCE_ACCOUNTING_ONLY','resource_rows':settlement_rows})
            return c['settlement']
        return self._change(change)


def verify_report(report_bytes, trust, start_bytes, basis, budget_bytes, minimum_revision=0):
    """Explicit selected bytes only. Invalid/absent evidence is UNKNOWN, never zero."""
    try:
        return _verify_report(report_bytes, trust, start_bytes, basis, budget_bytes, minimum_revision)
    except (KeyError, TypeError, AttributeError, IndexError, ZeroDivisionError):
        raise Refused('Malformed report; preserve UNKNOWN and held amounts.') from None


def _verify_report(report_bytes, trust, start_bytes, basis, budget_bytes, minimum_revision):
    need(type(report_bytes) is bytes and len(report_bytes) <= MAX_BYTES)
    record = load.load_json_bytes(report_bytes); body = authenticate(record,trust)
    expected = parent_binding(start_bytes,basis); budget = load.load_json_bytes(budget_bytes)
    budget_sha256 = sha(budget_bytes)
    need(body['schema'] == SCHEMA and all(body[k] == v for k,v in expected.items()))
    need(body['automatic_retry'] is False and body['unsupported_dimensions'] == UNKNOWN_DIMENSIONS)
    need(type(body['revision']) is int and type(minimum_revision) is int and body['revision'] >= minimum_revision >= 0)
    need(body['budget'] == dict(budget,budget_sha256=budget_sha256,domain='THIS_LOCAL_LEDGER_ONLY'))
    need(budget['schema'] == 'vfy.child-resource-budget/1' and budget['task_key'] == expected['task_key'] and budget['task_identity'] == expected['task_identity'] and budget['parent_start_sha256'] == sha(start_bytes))
    limits = axes(budget['resource_rows'],'limit'); need(all(v is not None for v in limits.values()))
    need([c['child_id'] for c in body['children']] == body['expected_child_ids'])
    event_ids = set(); attempt_ids = set(); event_count = 0
    for c in body['children']:
        need(set(c) == ({'child_id','reservation','dispatch','completion','settlement'} if c['reservation'] is None else {'child_id','attempt_id','reservation','dispatch','completion','settlement'}))
        if c['reservation'] is None:
            need(all(c[k] is None for k in ('dispatch','completion','settlement'))); continue
        need(text(c['attempt_id']) and c['attempt_id'] not in attempt_ids); attempt_ids.add(c['attempt_id'])
        for kind in ('reservation','dispatch','completion','settlement'):
            if c[kind] is None: continue
            e = authenticate(c[kind],trust); event_count += 1
            need(e['schema'] == 'vfy.child-'+kind+'/1' and e['automatic_retry'] is False)
            need(e['event_id'] not in event_ids); event_ids.add(e['event_id'])
            need(e['task_key'] == body['task_key'] and e['task_identity'] == body['task_identity'] and e['child_id'] == c['child_id'] and e['attempt_id'] == c['attempt_id'])
            need(e['parent_operation_id'] == body['parent_binding']['operation_id'] and e['parent_attempt_id'] == body['parent_binding']['attempt_id'] and e['parent_start_sha256'] == body['parent_binding']['start_sha256'])
            need(e['basis_artifact'] == basis and e['expected_child_ids'] == body['expected_child_ids'] and e['budget_id'] == budget['budget_id'] and e['budget_sha256'] == budget_sha256)
            bind = {k:e[k] for k in ('task_key','task_identity','child_id','attempt_id','parent_operation_id','parent_attempt_id','parent_start_sha256','basis_artifact','expected_child_ids','budget_id','budget_sha256')}
            need(e['event_id'] == kind+'-'+digest(bind))
            if kind == 'reservation':
                a = axes(e['resource_rows'],'reserved_amount'); need(set(a) == set(limits) and all(v is not None for v in a.values()))
                need(e['reservation_id'] == e['event_id'] and e['issued_at'] == e['recorded_at'] and e['state'] == 'RESERVED_LOCAL_HOLD')
            else:
                need(e['reservation_id'] == c['reservation']['body']['reservation_id'] and e['reservation_sha256'] == c['reservation']['sha256'])
            if kind == 'dispatch': need(e['state'] == 'INTENT_RECORDED_NOT_PROOF_OF_LAUNCH')
            if kind == 'completion':
                measured = axes(e['resource_rows'],'measured_amount'); need(set(measured) == set(limits))
                need(e['service_performed'] in ('PERFORMED','NOT_PERFORMED','UNKNOWN') and e['financial_or_external_settlement'] == 'UNKNOWN')
                need(e['resource_measured'] == ('RECORDED_PRODUCER_OBSERVATION' if all(v is not None for v in measured.values()) else 'PARTIAL_OR_UNKNOWN'))
                need(e['measurement_assurance'] == 'TRUSTED_PRODUCER_OBSERVATION_INPUT_NOT_INDEPENDENTLY_MEASURED_BY_LEDGER')
                need(set(e['observation']) == {'path','sha256'} and text(e['observation']['path']) and hex64(e['observation']['sha256']))
        need(c['completion'] is None or c['dispatch'] is not None)
        if c['settlement'] is not None:
            need(c['completion'] is not None)
            e=c['settlement']['body']; completion=c['completion']['body']
            need(e['completion_sha256'] == c['completion']['sha256'])
            need(e['settlement_id'] == 'settlement-'+digest({'reservation':e['reservation_id'],'completion':e['completion_sha256']}))
            need(e['settled_at'] == e['recorded_at'] and e['state'] == 'LOCAL_RESOURCE_ACCOUNTING_ONLY')
            need(e['service_performed'] == completion['service_performed'] and e['resource_measured'] == completion['resource_measured'] and e['financial_or_external_settlement'] == 'UNKNOWN')
            expected_rows=[dict(r,settled_amount_or_UNKNOWN=(r['measured_amount'] if completion['service_performed'] != 'UNKNOWN' else 'UNKNOWN')) for r in completion['resource_rows']]
            need(e['resource_rows'] == expected_rows, 'Settlement conflicts with measured completion; UNKNOWN.')
    need(body['revision'] == event_count)
    used = _usage(body)
    return {'state':'VERIFIED_SELECTED_SNAPSHOT_NOT_FRESHNESS','revision':body['revision'],
            'committed_exposure':{k:str(v) for k,v in used.items()},'limit_exceeded':any(used[k] > limits[k] for k in limits),
            'unknown_children':[c['child_id'] for c in body['children'] if c['completion'] is None or c['settlement'] is None or c['completion']['body']['service_performed'] == 'UNKNOWN' or any(r['settled_amount_or_UNKNOWN']=='UNKNOWN' for r in c['settlement']['body']['resource_rows'])],
            'authority_granted':False,'automatic_retry':False,'financial_or_external_settlement':'UNKNOWN','unsupported_dimensions':body['unsupported_dimensions']}
