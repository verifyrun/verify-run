"""One bounded development pipe session; live capability and key stay inside Run."""
import contextlib
import fcntl
import os
import select
import stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from vfy import child_ledger as m, service_attempt as service, service_tests
from vfy.service_read_cli import _inputs, MAX_INPUTS, MAX_STDIN

MAX_OUTPUT = 8 * 1024 * 1024
SELECTION = {'expected_snapshot_sha256', 'expected_pool_root', 'owner_trust',
    'child_trust', 'selected_observer', 'expected_child_trusts', 'minimum_revision',
    'selected_callback_identity', 'selected_managed_identity'}



def bounded_file(path, limit, *, secret=False):
    p = Path(path)
    m.need(p.is_absolute() and p == p.resolve())
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        m.need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= limit)
        if secret:
            m.need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size == 32)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        m.need(len(raw) == st.st_size and (st.st_size, st.st_mtime_ns) == (after.st_size, after.st_mtime_ns))
        return raw
    finally:
        os.close(fd)


@contextlib.contextmanager
def selected_pool(path, expected):
    raw = bounded_file(path, MAX_STDIN)
    m.need(m.hex64(expected) and m.sha(raw) == expected)
    p = m.load.load_json_bytes(raw)
    m.need(type(p) is dict and set(p) == {'schema', 'scope', 'inputs', 'selection',
        'key_file', 'session_seconds', 'service_identity'} and
        p['schema'] == 'vfy.service-accounting-profile/1' and
        p['scope'] == 'DISPOSABLE_DEVELOPMENT_ONLY' and
        p['service_identity'] == service.identity() and
        type(p['session_seconds']) is int and 1 <= p['session_seconds'] <= 900)
    m.need(type(p['selection']) is dict and set(p['selection']) == SELECTION)
    data = _inputs(p['inputs'], ('snapshot', 'config', 'predecessor', 'policy', 'managed_legacy'), MAX_INPUTS)
    selected = service_tests.load_service_pool(**p['selection'], snapshot_bytes=data['snapshot'],
        expected_config_bytes=data['config'], predecessor_snapshot_bytes=data['predecessor'],
        policy_bytes=data['policy'], managed_legacy_snapshot_bytes=data['managed_legacy'] or None)
    owner = selected.owner
    m.need(owner.root == owner.root.resolve() and owner.root.is_dir())
    key = Ed25519PrivateKey.from_private_bytes(bounded_file(p['key_file'], 32, secret=True))
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    m.need(owner.trust[owner.issuer] == {'public_key_hex': public, 'producer_identity': m.producer()})
    owner.key = key
    # The existing allocator lock, not a new independent coordination store.
    fd = os.open(owner.root / 'lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        m.need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        @contextlib.contextmanager
        def already_locked():
            m.need(not os.path.lexists(owner.root / 'pending.json'))
            yield
        owner.locked = already_locked
        pool = service.ServicePool(owner, predecessor_snapshot_bytes=data['predecessor'], policy_bytes=data['policy'])
        m.need(pool.snapshot() == data['snapshot'], 'Selected service head changed; no reset or replay.')
        yield pool, p['session_seconds']
    finally:
        os.close(fd)


class Pipe:
    def __init__(self, input_fd, output_fd, seconds, monotonic):
        self.monotonic = monotonic
        self.input = input_fd
        self.output = output_fd
        self.deadline = self.monotonic() + seconds
        self.pending = bytearray()
        os.set_blocking(self.input, False)
        os.set_blocking(self.output, False)

    def wait(self, *, writing=False):
        remaining = self.deadline - self.monotonic()
        m.need(remaining > 0, 'Session deadline exhausted.')
        r, w, _ = select.select([] if writing else [self.input], [self.output] if writing else [], [], remaining)
        m.need(bool(w if writing else r), 'Session deadline exhausted.')

    def read(self):
        while b'\n' not in self.pending:
            self.wait()
            try:
                chunk = os.read(self.input, min(65536, MAX_STDIN + 1 - len(self.pending)))
            except BlockingIOError:
                continue
            m.need(bool(chunk), 'Session EOF; no retry.')
            self.pending.extend(chunk)
            m.need(len(self.pending) <= MAX_STDIN, 'Oversized session frame.')
        raw, _, tail = self.pending.partition(b'\n')
        self.pending = bytearray(tail)
        return bytes(raw) + b'\n'

    def write(self, response):
        data = m.raw(response) + b'\n'
        m.need(len(data) <= MAX_OUTPUT, 'Oversized session response.')
        while data:
            self.wait(writing=True)
            try:
                written = os.write(self.output, data)
            except BlockingIOError:
                continue
            m.need(written > 0)
            data = data[written:]


class Session:
    def __init__(self, pool, profile_sha256, session_id, now):
        self.now = now
        self.pool = pool
        self.profile = profile_sha256
        self.id = session_id
        self.sequence = 0
        self.ticket = None
        self.request = None
        self.preview = None
        self.terminal = False
        self.state = 'OPEN'

    def response(self, state, record=None, request_sha256=None, error=None):
        return dict(schema='vfy.service-accounting-response/1', profile_sha256=self.profile,
            session_id=self.id, sequence=self.sequence, request_sha256=request_sha256,
            state=state, record=record, error=error, full_cost='UNKNOWN', **service.FLAGS)

    def handle(self, raw):
        q = m.load.load_json_bytes(raw)
        m.need(type(q) is dict and set(q) == {'schema', 'session_id', 'sequence', 'operation', 'inputs'} and
            q['schema'] == 'vfy.service-accounting-frame/1' and q['session_id'] == self.id and
            type(q['sequence']) is int and q['sequence'] == self.sequence + 1 and not self.terminal)
        op = q['operation']
        allowed = {'OPEN': {'ADMIT'}, 'ADMITTED': {'CONSUME', 'UNKNOWN'}, 'CONSUMED': {'SETTLE', 'UNKNOWN'}}
        m.need(op in allowed[self.state])
        names = {'ADMIT': ('request', 'preview', 'approval'), 'CONSUME': ('start',),
            'SETTLE': ('result', 'stdout', 'stderr'), 'UNKNOWN': ()}[op]
        inputs = _inputs(q['inputs'], names, MAX_INPUTS)
        self.sequence = q['sequence']
        if op == 'ADMIT':
            self.request, self.preview = inputs['request'], inputs['preview']
            self.ticket = self.pool.admit(request_bytes=self.request, preview_bytes=self.preview,
                approval_bytes=inputs['approval'], recorded_at=self.now())
            record = self.ticket
            state = 'ADMITTED'
        elif op == 'CONSUME':
            record = self.pool.consume(self.ticket, request_bytes=self.request, preview_bytes=self.preview,
                start_bytes=inputs['start'], recorded_at=self.now())
            state = 'CONSUMED'
        elif op == 'SETTLE':
            record = self.pool.settle(self.ticket, result_bytes=inputs['result'],
                stdout_bytes=inputs['stdout'], stderr_bytes=inputs['stderr'], recorded_at=self.now())
            state = 'SETTLED'
            self.terminal = True
        else:
            record = self.pool.mark_unknown(self.ticket, reason='caller explicitly stopped; no retry', recorded_at=self.now())
            state = 'UNKNOWN_HOLD_RETAINED'
            self.terminal = True
        self.state = state
        return self.response(state, record, m.sha(raw))

    def abandon(self):
        if self.ticket is not None and not self.terminal:
            try:
                self.pool.mark_unknown(self.ticket, reason='pipe interrupted or refused; no retry', recorded_at=self.now())
            except Exception:
                pass  # pending publication or already UNKNOWN: retain the original hold.
        self.pool._live.clear()
        self.terminal = True


def run(*, profile, profile_sha256, input_fd, output_fd, session_id, now, monotonic):
    session = None
    pipe = Pipe(input_fd, output_fd, 30, monotonic)
    try:
        with selected_pool(profile, profile_sha256) as (pool, seconds):
            pipe.deadline = monotonic() + seconds
            session = Session(pool, profile_sha256, session_id, now)
            try:
                pipe.write(session.response('OPEN'))
                while not session.terminal:
                    raw = pipe.read()
                    pipe.write(session.handle(raw))
                return 0
            finally:
                session.abandon()
    except Exception as exc:
        response = (session.response('REFUSED', error=type(exc).__name__) if session else
            dict(schema='vfy.service-accounting-response/1', profile_sha256=profile_sha256 if m.hex64(profile_sha256) else None,
                session_id=None, sequence=0, request_sha256=None, state='REFUSED', record=None,
                error=type(exc).__name__, full_cost='UNKNOWN', **service.FLAGS))
        try:
            pipe.write(response)
        except Exception:
            return 1
        return 12
