"""One bound descriptor and direct-child observation. Never a source-stop proof."""
import contextlib
import hashlib
import os
import stat
from pathlib import Path
from vfy import canon, load
from vfy.errors import ExecutionConfigurationInvalid

ENV = 'VFY_CUSTODY_HANDOFF'
LIMIT = 1048576

def need(value):
    if not value:
        raise ExecutionConfigurationInvalid('Custody handoff is unavailable or differs from its binding.')

def digest(value):
    return hashlib.sha256(canon.canonical_bytes(value)).hexdigest()

def hex_digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

def read_file(name):
    p = Path(name)
    need(p.is_absolute() and p == p.resolve() and not p.is_symlink())
    fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= LIMIT)
        with os.fdopen(os.dup(fd), 'rb') as f:
            data = f.read(LIMIT + 1)
        need(len(data) <= LIMIT)
        return data
    finally:
        os.close(fd)

def commitment(envelope):
    return digest({k: v for k, v in envelope.items() if k != 'fd'})

class Handoff:
    def __init__(self, envelope):
        self.fd = None
        try:
            self.text = canon.canonical_bytes(envelope)
            self.envelope = load.load_json_bytes(self.text)
            self._shape()
            import fcntl
            self.fd = fcntl.fcntl(self.envelope['fd'], fcntl.F_DUPFD_CLOEXEC, 3)
            self.validate()
        except (OSError, ValueError, TypeError, KeyError):
            self.close()
            raise ExecutionConfigurationInvalid('Custody handoff could not be validated.') from None
        except BaseException:
            self.close()
            raise

    def _shape(self):
        e = self.envelope
        need(type(e) is dict and set(e) == {'binding', 'intent_path', 'intent_sha256', 'fd'})
        need(type(e['fd']) is int and e['fd'] >= 3)
        b = e['binding']
        need(type(b) is dict and set(b) == {'version', 'operation_id', 'source_id', 'argv', 'lease', 'worker_files', 'worker_data', 'coverage'})
        need(type(b['version']) is int and b['version'] == 1 and b['coverage'] == 'guarded-intents-v1')
        need(hex_digest(b['operation_id']) and hex_digest(b['source_id']) and hex_digest(e['intent_sha256']))
        need(type(b['argv']) is list and b['argv'] and all(type(s) is str and '\0' not in s for s in b['argv']))
        need(type(b['lease']) is dict and set(b['lease']) == {'device', 'inode'} and all(type(v) is int and v >= 0 for v in b['lease'].values()))
        files = b['worker_files']
        need(type(files) is dict and 1 <= len(files) <= 512 and b['argv'][0] in files)
        need(all(type(p) is str and hex_digest(h) for p, h in files.items()))
        need(type(b['worker_data']) is dict and len(self.text) <= LIMIT and type(e['intent_path']) is str)

    def validate(self, candidate=None, environment=None):
        try:
            self._validate(candidate, environment)
        except (OSError, ValueError, TypeError, KeyError):
            raise ExecutionConfigurationInvalid('Custody handoff could not be validated.') from None

    def _validate(self, candidate=None, environment=None):
        import fcntl
        b = self.envelope['binding']
        st = os.fstat(self.fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
        need((st.st_dev, st.st_ino) == (b['lease']['device'], b['lease']['inode']))
        need(fcntl.fcntl(self.fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
        raw = read_file(self.envelope['intent_path'])
        need(hashlib.sha256(raw).hexdigest() == self.envelope['intent_sha256'])
        expected = {'schema': 'vfy.custody-intent/1', 'binding_sha256': digest(b), 'state': 'PENDING'}
        need(raw == canon.canonical_bytes(expected))
        need(not os.path.lexists(self.envelope['intent_path'] + '.terminal.json'))
        need(not os.path.lexists(self.envelope['intent_path'] + '.claimed'))
        for name, expected_hash in b['worker_files'].items():
            p = Path(name)
            need(p.is_absolute() and p == p.resolve() and not p.is_symlink())
            fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                need(stat.S_ISREG(os.fstat(fd).st_mode))
                h = hashlib.sha256()
                with os.fdopen(os.dup(fd), 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        h.update(chunk)
                need(h.hexdigest() == expected_hash)
            finally:
                os.close(fd)
        if candidate is not None:
            need(candidate['action']['argv'] == b['argv'])
            need(candidate['action'].get('params', {}).get('run_custody_sha256') == commitment(self.envelope))
        if environment is not None:
            need(ENV not in environment)

    def claim(self, authorization_id):
        """One dispatch per protected intent, including failed/unknown dispatches."""
        try:
            path = self.envelope['intent_path'] + '.claimed'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(canon.canonical_bytes({'handoff_sha256': commitment(self.envelope),
                                             'authorization_id': authorization_id}))
                f.flush(); os.fsync(f.fileno())
            directory = os.open(str(Path(path).parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            raise ExecutionConfigurationInvalid('Custody intent is claimed or cannot be claimed; retain UNKNOWN.') from None

    def child_environment(self, environment):
        need(ENV not in environment)
        value = {k: v for k, v in self.envelope.items() if k != 'fd'}
        value.update(fd=self.fd, handoff_sha256=commitment(self.envelope))
        return dict(environment, **{ENV: canon.canonicalize(value)})

    def terminal(self, code, not_started=False, pid=None):
        if code is None and not not_started:
            return
        body = {'schema': 'vfy.custody-terminal/1', 'handoff_sha256': commitment(self.envelope),
                'returncode': code, 'pid': pid, 'scope': 'NOT_STARTED' if not_started else 'DIRECT_CHILD_ONLY'}
        path = self.envelope['intent_path'] + '.terminal.json'
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(canon.canonical_bytes(body)); f.flush(); os.fsync(f.fileno())
            directory = os.open(str(Path(path).parent), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            # Partial/missing terminal remains UNKNOWN. Do not lose the action receipt.
            pass

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

@contextlib.contextmanager
def open_handoff(path):
    try:
        handoff = Handoff(load.load_json_bytes(read_file(path)))
    except (OSError, ValueError, TypeError, KeyError):
        raise ExecutionConfigurationInvalid('Custody handoff could not be validated.') from None
    try:
        yield handoff
    finally:
        handoff.close()
