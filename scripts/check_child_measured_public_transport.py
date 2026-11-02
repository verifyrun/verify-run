"""Independent archive/read-only consumer check; never an installed CI claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import zipfile


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('packet', type=Path)
    ap.add_argument('engineer', type=Path)
    ap.add_argument('original_source', type=Path)
    args = ap.parse_args()
    selection = json.loads((args.packet / 'TRANSPORT.json').read_bytes())
    archive = args.packet / 'child-measured-public-receipts.zip'
    assert sha(archive.read_bytes()) == selection['archive_sha256']
    destination = Path(tempfile.mkdtemp(prefix='child-measured-public-reader-')).resolve()
    with zipfile.ZipFile(archive) as z:
        assert len(z.infolist()) == len(selection['members']) == 44
        assert set(z.namelist()) == set(selection['members'])
        for info in z.infolist():
            p = PurePosixPath(info.filename)
            assert not p.is_absolute() and '..' not in p.parts
            assert stat.S_ISREG(info.external_attr >> 16)
            assert info.file_size == selection['members'][info.filename]['bytes']
            b = z.read(info)
            assert sha(b) == selection['members'][info.filename]['sha256']
            target = destination / info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as f:
                f.write(b)
            target.chmod(0o444)
    # The remaining check can read, but cannot write files or launch/network.
    def read_only(event, values):
        if event == 'open':
            _, mode, flags = values
            if (isinstance(mode, str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                raise RuntimeError('review refuses filesystem write')
        if event.startswith(('subprocess.', 'socket.')) or event in ('os.system', 'os.posix_spawn', 'os.fork', 'os.exec', 'os.remove', 'os.rename', 'os.mkdir'):
            raise RuntimeError('review refuses effect: ' + event)
    sys.addaudithook(read_only)
    sys.path.insert(0, str(args.engineer))
    from engineer.experience import measured_children as mc
    from engineer.selected_inputs import selected_inputs
    audit = destination / 'audit'
    checks = {}
    with selected_inputs({'run_source': str(args.original_source), 'run_audit': str(audit)}):
        m, observer = mc.load_run()
        # Authenticate snapshots against each retained public trust selection.
        # This does not independently authorize the issuer or establish freshness.
        for case in ('first', 'follow-on', 'interrupted'):
            d = audit / 'demonstration' / case
            checks[case + '_report'] = m.verify_report(
                (d / 'report.json').read_bytes(), json.loads((d / 'trust.json').read_bytes()),
                (d / 'START.json').read_bytes(), json.loads((d / 'basis.json').read_bytes()),
                (d / 'budget.json').read_bytes())
        d = audit / 'demonstration/first'
        root = d / 'ledger'
        q = json.loads((d / 'request.json').read_bytes())
        body = json.loads((d / 'report.json').read_bytes())['body']
        trust = json.loads((d / 'trust.json').read_bytes())
        operation = {k: q[k] for k in ('task_key', 'task_identity', 'operation_id', 'attempt_id', 'argv', 'cwd')}
        operation.update(parent=q['parent_start'], stdin={'path': str(d / 'input.json'), 'sha256': sha((d / 'input.json').read_bytes())})
        rid = body['children'][0]['reservation']['body']['reservation_id']
        original_read = mc.cs.read
        def reader(path):
            path = Path(path)
            for stream in ('stdout', 'stderr'):
                if path == root / (rid + '.' + stream + '.bin'):
                    return original_read(d / (stream + '.bin'))
            return original_read(path)
        mc.request_path = lambda *a: d / 'request.json'
        mc.cs.read = reader
        rows = mc.verify_companions(m, root, body, trust, observer.identity(), operation)
        assert rows[0]['state'] == 'VERIFIED_MEASURED_LOCAL_COMPANIONS'
        assert all(r['state'] == 'UNKNOWN_INCOMPLETE' for r in rows[1:])
        checks['first_companions'] = rows
        negatives = []
        for kind in ('missing', 'signature', 'output', 'request', 'runtime', 'observer'):
            def altered(path):
                path = Path(path)
                value = reader(path)
                if kind == 'missing' and path.name.endswith('.acquisition.json'):
                    raise FileNotFoundError('retained acquisition absent')
                if kind == 'signature' and path.name.endswith('.acquisition.json'):
                    v = json.loads(value); v['signature'] = '00' * 64
                    return mc.cs.raw(v)
                if kind == 'output' and path.name.endswith('.stdout.bin'):
                    return value + b'changed'
                if kind == 'request' and path.name == 'request.json':
                    return value + b'\n'
                return value
            mc.cs.read = altered
            op = dict(operation)
            obs = observer.identity()
            if kind == 'runtime': op['argv'] = ['substituted']
            if kind == 'observer': obs = dict(obs, source_sha256='0' * 64)
            row = mc.verify_companions(m, root, body, trust, obs, op)[0]
            assert row['state'] == 'UNKNOWN_MEASUREMENT_CORRESPONDENCE' and row['retry'] is False
            negatives.append(kind)
        mc.cs.read = original_read
        checks['negative_controls'] = negatives
    assert all(sha((destination / n).read_bytes()) == v['sha256'] for n, v in selection['members'].items())
    checks.update(archive_sha256=selection['archive_sha256'], extracted_root=str(destination),
                  source_transport=False, original_source=str(args.original_source),
                  consumer_sha256=sha((args.engineer / 'engineer/experience/measured_children.py').read_bytes()),
                  retained_members_unchanged=True, hosted_ci_closure=False,
                  effects='NO_DISPATCH_NO_SIGNING_NO_STORE_ACCESS', full_cost='UNKNOWN')
    print(json.dumps(checks, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
