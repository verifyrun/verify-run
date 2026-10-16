"""Digest-selected historical byte verification. No admission, recovery or dispatch."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import zipfile

SOURCE_MANIFEST = '29a068926de05684569b57555996b6d963c4e1ad596741c8a933937192547926'
MODULES = ('__init__.py', 'canon.py', 'load.py', 'errors.py', 'child_ledger.py')
MAX_ARCHIVE = 2 * 1024 * 1024

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    with args.archive.open('rb') as stream:
        raw = stream.read(MAX_ARCHIVE + 1)
    require(len(raw) <= MAX_ARCHIVE and sha(raw) == args.sha256, 'Selected archive digest/size mismatch')
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        require(len(infos) == 49 and len({i.filename for i in infos}) == 49, 'Duplicate or wrong member count')
        require(sum(i.file_size for i in infos) <= MAX_ARCHIVE, 'Expanded byte bound exceeded')
        members = {}
        for info in infos:
            path = PurePosixPath(info.filename)
            require(not path.is_absolute() and '..' not in path.parts and str(path) == info.filename,
                    'Unsafe member path')
            require(stat.S_ISREG(info.external_attr >> 16) and info.compress_type == zipfile.ZIP_STORED,
                    'Nonregular or compressed member')
            members[info.filename] = archive.read(info)
    require(sha(members['audit/SOURCE_MANIFEST.json']) == SOURCE_MANIFEST, 'Original manifest changed')
    manifest = json.loads(members['audit/SOURCE_MANIFEST.json'])
    require({n for n in members if n.startswith('source/')} == {'source/vfy/' + n for n in MODULES},
            'Unexpected executable source')
    for name in MODULES:
        require(sha(members['source/vfy/' + name]) == manifest['files']['vfy/' + name], 'Original source changed')
    require(not any(n == 'vfy' or n.startswith('vfy.') for n in sys.modules), 'Ambient vfy forbidden')
    # Resolve ordinary dependencies before restricting runtime operations.
    import yaml
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes(32)).verify(bytes(64), b'')
    except Exception:
        pass
    destination = Path(tempfile.mkdtemp(prefix='child-keyless-reader-')).resolve()
    for name, body in members.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(body)
        target.chmod(0o444)
    def guard(event, values):
        if event == 'open':
            path, mode, flags = values
            if (isinstance(mode, str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                raise RuntimeError('Read-only verifier refuses write')
            if isinstance(path, (str, bytes)) and os.fsdecode(path).startswith('/Users/devinbostick/'):
                raise RuntimeError('Original host reach-through forbidden')
        if event.startswith(('subprocess.', 'socket.')) or event in ('os.system','os.posix_spawn','os.fork','os.exec','os.remove','os.rename','os.mkdir'):
            raise RuntimeError('Read-only verifier refuses effect: ' + event)
    sys.dont_write_bytecode = True
    sys.addaudithook(guard)
    sys.path.insert(0, str(destination / 'source'))
    from vfy import child_ledger as ledger
    results = {}
    controls = []
    for case in ('first', 'follow-on', 'interrupted'):
        prefix = 'audit/demonstration/' + case + '/'
        selected = {n: members[prefix + n] for n in ('report.json','trust.json','START.json','basis.json','budget.json')}
        def verify(values):
            return ledger.verify_report(values['report.json'], json.loads(values['trust.json']),
                                        values['START.json'], json.loads(values['basis.json']), values['budget.json'])
        results[case] = verify(selected)
        if args.self_test:
            for kind in ('signature','trust','start','budget','basis'):
                changed = dict(selected)
                if kind == 'signature':
                    value = json.loads(changed['report.json']); value['signature'] = '00' * 64
                    changed['report.json'] = json.dumps(value).encode()
                elif kind == 'trust':
                    changed['trust.json'] = b'{}'
                elif kind in ('start','budget'):
                    key = {'start':'START.json','budget':'budget.json'}[kind]
                    changed[key] += b'\n'
                else:
                    value = json.loads(changed['basis.json']); value['sha256'] = '0' * 64
                    changed['basis.json'] = json.dumps(value).encode()
                try:
                    verify(changed)
                except ledger.Refused:
                    controls.append(case + ':' + kind)
                else:
                    raise ValueError('Tamper accepted: ' + case + ':' + kind)
    require(all((destination / n).read_bytes() == b for n, b in members.items()), 'Retained bytes changed')
    output = {'schema':'run.child-measured-keyless-check/1', 'archive_sha256':sha(raw),
              'source_manifest_sha256':SOURCE_MANIFEST, 'source_scope':'FIVE_EXACT_VERIFIER_MODULES_NOT_COMPLETE_SOURCE',
              'reports':results, 'negative_controls':controls, 'retained_members_unchanged':True,
              'authority_granted':False, 'automatic_retry':False, 'freshness':'UNKNOWN',
              'full_cost':'UNKNOWN', 'admission_and_custody':'NOT_CHECKED',
              'companion_correspondence':'NOT_CHECKED', 'hosted_ci_closure':False}
    print(json.dumps(output, sort_keys=True, indent=2))

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'state':'UNKNOWN','error':str(exc), 'authority_granted':False,'automatic_retry':False}))
        raise SystemExit(2)
