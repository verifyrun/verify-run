"""Copy only retained public demonstration bytes; never load or dispatch Run.

Exact source transport is blocked by literal fixture signing keys in its sealed
manifest. This packages public audit bytes only, NOT a hosted test closure.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


def sha(b):
    return hashlib.sha256(b).hexdigest()


def regular(root, name):
    p = PurePosixPath(name)
    assert not p.is_absolute() and '..' not in p.parts
    target = root / name
    assert target.resolve() == target and stat.S_ISREG(target.lstat().st_mode), name
    return target.read_bytes()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('repository', type=Path)
    ap.add_argument('output', type=Path)
    args = ap.parse_args()
    source = args.repository / 'build/child-measured-20261007/source'
    audit = args.repository / 'docs/audit/child-measured-20261007'
    manifest_bytes = regular(audit, 'SOURCE_MANIFEST.json')
    assert sha(manifest_bytes) == '29a068926de05684569b57555996b6d963c4e1ad596741c8a933937192547926'
    manifest = json.loads(manifest_bytes)
    total = 0
    literal_keys = []
    # Validate every original member; do not copy any source bytes.
    pattern = rb'"private_key_hex"\s*:\s*"[0-9a-fA-F]{64}"'
    for name, digest in manifest['files'].items():
        b = regular(source, name)
        assert sha(b) == digest, name
        total += len(b)
        if re.search(pattern, b):
            literal_keys.append(name)
    members = {'audit/SOURCE_MANIFEST.json': manifest_bytes,
               'audit/OBSERVER_SELECTION.json': regular(audit, 'OBSERVER_SELECTION.json')}
    assert sha(members['audit/OBSERVER_SELECTION.json']) == '2b56c784f61e12e43d475549a6900ec0137b590f1afe8203d273d6686893240f'
    for case in ('first', 'follow-on', 'interrupted'):
        prefix = 'demonstration/' + case + '/'
        names = ['trust.json', 'request.json', 'stdout.bin', 'stderr.bin',
                 'report.json', 'input.json', 'basis.json', 'START.json',
                 'budget.json', 'local-purpose.json', 'NOTICE.json']
        companions = sorted((audit / prefix / 'ledger').glob('reservation-*.*.json'))
        assert len(companions) == 3
        assert {p.name.rsplit('.', 2)[1] for p in companions} == {'binding', 'acquisition', 'observation'}
        names += ['ledger/' + p.name for p in companions]
        for name in names:
            b = regular(audit, prefix + name)
            assert not re.search(pattern, b)
            assert b'PRIVATE KEY-----' not in b
            members['audit/' + prefix + name] = b
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / 'child-measured-public-receipts.zip'
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_STORED) as z:
        for name, b in sorted(members.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o444) << 16
            z.writestr(info, b)
    inventory = {
        'schema': 'run.child-measured-public-transport/1',
        'state': 'PUBLIC_RECEIPTS_ONLY_SOURCE_AND_HOSTED_CLOSURE_BLOCKED',
        'archive_sha256': sha(archive.read_bytes()),
        'archive_bytes': archive.stat().st_size,
        'members': {n: {'sha256': sha(b), 'bytes': len(b)} for n, b in sorted(members.items())},
        'original_source_manifest_sha256': sha(manifest_bytes),
        'original_source_verified_members': len(manifest['files']),
        'original_source_verified_bytes': total,
        'excluded_source_literal_signing_key_members': literal_keys,
        'source_included': False, 'mutable_stores_included': False,
        'authority_granted': False, 'automatic_retry': False,
        'full_lifecycle_cost': 'UNKNOWN',
    }
    with (args.output / 'TRANSPORT.json').open('x') as f:
        json.dump(inventory, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({k: v for k, v in inventory.items() if k not in ('members', 'excluded_source_literal_signing_key_members')}))


if __name__ == '__main__':
    main()
