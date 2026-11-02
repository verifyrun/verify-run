"""Run installed repair/consumer tests with a measured wheel and explicit import custody.

Invoke using the clean environment's python -I -B. This harness never installs or edits a package.
Full frozen-source tests and installed public CLI/conformance checks remain separate evidence.
"""
import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import sys
import unittest
import zipfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_wheel(wheel, expected, site):
    if sha(wheel) != expected:
        raise RuntimeError("wheel identity mismatch")
    checked = {}
    with zipfile.ZipFile(wheel) as archive:
        record = next(n for n in archive.namelist() if n.endswith('.dist-info/RECORD'))
        for name, digest, size in csv.reader(io.StringIO(archive.read(record).decode())):
            if not digest:
                continue
            if not digest.startswith('sha256='):
                raise RuntimeError("unsupported record digest")
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts:
                raise RuntimeError("unsupported record path")
            body = (site / relative).read_bytes()
            observed = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip('=')
            if observed != digest.split('=', 1)[1] or len(body) != int(size):
                raise RuntimeError("installed file differs: " + name)
            checked[name] = hashlib.sha256(body).hexdigest()
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', required=True)
    parser.add_argument('--wheel-sha256', required=True)
    parser.add_argument('--tests-root', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if Path(args.out).exists():
        parser.error('evidence already exists')
    if not sys.flags.isolated:
        parser.error('use python -I to exclude checkout imports during runtime loading')
    import vfy  # loaded before making test sources reachable
    package = Path(vfy.__file__).resolve().parent
    if 'site-packages' not in package.parts:
        raise RuntimeError('vfy did not load from clean installed site-packages')
    before = verify_wheel(args.wheel, args.wheel_sha256, package.parent)
    root = Path(args.tests_root).resolve()
    # Test fixtures/source inspections use frozen input; runtime package search remains installed.
    for name, digest in before.items():
        if name.startswith('vfy/') and '/_schemas/' not in name and '/_templates/' not in name:
            source = root / name
            if source.exists() and sha(source) != digest:
                raise RuntimeError('frozen runtime source differs from wheel: ' + name)
    sys.path.insert(0, str(root))
    names = ['tests.test_authorization', 'tests.test_receipt', 'tests.test_protocol_repairs',
             'tests.test_execution_report', 'tests.test_consumer_interface_probe']
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    imported = {}
    for name, module in sorted(sys.modules.items()):
        if name != 'vfy' and not name.startswith('vfy.'):
            continue
        location = getattr(module, '__file__', None)
        if location:
            path = Path(location).resolve()
            if not path.is_relative_to(package):
                raise RuntimeError('runtime import escaped installed package: ' + str(path))
            imported[name] = {'path': str(path), 'sha256': sha(path)}
    after = verify_wheel(args.wheel, args.wheel_sha256, package.parent)
    if before != after:
        raise RuntimeError('installed subject changed during tests')
    evidence = {'schema': 'installed-successor-verification/1',
                'wheel_sha256': args.wheel_sha256, 'wheel': str(Path(args.wheel).resolve()),
                'runtime_version': importlib.metadata.version('verify-run'),
                'python': sys.version, 'executable': sys.executable,
                'tests': result.testsRun, 'skips': len(result.skipped),
                'failures': len(result.failures), 'errors': len(result.errors),
                'result': 'PASS' if result.wasSuccessful() else 'FAIL',
                'suite_names': names, 'installed_files_before': before,
                'installed_files_unchanged_after': True, 'runtime_imports': imported,
                'test_source_root': str(root),
                'scope': 'Installed runtime regressions; source inspections use frozen matching source. No whole-application adapter claim.'}
    with open(args.out, 'x') as output:
        json.dump(evidence, output, indent=2, sort_keys=True)
        output.write('\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
