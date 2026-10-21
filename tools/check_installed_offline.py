"""Off-checkout installed-entry controls; no receipt execution or trust enrollment."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module-sha256', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='vfy-offline-install-') as directory:
        root = Path(directory)
        probe = subprocess.run([sys.executable, '-I', '-c',
            'import hashlib,json;from pathlib import Path;from vfy import offline_adoption_consumer as c;'
            'p=Path(c.__file__).resolve();print(json.dumps(dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())))'],
            cwd=root, capture_output=True, text=True, check=True)
        selected = json.loads(probe.stdout)
        if 'site-packages' not in Path(selected['path']).parts or selected['sha256'] != args.module_sha256:
            raise ValueError('Installed module does not match independently selected source bytes')
        command = [sys.executable, '-I', '-m', 'vfy.offline_adoption_consumer']
        subprocess.run(command + ['--help'], cwd=root, capture_output=True, check=True)
        policy = root/'policy.json'; policy.write_bytes(b'{}')
        bundle = root/'bundle.json'; bundle.write_bytes(b'{}')
        common = ['--bundle', str(bundle), '--policy', str(policy), '--expected-final-plan-sha256', 'a'*64]
        controls = {}
        for name, pin in [('wrong_policy_digest', '0'*64), ('missing_original_inputs', hashlib.sha256(policy.read_bytes()).hexdigest())]:
            result = subprocess.run(command + common + ['--policy-sha256', pin], cwd=root, capture_output=True, text=True)
            value = json.loads(result.stdout)
            if result.returncode != 12 or value.get('state') != 'REFUSED' or value.get('result') is not None:
                raise ValueError('Installed refusal control did not refuse: '+name)
            controls[name] = True
        print(json.dumps(dict(state='INSTALLED_ENTRY_CONTROLS_PASSED', module=selected, controls=controls,
            accepted_receipt_verified=False, effects_executed=False)))


if __name__ == '__main__':
    main()
