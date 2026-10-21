"""Read-only example consumer for the installed historical-adoption verifier.

The recipient independently selects the installed interpreter, policy digest and
final-plan digest. Neither a bundle nor this example bootstraps trust by itself.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
from vfy import service_adoption_history as history


def bounded(path, limit):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Input exceeds historical verifier bound')
    return raw


def request(bundle_bytes, policy_bytes, policy_sha256, final_plan_sha256):
    if hashlib.sha256(policy_bytes).hexdigest() != policy_sha256:
        raise ValueError('Independently selected policy digest differs')
    bundle = json.loads(bundle_bytes)
    if type(bundle) is not dict or set(bundle) != {'plan', 'preparation', 'intent', 'completion'}:
        raise ValueError('Select only the four original receipt inputs; uploaded policy is not authority')
    value = dict(schema='vfy.verify-service-adoption-history-request/1', inputs=bundle,
                 policy=json.loads(policy_bytes), expected_final_plan_sha256=final_plan_sha256)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if len(raw) > history.MAX_BYTES:
        raise ValueError('Combined request exceeds historical verifier bound')
    return raw


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', required=True, type=Path)
    p.add_argument('--policy', required=True, type=Path)
    p.add_argument('--policy-sha256', required=True)
    p.add_argument('--expected-final-plan-sha256', required=True)
    args = p.parse_args(argv)
    try:
        raw = request(bounded(args.bundle, history.MAX_BYTES), bounded(args.policy, history.MAX_BYTES),
                      args.policy_sha256, args.expected_final_plan_sha256)
    except (OSError, ValueError, TypeError):
        print(json.dumps(dict(state='REFUSED', result=None, **history.FLAGS)))
        return 12
    import sys
    return history.run(request_sha256=hashlib.sha256(raw).hexdigest(), stdin=io.BytesIO(raw), out=sys.stdout)


if __name__ == '__main__':
    raise SystemExit(main())
