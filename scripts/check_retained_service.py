#!/usr/bin/env python3
"""Read-only installed checker for an independently selected exported owner context.

No executor imports, reconstruction from keys, pool mutations, or source recapture.
Output is a derived observation, not a new owner-signed receipt or semantic truth.
"""
import argparse
import json
from pathlib import Path
import sys

p=argparse.ArgumentParser(description=__doc__)
for flag in ('installed-root','attempt-root','context','context-sha256','snapshot-sha256','output'):
    p.add_argument('--'+flag,required=True)
p.add_argument('--minimum-revision',type=int,required=True)
args=p.parse_args()
installed=Path(args.installed_root).resolve(strict=True)
sys.path.insert(0,str(installed))
from vfy import child_ledger as m, service_tests as tests
if not Path(tests.__file__).resolve().is_relative_to(installed):raise SystemExit('Wrong checker origin')
context_raw=m.read_file(Path(args.context))
m.need(m.sha(context_raw)==args.context_sha256,'Select exact independently supplied owner context')
c=m.load.load_json_bytes(context_raw)
m.need(set(c)=={'pool_root','config_hex','owner_trust','child_trust','observer','head_hex','policy_hex'},
       'This CLI accepts the common-predecessor Engineer context export only')
head=bytes.fromhex(c['head_hex'])
m.need(m.load.load_json_bytes(head)['body']['entries']==[], 'Use explicit per-request trust mapping for a nonempty predecessor')
root=Path(args.attempt_root)
snapshot=m.read_file(root/'ACCOUNTING_RESULT.json')
pool=tests.load_service_pool(snapshot_bytes=snapshot,expected_snapshot_sha256=args.snapshot_sha256,
    expected_pool_root=c['pool_root'],expected_config_bytes=bytes.fromhex(c['config_hex']),
    owner_trust=c['owner_trust'],child_trust=c['child_trust'],selected_observer=c['observer'],
    predecessor_snapshot_bytes=head,policy_bytes=bytes.fromhex(c['policy_hex']),
    expected_child_trusts={},minimum_revision=args.minimum_revision)
runner=m.read_file(root/'runner'/'verify_service_runner.py')
checker=tests.TestObservationChecker(pool,selection_bytes=m.read_file(root/'TEST_SELECTION.json'),
    requirements_bytes=m.read_file(root/'FROZEN_REQUIREMENTS.json'),runner_bytes=runner,
    limits=dict(input_bytes=16777216,cases=4096,requirements=1024,retained_bytes=33554432))
observed=checker.check(preview_bytes=m.read_file(root/'PREVIEW.json'),start_bytes=m.read_file(root/'START.json'),
    result_bytes=m.read_file(root/'RESULT.json'),stdout_bytes=m.read_file(root/'stdout.bin'),
    stderr_bytes=m.read_file(root/'stderr.bin'),accounting_snapshot_bytes=snapshot,
    request_sha256=m.sha(m.read_file(root/'TEST_REQUEST.json')))
output=Path(args.output)
m.need(output.is_absolute() and output==output.resolve(),'Canonical output path required')
m.fresh(output,m.raw(observed))
print(json.dumps({'output':str(output),'output_sha256':m.sha(m.raw(observed)),
    'state':observed['state'],'reason_codes':observed['reason_codes'],
    'reported_cases':observed['costs']['case_events'],'checker_identity':tests.identity(),
    'context_sha256':args.context_sha256,'snapshot_sha256':args.snapshot_sha256,
    'scope':'derived scoped process observation; no new signed receipt, no semantic truth'},sort_keys=True))
