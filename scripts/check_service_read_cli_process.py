#!/usr/bin/env python3
"""Stdlib-only public CLI consumer. Never imports Run or accesses spending keys.

Usage: python check_service_read_cli_process.py VFY RECEIPT_REQUEST RECONCILE_REQUEST
The retained subject must be fresh disposable synthetic producer evidence.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

executable=sys.argv[1]
for command,path,expected in [('verify-service-receipt',sys.argv[2],'VERIFIED_HISTORICAL_REVIEW_RECEIPT'),
                              ('reconcile-service-repair',sys.argv[3],'OBSERVED_CANDIDATE')]:
    raw=Path(path).read_bytes();digest=hashlib.sha256(raw).hexdigest()
    def call(payload,selected):
        return subprocess.run([executable,command,'--request-sha256',selected],input=payload,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
    result=call(raw,digest)
    assert result.returncode==0,(command,result.returncode,result.stderr,result.stdout)
    assert len(result.stdout)<=65536 and result.stderr==b''
    value=json.loads(result.stdout)
    assert value['state']=='READ_COMPLETED' and value['result']['state']==expected
    assert value['authority_granted'] is False and value['automatic_retry'] is False
    wrong=call(raw,'f'*64);assert wrong.returncode==12 and json.loads(wrong.stdout)['state']=='REFUSED'
    bad=call(b'{}',hashlib.sha256(b'{}').hexdigest());assert bad.returncode==12
    print(json.dumps(dict(command=command,executable=executable,exit=result.returncode,
        result_state=value['result']['state'],wrong_selection_exit=wrong.returncode,
        wrong_schema_exit=bad.returncode,stdout_bytes=len(result.stdout)),sort_keys=True))
