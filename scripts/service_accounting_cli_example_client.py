#!/usr/bin/env python3
"""Stdlib-only fresh synthetic CLI consumer. Never executes a service or retries.
Run ONLY with a newly prepared disposable example selection; used profiles refuse.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


def sha(raw):return hashlib.sha256(raw).hexdigest()
def raw(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def embedded(data):return dict(base64=base64.b64encode(data).decode(),sha256=sha(data))

def selected(entry):
    data=Path(entry['path']).read_bytes()
    assert len(data)<=16*1024*1024 and sha(data)==entry['sha256']
    return data

def durable(path,data):
    with path.open('xb') as out:
        out.write(data);out.flush();os.fsync(out.fileno())
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def main():
    executable,selection_path,selection_hash=sys.argv[1:]
    selection_raw=Path(selection_path).read_bytes();assert sha(selection_raw)==selection_hash
    selection=json.loads(selection_raw)
    assert selection['schema']=='vfy.service-session-synthetic-example/1'
    profile=selected(selection['profile'])
    request=selected(selection['request']);preview=selected(selection['preview'])
    approval=selected(selection['approval'])
    q=json.loads(request);root=Path(q['attempt_root']);assert not (root/'START.json').exists()
    logs=Path(selection['transcript']);logs.mkdir()
    lock=os.open(root/'ACCOUNTING.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    command=[executable,'service-accounting-session','--profile',selection['profile']['path'],
             '--profile-sha256',sha(profile)]
    proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True)
    deadline=time.monotonic()+15
    def receive(number):
        data=bytearray()
        while not data.endswith(b'\n'):
            remaining=deadline-time.monotonic();assert remaining>0
            assert select.select([proc.stdout],[],[],remaining)[0]
            part=os.read(proc.stdout.fileno(),min(65536,8*1024*1024+1-len(data)))
            assert part;data.extend(part);assert len(data)<=8*1024*1024
        durable(logs/(str(number)+'-response.json'),bytes(data))
        r=json.loads(data)
        assert r['schema']=='vfy.service-accounting-response/1' and r['profile_sha256']==sha(profile)
        assert r['sequence']==number and r['error'] is None and r['authority_granted'] is False
        assert r['automatic_retry'] is False and r['full_cost']=='UNKNOWN'
        return r
    try:
        opening=receive(0);assert opening['state']=='OPEN' and opening['request_sha256'] is None
        session=opening['session_id']
        def send(number,op,inputs,state):
            frame=raw(dict(schema='vfy.service-accounting-frame/1',session_id=session,
                sequence=number,operation=op,inputs={k:embedded(v) for k,v in inputs.items()}))+b'\n'
            durable(logs/(str(number)+'-request.json'),frame)
            proc.stdin.write(frame);proc.stdin.flush()
            reply=receive(number)
            assert reply['session_id']==session and reply['request_sha256']==sha(frame) and reply['state']==state
            return reply
        admission=send(1,'ADMIT',dict(request=request,preview=preview,approval=approval),'ADMITTED')
        durable(root/'ACCOUNTING_ADMISSION.json',raw(admission['record']))
        start=raw(dict(preview=sha(preview)));durable(root/'START.json',start)
        consumed=send(2,'CONSUME',dict(start=start),'CONSUMED')
        durable(root/'ACCOUNTING_CONSUMPTION.json',raw(consumed['record']))
        # No service is launched: synthetic no-launch result must stay UNKNOWN.
        result=raw(dict(preview=sha(preview),state='LAUNCH_FAILED',exit=None,
            limit_failure='SYNTHETIC_NO_EXECUTION',stdout_sha256=sha(b''),stderr_sha256=sha(b'')))
        for name,data in (('RESULT.json',result),('stdout.bin',b''),('stderr.bin',b'')):durable(root/name,data)
        settled=send(3,'SETTLE',dict(result=result,stdout=b'',stderr=b''),'SETTLED')
        assert settled['record']['body']['entries'][-1]['state']=='UNKNOWN'
        durable(root/'ACCOUNTING_RESULT.json',raw(settled['record']))
        proc.stdin.close();assert proc.wait(timeout=5)==0
        summary=dict(command=command,profile_sha256=sha(profile),attempt_root=str(root),
            sequence=['OPEN','ADMITTED','CONSUMED','SETTLED'],entry_state='UNKNOWN',
            service_executed=False,retry=False,transcript=str(logs))
        durable(logs/'SUMMARY.json',raw(summary)+b'\n')
        print(json.dumps(summary,indent=2))
    finally:
        if proc.poll() is None:proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()
        if not proc.stdin.closed:proc.stdin.close()
        os.close(lock)

if __name__=='__main__':main()
