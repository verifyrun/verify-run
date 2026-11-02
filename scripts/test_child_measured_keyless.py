"""Separate-process transport controls using copied bytes only; no signing/effects."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

checker, archive = map(Path, sys.argv[1:])
root = Path(tempfile.mkdtemp(prefix='keyless-transport-controls-'))
sha = lambda b: hashlib.sha256(b).hexdigest()
def check(path, digest):
    p = subprocess.run([sys.executable, '-I', '-B', str(checker), str(path), '--sha256', digest],
                       capture_output=True, timeout=30)
    result=json.loads(p.stdout)
    assert p.returncode==2 and result['state']=='UNKNOWN',result
    return result
results={'wrong_archive_digest':check(archive,'0'*64)}
with zipfile.ZipFile(archive) as z:
    items=[(info,z.read(info)) for info in z.infolist()]
for mode in ('source_tamper','missing_member','duplicate_member'):
    target=root/(mode+'.zip')
    with zipfile.ZipFile(target,'x') as z:
        for info,raw in items:
            if mode=='missing_member' and info.filename=='audit/OBSERVER_SELECTION.json':continue
            if mode=='source_tamper' and info.filename=='source/vfy/child_ledger.py':raw+=b'\n'
            z.writestr(info,raw)
        if mode=='duplicate_member':z.writestr(*items[0])
    results[mode]=check(target,sha(target.read_bytes()))
print(json.dumps(results,sort_keys=True,indent=2))
