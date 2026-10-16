"""Add five exact keyless verifier modules to the immutable 44-member transport."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile
from check_child_measured_keyless import MODULES, SOURCE_MANIFEST
from package_child_measured_public_receipts import regular

OLD_ARCHIVE = '24451a7929d6143c11ef7322f72f7b80c0890a47c6f7f1699d3a895464fae30f'

def sha(raw):return hashlib.sha256(raw).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=Path);ap.add_argument('old_archive',type=Path);ap.add_argument('output',type=Path)
    a=ap.parse_args()
    assert sha(a.old_archive.read_bytes()) == OLD_ARCHIVE
    with zipfile.ZipFile(a.old_archive) as z:
        assert len(z.infolist()) == len(set(z.namelist())) == 44
        members={n:z.read(n) for n in z.namelist()}
    assert sha(members['audit/SOURCE_MANIFEST.json']) == SOURCE_MANIFEST
    manifest=json.loads(members['audit/SOURCE_MANIFEST.json'])
    # Verify the entire original without copying keys or modifying any byte.
    excluded=[]
    for name,digest in manifest['files'].items():
        raw=regular(a.source,name)
        assert sha(raw)==digest,name
        if re.search(rb'"private_key_hex"\s*:\s*"[0-9a-fA-F]{64}"',raw):excluded.append(name)
    for name in MODULES:
        raw=regular(a.source,'vfy/'+name)
        assert b'PRIVATE KEY-----' not in raw
        assert not re.search(rb'"private_key_hex"\s*:\s*"[0-9a-fA-F]{64}"',raw)
        members['source/vfy/'+name]=raw
    a.output.mkdir(parents=True,exist_ok=False)
    path=a.output/'child-measured-keyless.zip'
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_STORED) as z:
        for name,raw in sorted(members.items()):
            info=zipfile.ZipInfo(name,(1980,1,1,0,0,0));info.create_system=3
            info.external_attr=(stat.S_IFREG|0o444)<<16;z.writestr(info,raw)
    result={'schema':'run.child-measured-keyless-transport/1','archive_sha256':sha(path.read_bytes()),
            'archive_bytes':path.stat().st_size,'predecessor_archive_sha256':OLD_ARCHIVE,
            'source_manifest_sha256':SOURCE_MANIFEST,'original_verified_members':len(manifest['files']),
            'source_members_included':5,'source_complete':False,'excluded_key_fixture_members':excluded,
            'members':{n:{'sha256':sha(b),'bytes':len(b)} for n,b in sorted(members.items())},
            'authority_granted':False,'automatic_retry':False,'mutable_custody_included':False}
    (a.output/'TRANSPORT.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('members','excluded_key_fixture_members')}))

if __name__=='__main__':main()
