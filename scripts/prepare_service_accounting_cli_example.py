#!/usr/bin/env python3
"""Run-owner fresh public synthetic setup, not an Engineer import or pool reset.
Uses test fixtures only to prepare a NEW disposable common->service context.
The public CLI itself cannot provision/attach/grant; production setup is not implied.
"""
import hashlib
import json
from pathlib import Path
import sys
checks,installed,client,executable=(Path(p).resolve(strict=True) for p in sys.argv[1:])
sys.path.insert(0,str(checks))
from vfy import service_accounting_cli
assert Path(service_accounting_cli.__file__).resolve().is_relative_to(installed)
from tests.test_service_accounting_cli import SessionTests
fixture=SessionTests();fixture.setUp()
# Retain this new synthetic context for the one-use installed consumer and review.
fixture.f.tmp._finalizer.detach()
root=fixture.f.base
profile=root/'SESSION_PROFILE.json';profile.write_text(json.dumps(fixture.profile,sort_keys=True,separators=(',',':')))
q,preview=fixture.f.action('stdlib-example')
request=root/'REQUEST.json';request.write_text(json.dumps(q,sort_keys=True,separators=(',',':')))
approval=root/'APPROVAL.json';approval.write_bytes(fixture.f.approval(q,preview))
def ref(path):return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
selection=dict(schema='vfy.service-session-synthetic-example/1',profile=ref(profile),request=ref(request),
    approval=ref(approval),preview=ref(Path(q['attempt_root'])/'PREVIEW.json'),transcript=str(root/'transcript'))
path=root/'EXAMPLE_SELECTION.json';path.write_text(json.dumps(selection,indent=2)+'\n')
print(json.dumps(dict(selection=ref(path),command=[sys.executable,'-I','-B',str(client),str(executable),str(path),ref(path)['sha256']],
    scope='FRESH_DISPOSABLE_SYNTHETIC_NO_SERVICE_EXECUTION',key_retention='local development fixture only; exclude seed from backup'),indent=2))
