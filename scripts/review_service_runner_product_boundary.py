"""Static independent review prototype only; does not import or execute subject code."""
import ast
import hashlib
import json
from pathlib import Path
import runpy
import tempfile

ROOT=Path('/private/tmp/verify-engineer-continuation-20261013')
RUNNER='engineer/change/service_test_runner.py'
OBSERVER='engineer/change/service_observation.py'
RUNNER_SHA='b4e9cd392f852701b734ebf44df958383f47d270b46ae19730a572fb86b43b19'
OBSERVER_SHA='1adb9a7b29368ef52f359599c92f8041c8ae4b7d545bd5c9976d64e609c36ad4'
IMPORTS={('django.test.runner','DiscoverRunner'),('django.conf','settings'),
         ('django.utils.module_loading','import_string')}

def reviewed_runner_import(root,path,node):
    # Proposed narrow predicate for Root; read the audited root, not this script's checkout.
    try:
        return (path.relative_to(root).as_posix()==RUNNER
            and isinstance(node,ast.ImportFrom) and node.level==0
            and len(node.names)==1 and node.names[0].asname is None
            and (node.module,node.names[0].name) in IMPORTS
            and hashlib.sha256(path.read_bytes()).hexdigest()==RUNNER_SHA
            and hashlib.sha256((root/OBSERVER).read_bytes()).hexdigest()==OBSERVER_SHA)
    except (OSError,ValueError):
        return False

def django_nodes(raw):
    return [n for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.ImportFrom)
            and (n.module or '').startswith('django')]

raw=(ROOT/RUNNER).read_bytes();observer=(ROOT/OBSERVER).read_bytes()
assert hashlib.sha256(raw).hexdigest()==RUNNER_SHA
assert hashlib.sha256(observer).hexdigest()==OBSERVER_SHA
nodes=django_nodes(raw);assert len(nodes)==3
assert all(reviewed_runner_import(ROOT,ROOT/RUNNER,n) for n in nodes)
gate=runpy.run_path(str(ROOT/'scripts/audit_product_experience.py'))
findings=gate['law_4_no_transport_in_the_new_surface'](ROOT)
assert len(findings)==3 and all(RUNNER in f and 'django' in f for f in findings)
controls={}
with tempfile.TemporaryDirectory(prefix='run-runner-static-review-') as tmp:
    root=Path(tmp);rp=root/RUNNER;op=root/OBSERVER
    rp.parent.mkdir(parents=True);rp.write_bytes(raw);op.write_bytes(observer)
    assert all(reviewed_runner_import(root,rp,n) for n in nodes)
    rp.write_bytes(raw+b'\n# changed\n')
    controls['changed_runner_bytes']=not any(reviewed_runner_import(root,rp,n) for n in nodes)
    rp.write_bytes(raw);op.write_bytes(observer+b'\n# changed\n')
    controls['changed_observer_bytes']=not any(reviewed_runner_import(root,rp,n) for n in nodes)
    op.write_bytes(observer)
    for rel in ('engineer/surface/runner.py','engineer/change/another_runner.py','engineer/assist/service_test_runner.py'):
        p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        controls['relocated_'+rel]=not any(reviewed_runner_import(root,p,n) for n in nodes)
    for statement in ('import django','from django.http import HttpResponse',
                      'from django.test.runner import DiscoverRunner as Alias',
                      'import urllib.request','import sqlite3'):
        n=ast.parse(statement).body[0]
        controls[statement]=not reviewed_runner_import(root,rp,n)
    rp.write_bytes(raw+b'\nimport django.http\n')
    controls['added_transport_changes_pin']=not any(reviewed_runner_import(root,rp,n) for n in nodes)
assert all(controls.values())
print(json.dumps(dict(disposition='ADMISSIBLE_EXACT_CONFINED_TEST_ADAPTER_ONLY',
    runner_sha256=RUNNER_SHA,observer_sha256=OBSERVER_SHA,existing_findings=findings,
    exact_imports=sorted(IMPORTS),prototype_negative_controls=controls,
    engineer_edited=False,subject_imported=False,service_executed=False,
    gate_integrated=False,semantic_acceptance='UNESTABLISHED'),indent=2))
