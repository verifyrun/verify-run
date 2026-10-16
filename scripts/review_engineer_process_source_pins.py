#!/usr/bin/env python3
"""Read-only exact-source gate experiment. Never imports/executes Engineer adapters."""
import ast,hashlib,json,runpy
from pathlib import Path
root=Path('/private/tmp/verify-engineer-continuation-20261013')
pins={
'engineer/change/pinned_backend/application.py':'6160f5de81814c8834aa993357c4a4f956ef75f3e8ec0e38ae510a63b4b859fc',
'engineer/cli.py':'db2462fd87e8674e0c596adbe510658bfef11c8b84b238adc10780b90fb19692',
'engineer/change/service_accounting_client.py':'7876e521ef4bce939149f1f581542d02c9233952e68bbf4448ec0f247e2d459d',
'engineer/change/service_observation.py':'1adb9a7b29368ef52f359599c92f8041c8ae4b7d545bd5c9976d64e609c36ad4',
'engineer/experience/service_read_cli.py':'c171cc39791bf2f3bfc136599259194bff74a8c4e7c4eae26485eccd0478f172'}
paths=[root/n for n in pins]+[root/'scripts/audit_assisted_construction.py']
def hashes():return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
before=hashes();assert all(before[n]==h for n,h in pins.items())
gate=runpy.run_path(str(paths[-1]),run_name='_read_only_review_gate')
baseline=gate['audit'](root)
table=gate['REVIEWED_PROCESS_SOURCES']
for name,digest in pins.items():table[name]=(digest,'Independent exact-source local-adapter boundary review; no assist or network waiver.')
proposed=gate['audit'](root)
matched={name:gate['_reviewed_process_source'](root,name) for name in pins}
changed_refuses={}
for name,digest in pins.items():
    table[name]=('0'*64,'deliberate wrong identity control')
    changed_refuses[name]=not gate['_reviewed_process_source'](root,name)
    table[name]=(digest,'review')
assist='engineer/assist/provider.py'
table[assist]=(hashlib.sha256((root/assist).read_bytes()).hexdigest(),'deliberate prohibited path control')
assist_refused=not gate['_reviewed_process_source'](root,assist)
assert all(matched.values()) and all(changed_refuses.values()) and assist_refused
assert hashes()==before
calls={}
for name in pins:
    tree=ast.parse((root/name).read_text())
    calls[name]=[dict(line=n.lineno,expression=ast.unparse(n.func)) for n in ast.walk(tree)
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess']
print(json.dumps(dict(scope='READ_ONLY_AST_AUDIT_IN_MEMORY_PIN_EXPERIMENT_NOT_HOSTED_CI',
    hashes=before,baseline_findings=baseline,proposed_exact_pin_findings=proposed,
    source_hashes_match=matched,wrong_hash_refused=changed_refuses,assist_always_excluded=assist_refused,
    subprocess_call_sites=calls,source_bytes_unchanged=True,adapters_executed=False),indent=2))
