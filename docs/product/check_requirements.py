"""Definition coverage only; never authorizes release."""
import argparse
import json
from pathlib import Path
EXPECTED = ["W01","W02","W03","W04","W05","W06","W07","W08","W09","W10","W11","W12","W13","W14","W15","W16","W17","W18","W19","W20","W21","W22","W23","W24","W25","W26","W27","W28","D01","ENT01","ENT02","ENT03","ENT04","ENT05","ENT06","ENT07","ENT08","ENT09","ENT10","ENT11","ENT12","ECO-AGENTS","ECO-SOURCES","ECO-INTENT","ECO-AUTHORITY","ECO-RECEIPTS","ECO-CHECKS","ECO-SITE","BIZ1","BIZ2","BIZ3","BIZ4","BIZ5","RES1","RES2","RES3","RES4","RES5","RES6","DESIGN-HANDOFF","PROJECT-FINISH","HEAD01","HEAD02","HEAD03","HEAD04","FEED01","FEED02","TEST-A","TEST-B","VALUE01","RESEARCH-UNLOCK","COMPARE-HISTORY","ECO-BIND"]
p = argparse.ArgumentParser()
p.add_argument('--release', action='store_true')
p.add_argument('--register', default=str(Path(__file__).with_name('product-requirements.json')))
a = p.parse_args()
d = json.loads(Path(a.register).read_text())
items = d['requirements']
ids = [x.get('id') for x in items]
def require(ok, message):
    if not ok:
        raise SystemExit(message)
require(len(ids) == len(set(ids)), 'Duplicate requirement ID')
require(set(ids) == set(EXPECTED), 'Missing or unexpected requirement IDs; reconcile full scope explicitly')
for r in items:
    for key in ('id','title','owner','acceptance','dependencies','sheet_row','definition_status','trace_status'):
        require(bool(r.get(key)), f'{r.get("id")}: missing {key}')
print(f'{len(items)} definitions covered; implementation and evidence not certified')
if a.release:
    raise SystemExit('RELEASE HELD: structural checks cannot verify independent receipts or authorize release')
