#!/bin/sh
# One command: install the published runtime from production PyPI into a clean environment, run the
# conformance suite against it, and check every digest in the kit.
#
#   sh tools/conformance_reference_run.sh [output-directory]
#
# It installs from PyPI and then runs offline. It never imports this repository's source: the
# implementation under test is the published distribution, exactly as an outside reader would get
# it. Run it from anywhere; it locates the kit relative to itself.
set -eu

KIT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-$(mktemp -d)}
PIN="verify-run==0.1.0a2"

mkdir -p "$OUT"
echo "kit    : $KIT_ROOT"
echo "output : $OUT"
echo

echo "1. clean environment, production PyPI, no cache"
python3 -m venv "$OUT/env"
"$OUT/env/bin/python" -m pip install --quiet --no-cache-dir "$PIN"
"$OUT/env/bin/python" -m pip show verify-run | grep -E '^(Name|Version|Location)'
"$OUT/env/bin/vfy" --version

echo
echo "2. the implementation under test is the installed distribution, not this source tree"
cd "$OUT"
"$OUT/env/bin/python" - <<'PY'
import sys, vfy
assert "site-packages" in vfy.__file__, vfy.__file__
assert not any("code/verify" in entry for entry in sys.path), "a source tree is on sys.path"
print("   ", vfy.__file__)
PY

echo
echo "3. conformance suite"
"$OUT/env/bin/python" "$KIT_ROOT/tools/run_conformance.py" \
    --profile "$KIT_ROOT/conformance/decision-replay-v1/profile.json" \
    --adapter "$OUT/env/bin/python $KIT_ROOT/tools/conformance_adapter.py" \
    --out "$OUT/result.json"

echo
echo "4. result validates against the declared schema, and every kit digest still matches"
"$OUT/env/bin/python" - "$KIT_ROOT" "$OUT/result.json" <<'PY'
import hashlib, json, pathlib, sys
kit_root, result_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
schema = json.loads((kit_root / "conformance/decision-replay-v1/result.schema.json")
                    .read_text(encoding="utf-8"))
result = json.loads(result_path.read_text(encoding="utf-8"))
missing = [name for name in schema["required"] if name not in result]
assert not missing, "result is missing required fields: %s" % missing
assert result["overall"] in ("PASS", "FAIL", "INCOMPLETE")
record = json.loads((kit_root / "conformance/decision-replay-v1/MANIFEST.json")
                    .read_text(encoding="utf-8"))
bad = [entry["file"] for entry in record["files"]
       if hashlib.sha256((kit_root / entry["file"]).read_bytes()).hexdigest() != entry["sha256"]]
assert not bad, "kit files changed since the manifest was written: %s" % bad
print("    result fields  : complete")
print("    kit digests    : %d files, all matching" % len(record["files"]))
print("    overall        : %s" % result["overall"])
print("    profile        : %s %s" % (result["profile_id"], result["profile_version"]))
print("    fixtures       : %s" % result["fixture_manifest_sha256"])
print("    implementation : %s %s" % (result["implementation"], result["implementation_version"]))
assert result["overall"] == "PASS", "the reference implementation did not pass"
PY

echo
echo "PASS — result written to $OUT/result.json"
