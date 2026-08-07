#!/bin/sh
# One command: install the published runtime from production PyPI into a clean environment, run the
# conformance suite against it, and check every digest in the kit.
#
#   sh tools/conformance_reference_run.sh [output-directory]
#
# It installs from PyPI and then runs offline. It never imports this repository's source: the
# implementation under test is the published distribution, exactly as an outside reader would get
# it. Run it from anywhere; it locates the kit relative to itself.
#
# The interpreter is $PYTHON when set, else python3. It must satisfy the distribution's own floor:
#
#   PYTHON=/opt/python3.11/bin/python3 sh tools/conformance_reference_run.sh
set -eu

KIT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-$(mktemp -d)}
PIN="verify-run==0.1.0a2"
PYTHON=${PYTHON:-python3}

# Preflight before anything is created. `pip install verify-run` on an interpreter below the
# distribution's floor fails with a resolver message that reads as "this package does not exist",
# which sends people looking for the wrong problem.
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "preflight: no interpreter named '$PYTHON'. Set PYTHON=/path/to/python3." >&2
    exit 2
fi
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)'; then
    echo "preflight: $PIN requires Python 3.11 or newer; '$PYTHON' is $("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')." >&2
    echo "           Re-run with PYTHON=/path/to/python3.11 sh tools/conformance_reference_run.sh" >&2
    exit 2
fi

mkdir -p "$OUT"
# Absolute from here on. Step 2 changes directory, and a relative output path resolved against the
# new one silently pointed at nothing.
OUT=$(CDPATH= cd -- "$OUT" && pwd)
echo "kit    : $KIT_ROOT"
echo "python : $($PYTHON -c 'import sys; print(sys.executable, "%d.%d.%d" % sys.version_info[:3])')"
echo "output : $OUT"
echo

echo "1. clean environment, production PyPI, no cache"
"$PYTHON" -m venv "$OUT/env"
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
# --adapter-arg rather than --adapter: neither of these paths is split, whatever is in them.
"$OUT/env/bin/python" "$KIT_ROOT/tools/run_conformance.py" \
    --profile "$KIT_ROOT/conformance/decision-replay-v1/profile.json" \
    --adapter-arg "$OUT/env/bin/python" \
    --adapter-arg "$KIT_ROOT/tools/conformance_adapter.py" \
    --adapter-arg=--vfy \
    --adapter-arg "$OUT/env/bin/vfy" \
    --out "$OUT/result.json"

echo
echo "4. result validates against the declared schema, and every kit digest still matches"
"$OUT/env/bin/python" "$KIT_ROOT/tools/check_conformance_result.py" \
    --kit "$KIT_ROOT" "$OUT/result.json"

echo
echo "PASS — result written to $OUT/result.json"
