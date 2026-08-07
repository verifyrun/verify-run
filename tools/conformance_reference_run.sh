#!/bin/sh
# One command: install a published runtime from production PyPI into a clean environment, run the
# conformance suite against it, and check every digest in the kit.
#
#   sh tools/conformance_reference_run.sh [output-directory] [implementation-version]
#
# It installs from PyPI and then runs offline. It never imports this repository's source: the
# implementation under test is the published distribution, exactly as an outside reader would get
# it. Run it from anywhere; it locates the kit relative to itself.
#
# **Which implementation is tested.** By default, the version this checkout declares in
# `pyproject.toml` — so on a released `main` the obvious command tests the current release, and the
# default can never silently fall behind a release again. Name any published version explicitly to
# test it instead:
#
#   sh tools/conformance_reference_run.sh out 0.1.0a2     # positional
#   VERSION=0.1.0a1 sh tools/conformance_reference_run.sh # or by environment
#
# **This is not the frozen-tag reproduction.** Two different questions:
#
#   * *does the current runtime pass the profile?* — this script on current `main`;
#   * *does the claim frozen at `conformance-v1.0.0` still reproduce?* — check that tag out and run
#     the script there, where both the kit and the reference implementation it names are frozen:
#       git checkout conformance-v1.0.0 && sh tools/conformance_reference_run.sh
#
# Neither answer substitutes for the other, and the profile's own
# `reference_implementation.version` is a frozen historical statement, not a requirement that
# conformance be tested with that version.
#
# The interpreter is $PYTHON when set, else python3. It must satisfy the distribution's declared
# floor, which is read from `pyproject.toml` rather than restated here.
#
#   PYTHON=/opt/python3.11/bin/python3 sh tools/conformance_reference_run.sh
set -eu

KIT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-$(mktemp -d)}
PYTHON=${PYTHON:-python3}

# The version under test, and where it comes from. Deriving the default from this checkout's own
# declared version is what keeps the obvious command honest: a released `main` tests its own
# release, with no separate constant to remember to move.
DECLARED=$(sed -n 's/^version = "\(.*\)"/\1/p' "$KIT_ROOT/pyproject.toml" | head -1)
if [ -n "${2:-}" ]; then VERSION=$2; ORIGIN="named on the command line"
elif [ -n "${VERSION:-}" ]; then ORIGIN="named by \$VERSION"
else VERSION=$DECLARED; ORIGIN="this checkout's declared version"; fi
if [ -z "$VERSION" ]; then
    echo "preflight: could not read a version from $KIT_ROOT/pyproject.toml, and none was given." >&2
    echo "           Name one: sh tools/conformance_reference_run.sh <output-dir> <version>" >&2
    exit 2
fi
PIN="verify-run==$VERSION"

# The floor comes from the distribution's own metadata. Restating it here is how a tooling constant
# and a package requirement drift apart.
FLOOR=$(sed -n 's/^requires-python = ">=\(.*\)"/\1/p' "$KIT_ROOT/pyproject.toml" | head -1)
FLOOR=${FLOOR:-3.11}

# Preflight before anything is created. `pip install verify-run` on an interpreter below the
# distribution's floor fails with a resolver message that reads as "this package does not exist",
# which sends people looking for the wrong problem.
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "preflight: no interpreter named '$PYTHON'. Set PYTHON=/path/to/python3." >&2
    exit 2
fi
if ! "$PYTHON" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= tuple(int(p) for p in '$FLOOR'.split('.')[:2]) else 1)"; then
    echo "preflight: $PIN requires Python $FLOOR or newer; '$PYTHON' is $("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')." >&2
    echo "           Re-run with PYTHON=/path/to/python$FLOOR sh tools/conformance_reference_run.sh" >&2
    exit 2
fi

mkdir -p "$OUT"
# Absolute from here on. Step 2 changes directory, and a relative output path resolved against the
# new one silently pointed at nothing.
OUT=$(CDPATH= cd -- "$OUT" && pwd)
echo "kit    : $KIT_ROOT"
echo "python : $($PYTHON -c 'import sys; print(sys.executable, "%d.%d.%d" % sys.version_info[:3])')"
echo "tested : $PIN   ($ORIGIN)"
echo "output : $OUT"
echo

echo "1. clean environment, production PyPI, no cache"
"$PYTHON" -m venv "$OUT/env"
# A version that is not published is a clear sentence, not a resolver dump. It is the expected
# answer on an unreleased checkout whose version has been bumped but not yet uploaded.
if ! "$OUT/env/bin/python" -m pip install --quiet --no-cache-dir "$PIN" 2>"$OUT/pip.err"; then
    echo "preflight: $PIN could not be installed from PyPI." >&2
    # pip's own upgrade notice is the loudest thing on that stream and says nothing about this.
    grep -E '^(ERROR|WARNING: )' "$OUT/pip.err" | head -3 | sed 's/^/           /' >&2
    echo "           Published versions are listed at https://pypi.org/project/verify-run/#history" >&2
    echo "           Name a published one: sh tools/conformance_reference_run.sh <output-dir> <version>" >&2
    exit 2
fi
"$OUT/env/bin/python" -m pip show verify-run | grep -E '^(Name|Version|Location)'
"$OUT/env/bin/vfy" --version

echo
echo "2. the implementation under test is the installed distribution, not this source tree"
cd "$OUT"
# The kit root is passed in rather than pattern-matched. The previous check looked for one
# developer's directory name, so on any other machine it asserted nothing at all.
"$OUT/env/bin/python" - "$KIT_ROOT" <<'PY'
import pathlib, sys, vfy
kit = pathlib.Path(sys.argv[1]).resolve()
here = pathlib.Path(vfy.__file__).resolve()
assert "site-packages" in here.parts, "not an installed distribution: %s" % here
assert kit not in here.parents, "the kit's own source tree is the implementation: %s" % here
for entry in sys.path:
    if not entry:
        continue
    resolved = pathlib.Path(entry).resolve()
    assert resolved != kit and kit not in resolved.parents, "the kit is on sys.path: %s" % entry
# An editable install points at a checkout through a .pth or a finder, and would pass the
# site-packages test above while running someone's working tree.
for path in pathlib.Path(here.parents[1]).glob("__editable__*verify*"):
    raise AssertionError("an editable install of verify-run is active: %s" % path)
print("   ", here)
print("    installed distribution, no kit source on sys.path, no editable install")
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
