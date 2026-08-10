"""Build the candidate artifact, run the conformance kit against **that artifact**, record both.

The dependency direction is the whole point of this tool.

It used to run the other way. `pyproject` declared a version, a release gate required the README to
say `Current reference result: PASS, 30/30 fixtures, verify-run <that version>`, and the reference
runner installed `verify-run==<that version>` from PyPI. So bumping to an unpublished version made
the gate *demand* a PASS sentence for an artifact that did not exist and had never been tested, and
the only way to go green was to write the claim first. A version label was deciding what a result
said.

Here the artifact comes first:

    build the wheel
    → hash it
    → install that exact file into a clean environment
    → run the kit against it
    → check the result against the kit
    → write a record binding artifact identity to result identity

Nothing in that chain can be satisfied by a sentence. The human-facing claim is generated from the
record afterwards, and `tests/test_release.py` checks the README against the record rather than
against `__version__`.

    python3 tools/build_reference_result.py [--out <dir>] [--keep]

Writes `conformance/reference-result.json`. Needs `build` and network access for the clean
environment's own dependencies; it never fetches the implementation under test, which is the local
artifact by construction.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROFILE = REPO / "conformance" / "decision-replay-v1" / "profile.json"
RECORD = REPO / "conformance" / "reference-result.json"
RECORD_VERSION = 1

# Reproducible wheel bytes, so re-running this tool on unchanged source produces the same digest.
SOURCE_DATE_EPOCH = "1735689600"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, **keywords):
    done = subprocess.run(argv, capture_output=True, text=True, **keywords)
    if done.returncode != 0:
        raise SystemExit("failed: %s\n%s\n%s" % (" ".join(map(str, argv)),
                                                 done.stdout[-2000:], done.stderr[-2000:]))
    return done


def installed_files_match_wheel(wheel, environment):
    """Check that the installed distribution's files are the wheel's files.

    A version banner is a string the candidate printed. This is the strongest binding Python
    packaging actually substantiates, so it is the one made — and it is stated as exactly what it
    is, not as attestation of a running process.

    The wheel's `RECORD` lists a SHA-256 for each member it installs. pip **rewrites** RECORD on
    install (console scripts, `.pyc`, relocated paths), so comparing the two files byte for byte
    proves nothing; comparing each declared member's digest to the installed file's digest does.

    Returns (checked, matched, missing). Any shortfall means the environment does not hold the
    bytes this wheel declared.
    """
    site = next(Path(environment).glob("lib/python*/site-packages"), None)
    if site is None:
        return 0, 0, ["no site-packages in the environment"]
    with zipfile.ZipFile(wheel) as archive:
        record_name = next((n for n in archive.namelist() if n.endswith(".dist-info/RECORD")), None)
        if record_name is None:
            return 0, 0, ["the wheel declares no RECORD"]
        rows = archive.read(record_name).decode("utf-8").splitlines()
    checked = matched = 0
    missing = []
    for row in rows:
        parts = row.rsplit(",", 2)
        if len(parts) != 3 or not parts[1].startswith("sha256="):
            continue                      # RECORD's own line carries no digest, by construction
        relative, declared = parts[0], parts[1].split("=", 1)[1]
        installed = site / relative
        if not installed.is_file():
            missing.append("absent: " + relative)
            continue
        checked += 1
        # RECORD uses urlsafe base64 without padding, not hex.
        actual = base64.urlsafe_b64encode(
            hashlib.sha256(installed.read_bytes()).digest()).rstrip(b"=").decode("ascii")
        if actual == declared:
            matched += 1
        else:
            missing.append("differs: " + relative)
    return checked, matched, missing


def declared_version():
    for line in (REPO / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit("pyproject.toml declares no version")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", help="working directory; a temporary one by default")
    parser.add_argument("--keep", action="store_true", help="do not remove the working directory")
    options = parser.parse_args()

    room = Path(options.out).resolve() if options.out else Path(tempfile.mkdtemp(prefix="ref-"))
    room.mkdir(parents=True, exist_ok=True)
    try:
        environment = dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH)

        print("1. build the candidate wheel from this tree")
        build_dir = room / "dist"
        run([sys.executable, "-m", "build", "--wheel", "--outdir", str(build_dir), str(REPO)],
            env=environment)
        wheels = sorted(build_dir.glob("*.whl"))
        if len(wheels) != 1:
            raise SystemExit("expected exactly one wheel, found %r" % [p.name for p in wheels])
        wheel = wheels[0]
        wheel_digest = digest(wheel)
        print("   %s\n   sha256 %s" % (wheel.name, wheel_digest))

        print("2. install that exact file into a clean environment")
        environment_root = room / "env"
        run([sys.executable, "-m", "venv", str(environment_root)])
        python = environment_root / "bin" / "python"
        vfy = environment_root / "bin" / "vfy"
        run([str(python), "-m", "pip", "install", "--quiet", str(wheel)])
        banner = run([str(vfy), "--version"]).stdout.strip()
        print("   %s (self-reported)" % banner)
        checked, matched, missing = installed_files_match_wheel(wheel, environment_root)
        if missing or not checked or matched != checked:
            raise SystemExit(
                "the environment does not hold this wheel's files (%d/%d matched): %s"
                % (matched, checked, "; ".join(missing[:5])))
        print("   %d of %d declared files match the wheel's own digests" % (matched, checked))

        print("3. run the kit against it")
        result_path = room / "result.json"
        run([sys.executable, str(REPO / "tools" / "run_conformance.py"),
             "--profile", str(PROFILE),
             "--adapter-arg", str(python),
             "--adapter-arg", str(REPO / "tools" / "conformance_adapter.py"),
             "--adapter-arg=--vfy", "--adapter-arg", str(vfy),
             "--out", str(result_path)])
        result = json.loads(result_path.read_text(encoding="utf-8"))
        print("   %s  %d/%d" % (result["overall"], result["counts"]["passed"],
                                result["counts"]["total"]))

        print("4. check the result against the kit")
        run([sys.executable, str(REPO / "tools" / "check_conformance_result.py"),
             str(result_path)])

        if result["overall"] != "PASS":
            raise SystemExit("the run did not pass, so there is no reference result to record")
        if result["implementation_version"] != declared_version():
            raise SystemExit(
                "the artifact reports %r and this tree declares %r"
                % (result["implementation_version"], declared_version()))

        print("5. record artifact identity beside result identity")
        record = {
            "record_version": RECORD_VERSION,
            "note": ("Generated by tools/build_reference_result.py. The artifact was built and "
                     "hashed before the run, and the run used that file. Do not edit by hand: a "
                     "claim in this file is only worth what produced it."),
            "implementation": {
                "distribution": "verify-run",
                "version": result["implementation_version"],
                "artifact": {"kind": "wheel", "filename": wheel.name, "sha256": wheel_digest},
                "self_reported_banner": banner,
                # Measured, not attested: every file the wheel declared with a digest is present
                # in the environment the run used, with that digest.
                "installed_files_verified": {"checked": checked, "matched": matched},
            },
            "profile": {"id": result["profile_id"], "version": result["profile_version"],
                        "sha256": result["profile_sha256"]},
            "fixtures": {"manifest_sha256": result["fixture_manifest_sha256"],
                         "ids": sorted(entry["fixture_id"] for entry in result["fixtures"])},
            "counts": result["counts"],
            "overall": result["overall"],
            "result_sha256": digest(result_path),
            "published": False,
        }
        RECORD.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("   %s" % RECORD.relative_to(REPO))
        print("\nreference claim, derived rather than authored:")
        print("  %s" % claim_sentence(record))
        if not record["published"]:
            print("\n  `published` is false: this names a candidate artifact by digest, not a\n"
                  "  release coordinate. The release step sets it once those bytes are published.")
    finally:
        if not options.keep and options.out is None:
            shutil.rmtree(room, ignore_errors=True)
    return 0


def claim_sentence(record):
    """The one human-facing sentence, generated from the record. Nothing else may author it."""
    return ("Current reference result: **%s**, %d/%d fixtures, `verify-run %s`, fixture manifest\n"
            "`%s…`." % (record["overall"], record["counts"]["passed"], record["counts"]["total"],
                        record["implementation"]["version"],
                        record["fixtures"]["manifest_sha256"][:16]))


if __name__ == "__main__":
    sys.exit(main())
