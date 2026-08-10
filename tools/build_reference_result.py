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
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
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
        print("   %s" % banner)

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
