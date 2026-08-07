"""Check one conformance result document, and check the kit that produced it.

Two questions, asked together because either answer alone is misleading:

  * is the result document complete and PASS?
  * is the kit that produced it still the kit that was published?

A PASS against a modified fixture set is not a pass against this profile, so the digests recorded
in `MANIFEST.json` are re-checked here rather than trusted.

    python3 tools/check_conformance_result.py result.json [--kit <root>] [--allow INCOMPLETE]

Exit status: 0 the result is acceptable, 1 it is not, 2 this checker could not run.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

MINIMUM_PYTHON = (3, 8)
KIT_ROOT = Path(__file__).resolve().parent.parent
PROFILE_DIR = "conformance/decision-replay-v1"

EXIT_OK, EXIT_UNACCEPTABLE, EXIT_CHECKER_ERROR = 0, 1, 2


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    running = tuple(sys.version_info[:2])
    if running < MINIMUM_PYTHON:
        print("checker error: needs Python %d.%d or newer, running on %d.%d"
              % (MINIMUM_PYTHON + running), file=sys.stderr)
        return EXIT_CHECKER_ERROR

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("result", help="the result document to check")
    parser.add_argument("--kit", default=str(KIT_ROOT), help="repository root holding the kit")
    parser.add_argument("--allow", action="append", default=[], metavar="VERDICT",
                        help="an additional acceptable `overall` value; repeatable")
    options = parser.parse_args()

    kit = Path(options.kit).resolve()
    try:
        schema = load(kit / PROFILE_DIR / "result.schema.json")
        record = load(kit / PROFILE_DIR / "MANIFEST.json")
        result = load(options.result)
    except (OSError, ValueError) as failure:
        print("checker error: %s" % failure, file=sys.stderr)
        return EXIT_CHECKER_ERROR

    problems = []
    missing = [name for name in schema["required"] if name not in result]
    if missing:
        problems.append("the result is missing required fields: %s" % ", ".join(missing))
    unknown = sorted(set(result) - set(schema["properties"]))
    if unknown and schema.get("additionalProperties") is False:
        problems.append("the result carries fields the schema does not declare: %s"
                        % ", ".join(unknown))

    changed = [entry["file"] for entry in record["files"]
               if not (kit / entry["file"]).is_file()
               or digest(kit / entry["file"]) != entry["sha256"]]
    if changed:
        problems.append("kit files differ from MANIFEST.json, so this result is not against the "
                        "published kit: %s" % ", ".join(changed))
    if result.get("manifest_problems"):
        problems.append("the fixture manifest did not check out: %s"
                        % "; ".join(result["manifest_problems"]))

    acceptable = {"PASS"} | set(options.allow)
    if result.get("overall") not in acceptable:
        problems.append("overall is %r and this check accepts %s"
                        % (result.get("overall"), ", ".join(sorted(acceptable))))

    for entry in result.get("fixtures", []):
        if entry["status"] != "PASS":
            problems.append("%s %s: %s" % (entry["status"], entry["fixture_id"],
                                           "; ".join(entry["problems"])[:160]))

    print("result fields  : %s" % ("complete" if not missing else "incomplete"))
    print("kit digests    : %d files, %s"
          % (len(record["files"]), "all matching" if not changed else "%d changed" % len(changed)))
    print("overall        : %s" % result.get("overall"))
    print("profile        : %s %s" % (result.get("profile_id"), result.get("profile_version")))
    print("fixtures       : %s" % result.get("fixture_manifest_sha256"))
    print("implementation : %s %s" % (result.get("implementation"),
                                      result.get("implementation_version")))
    if problems:
        print("\nnot acceptable:", file=sys.stderr)
        for problem in problems:
            print("  %s" % problem, file=sys.stderr)
        return EXIT_UNACCEPTABLE
    print("\nacceptable")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
