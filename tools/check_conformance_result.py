"""Check one conformance result document **against** the kit that was supposed to produce it.

Three questions, and the third is the one that makes the first two mean anything:

  * is the result document complete and PASS?
  * is the kit still the kit that was published?
  * **is this result a result of that kit?**

Asking the first two alone is how a forgery gets through, and it did: a document with
`fixtures: []`, every count zero, `overall: PASS` and a fixture-manifest digest of sixty-four
zeroes was called acceptable, because the kit was checked against *itself* and the result was
checked against *the schema*, and the two checks never met. Nothing tied the verdict to the
fixtures it claimed to have run.

So no field of the result is believed on its own account. The manifest and profile digests must
equal what this kit actually hashes to, the fixture ids must be exactly the set the kit declares
— none missing, none extra, none twice — and `counts` and `overall` are **recomputed from the
fixture rows** and compared, never read. A PASS over an empty fixture set is not a weak pass; it
is not a pass at all.

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
# Read from the profile rather than hardcoded, so a kit that moves its fixtures
# cannot be checked against a manifest this script guessed the name of.
PROFILE_NAME = "profile.json"

EXIT_OK, EXIT_UNACCEPTABLE, EXIT_CHECKER_ERROR = 0, 1, 2


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def kit_manifest_path(kit):
    """Where this kit's own profile says its fixture manifest lives."""
    profile_path = kit / PROFILE_DIR / PROFILE_NAME
    return profile_path, (profile_path.parent / load(profile_path)["fixture_manifest"]).resolve()


def kit_fixture_ids(manifest_path):
    """The fixture ids this kit actually declares, read from the kit and not from any result."""
    return sorted(entry["fixture_id"] for entry in load(manifest_path)["fixtures"])


def bind_to_kit(kit, record, result):
    """Require this result to be a result *of this kit*, and its verdict to follow its rows.

    Everything here is a relation between two documents. A single document, however well formed,
    cannot establish any of it — which is exactly why the forged PASS passed.
    """
    problems = []
    try:
        profile_path, manifest_path = kit_manifest_path(kit)
    except (OSError, ValueError, KeyError) as failure:
        return ["this kit's profile could not be read: %s" % failure]

    # 1. The digests the result *claims* must be the digests this kit *has*.
    for field, path, what in (("fixture_manifest_sha256", manifest_path, "fixture manifest"),
                              ("profile_sha256", profile_path, "profile")):
        if not path.is_file():
            problems.append("this kit has no %s at %s" % (what, path))
            continue
        actual = digest(path)
        claimed = result.get(field)
        if claimed != actual:
            problems.append(
                "the result names %s %r but this kit's %s hashes to %s, so the result is not "
                "against this kit" % (field, claimed, what, actual))

    # 2. The profile it names must be the profile this kit publishes.
    for field, key in (("profile_id", "profile_id"), ("profile_version", "profile_version")):
        if result.get(field) != record.get(key):
            problems.append("the result names %s %r and this kit publishes %r"
                            % (field, result.get(field), record.get(key)))

    # 3. The fixture set must be exactly the kit's: none missing, none extra, none twice.
    try:
        declared = kit_fixture_ids(manifest_path)
    except (OSError, ValueError, KeyError, TypeError) as failure:
        problems.append("this kit's fixture manifest could not be read: %s" % failure)
        return problems

    rows = result.get("fixtures")
    if not isinstance(rows, list):
        problems.append("the result has no fixtures array")
        return problems
    reported = [entry.get("fixture_id") for entry in rows]
    seen = sorted(set(reported))
    duplicates = sorted({name for name in reported if reported.count(name) > 1})
    if duplicates:
        problems.append("these fixtures are reported more than once: %s" % ", ".join(duplicates))
    missing_fixtures = [name for name in declared if name not in seen]
    extra = [name for name in seen if name not in declared]
    if missing_fixtures:
        problems.append("the result does not report %d of this kit's fixtures: %s"
                        % (len(missing_fixtures), ", ".join(missing_fixtures[:8])))
    if extra:
        problems.append("the result reports fixtures this kit does not declare: %s"
                        % ", ".join(extra[:8]))
    if not rows:
        # Stated separately because it is the forgery this check exists for, and "0 of 30
        # reported" is a less direct sentence than the one a reader needs.
        problems.append("a result over zero fixtures is not a pass against anything")

    # 4. The counts and the verdict are recomputed, never read. A summary field is a claim about
    #    rows that are right there; believing the claim instead of the rows is the whole defect.
    statuses = [entry.get("status") for entry in rows]
    recomputed = {"total": len(rows),
                  "required": len([e for e in rows if e.get("required")]),
                  "passed": statuses.count("PASS"),
                  "failed": statuses.count("FAIL"),
                  "skipped": statuses.count("SKIP")}
    claimed_counts = result.get("counts")
    if not isinstance(claimed_counts, dict):
        problems.append("the result has no counts object")
    else:
        for name, value in sorted(recomputed.items()):
            if claimed_counts.get(name) != value:
                problems.append("counts.%s says %r and the fixture rows say %d"
                                % (name, claimed_counts.get(name), value))
    verdict = ("FAIL" if recomputed["failed"] else
               "INCOMPLETE" if (recomputed["skipped"] or result.get("manifest_problems")
                                or not rows) else "PASS")
    if result.get("overall") != verdict:
        problems.append("overall says %r and the fixture rows say %s"
                        % (result.get("overall"), verdict))
    return problems


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

    problems.extend(bind_to_kit(kit, record, result))

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
