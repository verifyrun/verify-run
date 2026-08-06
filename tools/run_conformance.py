"""Vendor-neutral runner for the Decision Replay Conformance Profile.

The runner knows three things: a profile, a fixture manifest, and how to speak to an adapter. It
does not know `verify-run`, and it must not: the oracle is the expected observation recorded in
the manifest, never whatever some implementation happens to return. An implementation is measured
against the fixtures; the fixtures are not measured against an implementation.

    python3 tools/run_conformance.py \
        --profile conformance/decision-replay-v1/profile.json \
        --adapter "python3 tools/conformance_adapter.py" \
        --out result.json

Exit status: 0 PASS, 1 FAIL, 2 INCOMPLETE, 3 runner error. PASS is a self-reported test result.
It is not certification, and nothing here issues one.
"""

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

RUNNER_VERSION = "1.0.0"

EXIT_PASS, EXIT_FAIL, EXIT_INCOMPLETE, EXIT_RUNNER_ERROR = 0, 1, 2, 3

MAX_ADAPTER_OUTPUT = 1 << 20          # one mebibyte; an adapter that floods is a failing adapter
DEFAULT_ADAPTER_TIMEOUT_SECONDS = 180

# Anything resembling private key material must never reach a result document.
SECRET_MARKERS = ("PRIVATE KEY", "private_key", "BEGIN OPENSSH", "-----BEGIN")


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    return digest_bytes(Path(path).read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class RunnerError(Exception):
    """The run could not be conducted. This is never a verdict about an implementation."""


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as failure:
        raise RunnerError("could not read %s: %s" % (path, failure))


def check_manifest(root, manifest):
    """Every listed fixture exists at its recorded digest, and no fixture is present but unlisted."""
    problems = []
    listed = set()
    for fixture in manifest["fixtures"]:
        directory = root / fixture["bundle"]
        for name, recorded in sorted(fixture["files"].items()):
            path = directory / name
            listed.add(path.resolve())
            if not path.is_file():
                problems.append("listed but absent: %s/%s" % (fixture["bundle"], name))
            elif digest_file(path) != recorded:
                problems.append("digest mismatch: %s/%s" % (fixture["bundle"], name))
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.name.startswith("_") and path.name != "manifest.json":
            if path.resolve() not in listed:
                problems.append("present but unlisted: %s" % path.relative_to(root))
    return problems


def call_adapter(command, request, timeout_seconds=DEFAULT_ADAPTER_TIMEOUT_SECONDS):
    """Run the adapter once, bounded, with no shell and an explicit environment."""
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    try:
        completed = subprocess.run(
            command, input=canonical(request).encode("utf-8"),
            capture_output=True, timeout=timeout_seconds, env=environment)
    except subprocess.TimeoutExpired:
        return None, "adapter_timeout"
    except OSError as failure:
        return None, "adapter_not_runnable:%s" % type(failure).__name__
    if len(completed.stdout) > MAX_ADAPTER_OUTPUT:
        return None, "adapter_output_too_large"
    text = completed.stdout.decode("utf-8", "replace")
    if any(marker in text for marker in SECRET_MARKERS):
        return None, "adapter_leaked_secret_material"
    try:
        return json.loads(text), None
    except ValueError:
        return None, "adapter_output_unreadable"


def compare(expected, observed):
    """Compare only the observations the fixture declares. Silence is not agreement."""
    problems = []
    for field, wanted in sorted(expected.items()):
        if field in ("conformance", "stage", "reference_reason_code", "note"):
            continue
        if field.endswith("_any_of"):
            # Membership, not equality: the profile constrains which category a refusal may carry
            # without dictating the order in which an implementation checks.
            actual_field = field[: -len("_any_of")]
            if observed.get(actual_field) not in wanted:
                problems.append("%s: expected one of %r, observed %r"
                                % (actual_field, wanted, observed.get(actual_field)))
            continue
        if field not in observed:
            problems.append("adapter did not report %r" % field)
            continue
        if observed[field] != wanted:
            problems.append("%s: expected %r, observed %r" % (field, wanted, observed[field]))
    return problems


def evaluate_fixture(fixture, observed, adapter_error):
    """Return (status, problems). The manifest is the oracle."""
    if adapter_error:
        return "ERROR", [adapter_error]
    expected = fixture["expected"]
    accepted = observed.get("accepted")
    if expected["conformance"] == "accepted":
        if accepted is not True:
            return "FAIL", ["fixture must be accepted; adapter reported accepted=%r, "
                            "error_category=%r" % (accepted, observed.get("error_category"))]
        return ("PASS", []) if not compare(expected, observed) else \
            ("FAIL", compare(expected, observed))
    # refused
    if accepted is not False:
        return "FAIL", ["fixture must be refused; adapter accepted it (terminal=%r)"
                        % observed.get("terminal")]
    problems = compare(expected, observed)
    return ("PASS", []) if not problems else ("FAIL", problems)


def main():
    parser = argparse.ArgumentParser(description="Run a Decision Replay conformance suite.")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--adapter", required=True,
                        help="command that speaks the adapter protocol")
    parser.add_argument("--out", required=True, help="where to write the result document")
    parser.add_argument("--implementation", default="", help="label for the report")
    parser.add_argument("--adapter-timeout", type=int,
                        default=DEFAULT_ADAPTER_TIMEOUT_SECONDS,
                        help="seconds each adapter call may take before it is a failure")
    options = parser.parse_args()

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        profile_path = Path(options.profile).resolve()
        profile = load_json(profile_path)
        base = profile_path.parent
        manifest_path = (base / profile["fixture_manifest"]).resolve()
        manifest = load_json(manifest_path)
        fixtures_root = manifest_path.parent

        manifest_problems = check_manifest(fixtures_root, manifest)
        command = shlex.split(options.adapter)

        capabilities, capability_error = call_adapter(
            command, {"operation": "capabilities", "profile": profile["profile_id"]},
            options.adapter_timeout)
        if capability_error:
            capabilities = {"error": capability_error}

        results = []
        for fixture in sorted(manifest["fixtures"], key=lambda f: f["fixture_id"]):
            observed, adapter_error = call_adapter(
                command, {"operation": fixture["operation"],
                          "bundle": str(fixtures_root / fixture["bundle"]),
                          "profile": profile["profile_id"]}, options.adapter_timeout)
            status, problems = evaluate_fixture(fixture, observed or {}, adapter_error)
            results.append({
                "fixture_id": fixture["fixture_id"],
                "requirements": fixture["requirements"],
                "required": fixture.get("required", True),
                "status": status,
                "problems": problems,
                "observed_terminal": (observed or {}).get("terminal"),
                "observed_error_category": (observed or {}).get("error_category"),
                "implementation_reason": (observed or {}).get("implementation_reason"),
                "raw": (observed or {}).get("raw"),
            })

        required = [r for r in results if r["required"]]
        failed = [r for r in results if r["status"] in ("FAIL", "ERROR")]
        skipped = [r for r in required if r["status"] == "SKIPPED"]
        covered = sorted({requirement for fixture in manifest["fixtures"]
                          for requirement in fixture["requirements"]})

        if manifest_problems:
            overall = "INCOMPLETE"
        elif failed:
            overall = "FAIL"
        elif skipped or len(required) != len(manifest["fixtures"]):
            overall = "INCOMPLETE" if skipped else "PASS"
        else:
            overall = "PASS"

        by_requirement = {}
        for entry in results:
            for requirement in entry["requirements"]:
                current = by_requirement.get(requirement, "PASS")
                if entry["status"] != "PASS" or current != "PASS":
                    by_requirement[requirement] = "FAIL" if entry["status"] != "PASS" else current
                by_requirement.setdefault(requirement, "PASS")

        document = {
            "profile_id": profile["profile_id"],
            "profile_version": profile["profile_version"],
            "runner_version": RUNNER_VERSION,
            "implementation": options.implementation
            or (capabilities.get("implementation", {}) or {}).get("name", "unknown"),
            "implementation_version":
                (capabilities.get("implementation", {}) or {}).get("version", "unknown"),
            "adapter": options.adapter,
            "adapter_capabilities": capabilities,
            "environment": {"python": sys.version.split()[0], "platform": sys.platform},
            "started_at": started,
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "fixture_manifest_sha256": digest_file(manifest_path),
            "profile_sha256": digest_file(profile_path),
            "manifest_problems": manifest_problems,
            "requirement_status": dict(sorted(by_requirement.items())),
            "requirements_covered": covered,
            "fixtures": results,
            "counts": {"total": len(results), "required": len(required),
                       "passed": len([r for r in results if r["status"] == "PASS"]),
                       "failed": len(failed), "skipped": len(skipped)},
            "overall": overall,
            "declaration": "This is a self-reported test result against the named profile and "
                           "fixture manifest. It is not certification, accreditation, or approval "
                           "by any third party, and it makes none of the claims the profile "
                           "explicitly disclaims.",
        }
        Path(options.out).write_text(canonical(document) + "\n", encoding="utf-8")
        print("%s  %d/%d fixtures passed  profile=%s  manifest=%s"
              % (overall, document["counts"]["passed"], document["counts"]["total"],
                 profile["profile_id"], document["fixture_manifest_sha256"][:16]))
        for entry in results:
            if entry["status"] != "PASS":
                print("  %-8s %-42s %s" % (entry["status"], entry["fixture_id"],
                                           "; ".join(entry["problems"])[:110]))
        for problem in manifest_problems:
            print("  MANIFEST %s" % problem)
        return {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL,
                "INCOMPLETE": EXIT_INCOMPLETE}[overall]
    except RunnerError as failure:
        print("runner error: %s" % failure, file=sys.stderr)
        return EXIT_RUNNER_ERROR


if __name__ == "__main__":
    sys.exit(main())
