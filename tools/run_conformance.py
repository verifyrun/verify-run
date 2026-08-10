"""Vendor-neutral runner for the Decision Replay Conformance Profile.

The runner knows three things: a profile, a fixture manifest, and how to speak to an adapter. It
does not know `verify-run`, and it must not: the oracle is the expected observation recorded in
the manifest, never whatever some implementation happens to return. An implementation is measured
against the fixtures; the fixtures are not measured against an implementation.

    python3 tools/run_conformance.py \
        --profile conformance/decision-replay-v1/profile.json \
        --adapter "python3 tools/conformance_adapter.py" \
        --out result.json

`--adapter` is split with shell-like quoting rules. A path containing spaces is safer given as
repeated `--adapter-arg`, one token each, which is never split:

    python3 tools/run_conformance.py --profile ... --out result.json \
        --adapter-arg /opt/My Tools/python3 --adapter-arg /opt/My Tools/adapter.py

Exit status: 0 PASS, 1 FAIL, 2 INCOMPLETE, 3 runner error. PASS is a self-reported test result.
It is not certification, and nothing here issues one.

**A run that could not be conducted is INCOMPLETE.** An adapter that will not start, times out,
or does not speak the protocol is a fact about the harness; reporting it as FAIL would accuse an
implementation of failing a test it was never actually given.

**A fixture that *was* conducted and disagreed is FAIL, and stays FAIL.** The verdict follows the
strongest settled negative fact:

    any conducted fixture failed          -> FAIL
    the adapter emitted key material      -> FAIL
    anything could not be conducted       -> INCOMPLETE
    otherwise                             -> PASS

Absence of knowledge never erases knowledge already established. Reading INCOMPLETE first meant
one timed-out adapter call could report "nothing was measured" over twenty-nine measured failures.
"""

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

RUNNER_VERSION = "1.1.0"

# The runner's own floor, which is not the floor of any implementation it measures. Nothing here
# uses syntax an older interpreter would fail to parse, so this reports the problem in a sentence
# instead of dying inside `subprocess.run` on a keyword it does not have.
MINIMUM_PYTHON = (3, 8)

EXIT_PASS, EXIT_FAIL, EXIT_INCOMPLETE, EXIT_RUNNER_ERROR = 0, 1, 2, 3

MAX_ADAPTER_OUTPUT = 1 << 20          # one mebibyte; an adapter that floods is a failing adapter
DEFAULT_ADAPTER_TIMEOUT_SECONDS = 180

# Anything resembling private key material must never reach a result document.
# One observation, one name, one weight — see the verdict precedence below.
LEAKED_SECRET = "adapter_leaked_secret_material"

SECRET_MARKERS = ("PRIVATE KEY", "private_key", "BEGIN OPENSSH", "-----BEGIN")

# Problems that mean the run could not be conducted: the adapter would not start, gave up, or did
# not speak the protocol. None of them is an observation about replay, so none may become a
# verdict about an implementation. A leaked secret is deliberately NOT in this set — that is a
# real failure of the thing under test, and the profile cares about it.
SETUP_PROBLEMS = ("adapter_timeout", "adapter_output_unreadable", "adapter_output_too_large",
                  "adapter_not_runnable", "adapter_error")


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    return digest_bytes(Path(path).read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class RunnerError(Exception):
    """The run could not be conducted. This is never a verdict about an implementation."""


def preflight(version_info=None):
    """Return a clear sentence if this interpreter cannot run the runner, else None."""
    running = tuple((version_info or sys.version_info)[:2])
    if running >= MINIMUM_PYTHON:
        return None
    return ("this runner needs Python %d.%d or newer and is running on %d.%d; "
            "re-run it with a newer interpreter, for example "
            "`python3.11 tools/run_conformance.py ...`. The implementation under test may "
            "require a different version — that is the adapter's business, not the runner's."
            % (MINIMUM_PYTHON + running))


def resolve_adapter(adapter, adapter_arg):
    """Return the adapter argv, or say plainly why there is not one.

    Resolved before a single fixture runs, because "the adapter is not where you said it was" is
    a sentence, and thirty identical `adapter_not_runnable` lines are not.
    """
    if adapter_arg:
        if adapter:
            raise RunnerError("give --adapter or --adapter-arg, not both")
        command = list(adapter_arg)
    elif adapter:
        command = shlex.split(adapter)
    else:
        raise RunnerError("no adapter was given; use --adapter or repeated --adapter-arg")
    if not command:
        raise RunnerError("the adapter command is empty")
    program = command[0]
    if not (shutil.which(program) or Path(program).is_file()):
        raise RunnerError(
            "the adapter command is not runnable: %r is not on PATH and is not a file. "
            "If the path contains spaces, pass it as repeated --adapter-arg, which is never "
            "split." % program)
    return command


def setup_problem(text):
    """Whether one recorded problem means the run could not be conducted."""
    return any(text == marker or text.startswith(marker + ":") for marker in SETUP_PROBLEMS)


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
        return None, LEAKED_SECRET
    try:
        envelope = json.loads(text)
    except ValueError:
        return None, "adapter_output_unreadable"
    if isinstance(envelope, dict) and envelope.get("adapter_error"):
        # The adapter said, in the protocol rather than by dying, that it could not conduct this
        # call: no implementation, wrong interpreter, unusable bundle. Not a refusal to replay.
        return envelope, "adapter_error:%s" % envelope["adapter_error"]
    return envelope, None


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
    parser.add_argument("--adapter", default="",
                        help="command that speaks the adapter protocol, split shell-style")
    parser.add_argument("--adapter-arg", action="append", default=[], metavar="TOKEN",
                        help="one argv token of the adapter command; repeatable and never split. "
                             "A token beginning with a dash needs the attached form, "
                             "--adapter-arg=--flag, or it is read as an option of this runner.")
    parser.add_argument("--out", required=True, help="where to write the result document")
    parser.add_argument("--implementation", default="", help="label for the report")
    parser.add_argument("--adapter-timeout", type=int,
                        default=DEFAULT_ADAPTER_TIMEOUT_SECONDS,
                        help="seconds each adapter call may take before it is a failure")
    options = parser.parse_args()

    unusable = preflight()
    if unusable:
        print("runner error: " + unusable, file=sys.stderr)
        return EXIT_RUNNER_ERROR

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        profile_path = Path(options.profile).resolve()
        profile = load_json(profile_path)
        base = profile_path.parent
        manifest_path = (base / profile["fixture_manifest"]).resolve()
        manifest = load_json(manifest_path)
        fixtures_root = manifest_path.parent

        manifest_problems = check_manifest(fixtures_root, manifest)
        command = resolve_adapter(options.adapter, options.adapter_arg)

        # Everything that means "this run could not be conducted". Kept apart from the fixture
        # verdicts all the way to the exit status, because they answer different questions.
        setup_notes = []
        security_failures = []
        results = []

        capabilities, capability_error = call_adapter(
            command, {"operation": "capabilities", "profile": profile["profile_id"]},
            options.adapter_timeout)
        if capability_error:
            capabilities = {"error": capability_error}
            if capability_error == LEAKED_SECRET:
                # The same observation must carry the same weight wherever it is made. Emitting
                # private key material during the capabilities probe was previously recorded as a
                # setup problem and reported INCOMPLETE, while the identical emission during a
                # fixture was FAIL — so an adapter could downgrade its own leak by leaking sooner.
                security_failures.append(
                    "the adapter emitted private key material answering the capabilities request")
            else:
                setup_notes.append(
                    "the adapter did not answer the capabilities request (%s), so no fixture was "
                    "run" % capability_error)
        else:
            accepted = capabilities.get("accepted_profiles")
            if isinstance(accepted, list) and profile["profile_id"] not in accepted:
                setup_notes.append(
                    "the adapter declares profiles %s and this kit is %r, so no fixture was run"
                    % (", ".join(repr(name) for name in accepted) or "none",
                       profile["profile_id"]))

        for fixture in ([] if setup_notes
                        else sorted(manifest["fixtures"], key=lambda f: f["fixture_id"])):
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

        # A fixture whose only problems are transport problems was never actually put to the
        # implementation. It is not a failed test; it is a test that did not happen.
        security_failures += ["%s: %s" % (r["fixture_id"], LEAKED_SECRET) for r in results
                              if LEAKED_SECRET in r["problems"]]
        not_conducted = [r for r in results if r["status"] == "ERROR" and r["problems"]
                         and all(setup_problem(p) for p in r["problems"])]
        setup_notes += ["%s: %s" % (r["fixture_id"], "; ".join(r["problems"]))
                        for r in not_conducted]

        required = [r for r in results if r["required"]]
        failed = [r for r in results if r["status"] in ("FAIL", "ERROR")
                  and r not in not_conducted]
        skipped = [r for r in required if r["status"] == "SKIPPED"]
        covered = sorted({requirement for fixture in manifest["fixtures"]
                          for requirement in fixture["requirements"]})

        # Verdict precedence, strongest settled negative fact first. A fixture that was actually
        # conducted and disagreed is knowledge; a fixture that could not be conducted is the
        # absence of knowledge, and absence must never erase what was already established.
        #
        # This ordering was inverted: `INCOMPLETE` was tested before `FAIL`, so twenty-nine
        # conducted failures plus one adapter timeout reported INCOMPLETE — "nothing was
        # measured" — while the result document itself carried twenty-nine measured failures. An
        # implementation could have obtained that by making one fixture's adapter call time out.
        if failed:
            overall = "FAIL"
        elif security_failures:
            overall = "FAIL"
        elif manifest_problems or setup_notes or skipped:
            overall = "INCOMPLETE"
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
            "adapter": options.adapter or " ".join(shlex.quote(t) for t in command),
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
        if setup_notes:
            # Said in a sentence, on stderr, because this is not a verdict about anything.
            print("\nthe run could not be conducted, so nothing was measured:", file=sys.stderr)
            for note in setup_notes[:10]:
                print("  %s" % note, file=sys.stderr)
            if len(setup_notes) > 10:
                print("  ... and %d more" % (len(setup_notes) - 10), file=sys.stderr)
            print("INCOMPLETE is not FAIL: no implementation was measured against this profile.",
                  file=sys.stderr)
        return {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL,
                "INCOMPLETE": EXIT_INCOMPLETE}[overall]
    except RunnerError as failure:
        print("runner error: %s" % failure, file=sys.stderr)
        return EXIT_RUNNER_ERROR


if __name__ == "__main__":
    sys.exit(main())
