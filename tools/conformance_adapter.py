"""Reference conformance adapter for `verify-run`.

The conformance runner is vendor-neutral: it knows bundles and expected observations, and nothing
about any particular implementation. This adapter is the bridge for one implementation — the
released `verify-run` distribution — and it is an example, not part of the normative contract.

It speaks the adapter protocol: one JSON request on stdin, one JSON envelope on stdout.

    request   {"operation": "replay", "bundle": "<directory>"}
    envelope  {"implementation": {...}, "accepted": bool, "terminal": "ALLOW"|null, ...}

Rules this adapter keeps, and which any adapter must keep:

  * it uses only the implementation's public surface — here the `vfy` command line. It imports no
    runtime module, reads no runtime source, and never touches a local checkout.
  * it normalizes transport shape only. It maps this implementation's reason codes onto the
    profile's neutral error categories through the table below, which is declared, small, and
    auditable — and it never collapses one terminal class into another.
  * it decides nothing. Whether an observation conforms is the runner's comparison against the
    fixture manifest, never this adapter's opinion.
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

ADAPTER_VERSION = "1.1.0"

# This implementation's floor, declared by its own package metadata. The runner has a lower floor
# of its own and does not care about this one; an adapter is where an implementation's environment
# requirements belong.
MINIMUM_PYTHON = (3, 11)

# This implementation's reason codes, mapped onto the profile's neutral categories. A mapping is
# declared rather than inferred so an auditor can see exactly what was normalized.
ERROR_CATEGORY = {
    "signature_invalid": "signature_invalid",
    "signature_malformed": "signature_malformed",
    "signing_key_unknown": "key_untrusted",
    "signing_key_retired": "key_untrusted",
    "signing_key_invalid": "key_untrusted",
    "receipt_schema_invalid": "artifact_schema_invalid",
    "candidate_schema_invalid": "artifact_schema_invalid",
    "snapshot_schema_invalid": "artifact_schema_invalid",
    "rulebook_schema_invalid": "artifact_schema_invalid",
    "source_syntax_invalid": "artifact_schema_invalid",
    "canonical_form_invalid": "artifact_noncanonical",
    "store_artifact_noncanonical": "artifact_noncanonical",
    "replay_body_missing": "input_missing",
    "store_record_incomplete": "input_missing",
    "replay_body_mismatch": "binding_mismatch",
    "receipt_binding_mismatch": "binding_mismatch",
    "replay_result_mismatch": "binding_mismatch",
    "store_record_conflict": "binding_mismatch",
    "snapshot_rulebook_mismatch": "binding_mismatch",
    "snapshot_item_missing": "binding_mismatch",
    "authorization_binding_mismatch": "binding_mismatch",
    "authorization_expired": "authorization_not_spendable",
    "authorization_not_yet_valid": "authorization_not_spendable",
    "authorization_nonce_reused": "authorization_not_spendable",
}

BODIES = ("rulebook", "candidate", "snapshot", "authorization")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class AdapterEnvironmentError(Exception):
    """This adapter cannot conduct the call. Never a refusal to replay, and never a verdict.

    Reported inside the protocol rather than by dying, so the runner records INCOMPLETE with the
    reason instead of reading a dead process as thirty failed fixtures.
    """


def preflight():
    """Return a clear sentence if this interpreter cannot run the implementation, else None."""
    running = tuple(sys.version_info[:2])
    if running >= MINIMUM_PYTHON:
        return None
    return ("verify-run requires Python %d.%d or newer and this adapter is running on %d.%d. "
            "Install it into an interpreter that meets that floor and point the runner at it, "
            "for example --adapter \"/path/to/py311/bin/python tools/conformance_adapter.py\"."
            % (MINIMUM_PYTHON + running))


def version_of(path):
    """Return what `--version` printed, or None if this is not the implementation under test.

    `vfy` is a short name and this adapter is not the only thing that may have claimed it. A
    candidate that answers `--version` with anything but this distribution's banner is some other
    program, and running a conformance suite against some other program is how a kit produces a
    confident result about nothing.
    """
    try:
        completed = subprocess.run([str(path), "--version"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    text = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 or not text.startswith("verify-run "):
        return None
    return text.split()[-1]


def vfy_command(named=None):
    """Locate the installed command line, and prove it is the right one. Never a source tree."""
    tried = []
    candidates = [Path(named)] if named else \
        [Path(sys.executable).parent / name for name in ("vfy", "vfy.exe")]
    if not named:
        found = shutil.which("vfy")
        if found:
            candidates.append(Path(found))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        if version_of(candidate) is not None:
            return str(candidate)
        tried.append(str(candidate))
    raise AdapterEnvironmentError(
        "no verify-run command line was found for this adapter. Interpreter: %s. %s Install the "
        "distribution under test into that interpreter — `pip install verify-run` — or name the "
        "executable with --vfy."
        % (sys.executable,
           ("These were found but did not identify as verify-run: %s." % ", ".join(tried))
           if tried else "Nothing named `vfy` was found beside it or on PATH."))


def run(argv, cwd):
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    return subprocess.run(argv, cwd=str(cwd), capture_output=True, timeout=120, env=environment)


def implementation_identity(vfy):
    completed = run([vfy, "--version"], Path.cwd())
    text = completed.stdout.decode("utf-8", "replace").strip()
    version = text.split()[-1] if text else "unknown"
    location = ""
    probe = subprocess.run([sys.executable, "-c",
                            "import vfy, sys; sys.stdout.write(vfy.__file__)"],
                           capture_output=True, text=True)
    if probe.returncode == 0:
        location = probe.stdout.strip()
    return {"name": "verify-run", "version": version, "surface": "cli",
            "module_location": location}


def materialize(bundle, root, vfy):
    """Lay the bundle out as a workspace this implementation's command line accepts.

    Only published artifact shapes are used: the store layout from the released specification and
    a trust anchor holding public keys. Nothing here is a runtime internal.
    """
    completed = run([vfy, "--workspace", str(root), "init", "--template", "pipeline-gate"], root)
    if completed.returncode != 0:
        raise AdapterEnvironmentError(
            "the implementation could not create a workspace to replay into: "
            + completed.stderr.decode("utf-8", "replace").strip())
    if not (bundle / "receipt.json").is_file():
        raise AdapterEnvironmentError(
            "the fixture bundle has no receipt.json: " + str(bundle))

    trust = bundle / "trust.json"
    if trust.is_file():
        (root / ".vfy" / "keys" / "trust.json").write_bytes(trust.read_bytes())

    receipt_bytes = (bundle / "receipt.json").read_bytes()
    try:
        receipt_id = json.loads(receipt_bytes)["receipt_id"]
    except (ValueError, KeyError, TypeError):
        receipt_id = "r-unreadable"
    receipts = root / ".vfy" / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    (receipts / (receipt_id + ".json")).write_bytes(receipt_bytes)

    inputs = receipts / (receipt_id + ".inputs")
    inputs.mkdir(exist_ok=True)
    for name in BODIES:
        source = bundle / (name + ".json")
        if source.is_file():
            (inputs / (name + ".json")).write_bytes(source.read_bytes())
    return receipt_id


def envelope(operation, completed, implementation, extra=None):
    stdout = completed.stdout.decode("utf-8", "replace")
    stderr = completed.stderr.decode("utf-8", "replace")
    body = {
        "adapter": "verify-run-cli",
        "adapter_version": ADAPTER_VERSION,
        "implementation": implementation,
        "operation": operation,
        "accepted": completed.returncode in (0, 10, 11),
        "terminal": None,
        "signature_verified": None,
        "recomputed": None,
        "bindings_verified": None,
        "error_category": None,
        "implementation_reason": None,
        "raw": {"exit_status": completed.returncode,
                "stdout_sha256": digest(completed.stdout),
                "stderr_sha256": digest(completed.stderr)},
    }
    if body["accepted"]:
        try:
            reported = json.loads(stdout)
            body["terminal"] = reported.get("outcome")
            body["signature_verified"] = bool(reported.get("verified"))
            body["recomputed"] = bool(reported.get("replayed"))
            body["bindings_verified"] = bool(reported.get("authorization_verified")) \
                if reported.get("authorization_verified") is not None else None
        except ValueError:
            body["accepted"] = False
            body["error_category"] = "adapter_output_unreadable"
    else:
        reason = stderr.strip().split(":", 1)[0].strip() if ":" in stderr else stderr.strip()
        body["implementation_reason"] = reason or None
        body["error_category"] = ERROR_CATEGORY.get(reason, "unclassified")
    if extra:
        body.update(extra)
    return body


def operation_replay(bundle, implementation, vfy):
    root = Path(tempfile.mkdtemp(prefix="conformance-"))
    try:
        receipt_id = materialize(bundle, root, vfy)
        relative = Path(".vfy") / "receipts" / (receipt_id + ".json")
        completed = run([vfy, "--workspace", str(root), "--json", "replay", str(relative)], root)
        return envelope("replay", completed, implementation)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def operation_capabilities(_bundle, implementation, _vfy):
    return {
        "adapter": "verify-run-cli",
        "adapter_version": ADAPTER_VERSION,
        "implementation": implementation,
        "operation": "capabilities",
        "operations": ["replay", "capabilities"],
        # Live spending is not exposed on this implementation's public surface: `vfy run` issues
        # and consumes an authorization inside one invocation and accepts no externally supplied
        # authorization, so an adapter cannot present one for spending. Declared, not hidden.
        "live_spend": False,
        "accepted_profiles": ["decision-replay-v1"],
        "accepted_artifact_versions": ["1"],
        "historical_replay_supported": True,
        "migration_rewrites_protected_bytes": False,
        "retired_keys_verify_history": True,
    }


OPERATIONS = {"replay": operation_replay, "capabilities": operation_capabilities}


def main():
    parser = argparse.ArgumentParser(description="Reference conformance adapter for verify-run.")
    parser.add_argument("--request", help="path to a JSON request; stdin when absent")
    parser.add_argument("--vfy", help="path to the vfy executable under test; searched when absent")
    options = parser.parse_args()

    operation = "unknown"
    try:
        unusable = preflight()
        if unusable:
            raise AdapterEnvironmentError(unusable)
        raw = Path(options.request).read_text(encoding="utf-8") if options.request \
            else sys.stdin.read()
        request = json.loads(raw)
        operation = request.get("operation", "replay")
        if operation not in OPERATIONS:
            json.dump({"adapter": "verify-run-cli", "operation": operation,
                       "error_category": "unsupported_operation", "accepted": False}, sys.stdout)
            return 0

        vfy = vfy_command(options.vfy)
        implementation = implementation_identity(vfy)
        bundle = Path(request["bundle"]) if request.get("bundle") else None
        result = OPERATIONS[operation](bundle, implementation, vfy)
    except AdapterEnvironmentError as failure:
        result = {"adapter": "verify-run-cli", "adapter_version": ADAPTER_VERSION,
                  "operation": operation, "accepted": False, "adapter_error": str(failure)}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as failure:
        # Anything else that stopped the call is still the harness's problem, not a replay
        # observation. Reported the same way, with the type named and nothing invented.
        result = {"adapter": "verify-run-cli", "adapter_version": ADAPTER_VERSION,
                  "operation": operation, "accepted": False,
                  "adapter_error": "%s: %s" % (type(failure).__name__, failure)}
    sys.stdout.write(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
