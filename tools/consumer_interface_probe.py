"""Executable interface investigation; not a supported engineering profile.

Uses only the public installed CLI. See docs/contracts/CONSUMER_INTERFACE_INVESTIGATION.md.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

PROFILE = "consumer-interface-probe-v1"
LIMIT = 32768

# This literal, including the code it will compile, is protected as command argv by Run.
WORKER = r'''
import base64, hashlib, json, os, sys
from pathlib import Path
try:
    bundle = json.loads(sys.argv[1])
    if set(bundle) != {"profile", "source", "source_sha256", "context"}:
        raise ValueError("unsupported fields")
    if bundle["profile"] != "consumer-interface-probe-v1":
        raise ValueError("unsupported profile")
    context = bundle["context"]
    if set(context) != {"environment", "cwd", "cwd_device", "cwd_inode", "python", "python_version", "ambient_access"}:
        raise ValueError("unsupported context")
    if context["ambient_access"] != "trusted-host":
        raise ValueError("unsupported isolation")
    actual = os.stat(".")
    if (dict(os.environ) != context["environment"] or
        str(Path.cwd().resolve()) != context["cwd"] or
        actual.st_dev != context["cwd_device"] or actual.st_ino != context["cwd_inode"] or
        str(Path(sys.executable).resolve()) != context["python"] or
        sys.version != context["python_version"] or
        not sys.flags.isolated or not sys.flags.no_site):
        raise ValueError("context mismatch")
    source = base64.b64decode(bundle["source"], validate=True)
    if hashlib.sha256(source).hexdigest() != bundle["source_sha256"]:
        raise ValueError("source mismatch")
    program = compile(source, "<captured-checker>", "exec")
except (ValueError, TypeError, KeyError, OSError, SyntaxError):
    raise SystemExit(65)
# No reopening a source path after the check.
sys.argv = ["<captured-checker>"]
exec(program, {"__name__": "__main__", "__file__": "<captured-checker>"})
'''


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def capture(source, cwd, environment):
    """Caller supplies expected context; this probe uses the invoking trusted interpreter."""
    if not isinstance(environment, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in environment.items()):
        raise ValueError("environment must contain strings")
    cwd = Path(cwd).resolve(strict=True)
    status = cwd.stat()
    body = Path(source).read_bytes()
    bundle = {"profile": PROFILE, "source": base64.b64encode(body).decode(),
              "source_sha256": hashlib.sha256(body).hexdigest(),
              "context": {"environment": environment, "cwd": str(cwd),
                          "cwd_device": status.st_dev, "cwd_inode": status.st_ino,
                          "python": str(Path(sys.executable).resolve()),
                          "python_version": sys.version, "ambient_access": "trusted-host"}}
    data = encode(bundle)
    if len(data) > LIMIT:
        raise ValueError("bundle exceeds investigation size bound")
    return data


def command(data, expected):
    """Only a caller-retained expected digest is a binding; a bundle cannot approve itself."""
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("bundle identity mismatch")
    bundle = json.loads(data)
    if bundle.get("profile") != PROFILE:
        raise ValueError("unsupported profile")
    if bundle.get("context", {}).get("ambient_access") != "trusted-host":
        raise ValueError("unsupported context")
    return [bundle["context"]["python"], "-I", "-S", "-c", WORKER, data.decode()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="operation", required=True)
    make = actions.add_parser("capture")
    make.add_argument("--source", required=True)
    make.add_argument("--cwd", required=True)
    make.add_argument("--environment-json", required=True)
    make.add_argument("--out", required=True)
    launch = actions.add_parser("launch")
    launch.add_argument("--bundle", required=True)
    launch.add_argument("--expected-sha256", required=True)
    launch.add_argument("--vfy", required=True)
    launch.add_argument("--workspace", required=True)
    launch.add_argument("--identity", action="append", default=[])
    args = parser.parse_args()
    try:
        if args.operation == "capture":
            data = capture(args.source, args.cwd, json.loads(args.environment_json))
            # Never overwrite a captured bundle.
            with open(args.out, "xb") as target:
                target.write(data)
            print(hashlib.sha256(data).hexdigest())
            return 0
        argv = command(Path(args.bundle).read_bytes(), args.expected_sha256)
        invocation = [args.vfy, "--workspace", args.workspace, "--json", "run"]
        for identity in args.identity:
            invocation.extend(["--identity", identity])
        return subprocess.run(invocation + ["--"] + argv, timeout=3700).returncode
    except (ValueError, KeyError, TypeError, OSError) as failure:
        print("interface_probe_refused: " + str(failure), file=sys.stderr)
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
