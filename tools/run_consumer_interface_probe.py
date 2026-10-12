"""Reproduce the public-CLI path against an explicitly selected installed vfy.

Creates only temporary workspaces and an explicitly named new result file. No production profile
is adopted; the permissive rulebook authorizes a local experiment, not engineering acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from consumer_interface_probe import capture


def run(vfy, artifact_identity):
    room = Path(tempfile.mkdtemp(prefix="verify-consumer-interface-")).resolve()
    results = []
    for name, mutate_context in [("captured-source", False), ("mutated-context", True)]:
        root = room / name
        root.mkdir()
        initial = subprocess.run([vfy, "--workspace", str(root), "init"],
                                 capture_output=True, text=True, timeout=30)
        if initial.returncode:
            raise RuntimeError(initial.stderr)
        rule = {"rulebook_id": "interface-probe-permission", "version": "1.0.0",
                "adopted_at": "2026-09-18T00:00:00Z",
                "description": "Permission for this local experiment only; no engineering acceptance.",
                "track": [], "evidence": [], "rules": [{"id": "permit-probe", "when": "true == true",
                "outcome": "ALLOW", "reason": "Local experiment permission only."}],
                "default_outcome": "HOLD"}
        (root / "rulebook.yaml").write_text(json.dumps(rule))
        env = {"LC_ALL": "C"}
        if sys.platform == "darwin":
            env["__CF_USER_TEXT_ENCODING"] = "0x%X:0x0:0x0" % os.getuid()
        source = root / "checker.py"
        source.write_text('from pathlib import Path\nPath("checker-ran").write_text("captured-original")\n')
        data = capture(source, root, env)
        bundle = root / "bundle.json"
        bundle.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        source.write_text('raise RuntimeError("mutable replacement executed")\n')
        config_path = root / ".vfy/config.json"
        config = json.loads(config_path.read_text())
        config["execution"]["environment"] = dict(env)
        if mutate_context:
            config["execution"]["environment"]["MODE"] = "changed-after-capture"
        config_path.write_text(json.dumps(config))
        command = [sys.executable, "-B", str(Path(__file__).with_name("consumer_interface_probe.py")),
                   "launch", "--bundle", str(bundle), "--expected-sha256", expected,
                   "--vfy", vfy, "--workspace", str(root)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
        payload = json.loads(completed.stdout)
        if payload.get("outcome") != "ALLOW" or payload.get("exit_status") != (65 if mutate_context else 0):
            raise RuntimeError("Unexpected Run result: " + repr(payload))
        marker = root / "checker-ran"
        if marker.exists() == mutate_context:
            raise RuntimeError("Checker execution differs from expected result")
        if not mutate_context and marker.read_text() != "captured-original":
            raise RuntimeError("The captured checker did not execute")
        replay = subprocess.run([vfy, "--workspace", str(root), "--json", "replay",
                                 str(root / payload["receipt_path"])],
                                capture_output=True, text=True, timeout=30)
        if replay.returncode:
            raise RuntimeError("Replay failed: " + replay.stderr)
        results.append({"case": name, "bundle_sha256": expected, "cli_exit": completed.returncode,
                        "run": payload, "checker_started": not mutate_context,
                        "replay": json.loads(replay.stdout)})
    return {"evidence_profile": "consumer-interface-probe-v1", "workspace_root": str(room),
            "runtime_artifact_identity_supplied_by_caller": artifact_identity,
            "cases": results,
            "scope": "Captured Python body and actual context only; not engineering acceptance or isolation."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vfy", required=True)
    parser.add_argument("--artifact-sha256", required=True,
                        help="external caller identity; this script does not attest installed files")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if Path(args.out).exists():
        parser.error("output already exists; use a new evidence identity")
    result = run(str(Path(args.vfy).resolve()), args.artifact_sha256)
    with open(args.out, "x") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print("PASS: captured source executed; changed actual context refused; both receipts replayed")


if __name__ == "__main__":
    main()
