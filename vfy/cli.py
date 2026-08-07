"""The `vfy` command line, per spec/cli.md.

Parsing, rendering, and exit codes. Every decision is made below this file, and nothing here
re-implements one. Importing this module reads no file, no clock, and no environment.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from vfy import __version__, canon, resources, workflow
from vfy.errors import VerifyError

CLI_VERSION = 1

# Three separate things, never merged: the decision, the child's status, and the CLI's health.
EXIT_OK = 0
EXIT_BLOCK = 10
EXIT_HOLD = 11
EXIT_ERROR = 12
EXIT_EXECUTION_FAILED = 13
EXIT_RECORDING_FAILED = 14
EXIT_OPERATIONAL = 1
EXIT_USAGE = 2

_DECISION_EXIT = {"ALLOW": EXIT_OK, "BLOCK": EXIT_BLOCK, "HOLD": EXIT_HOLD, "ERROR": EXIT_ERROR}

_DEVELOPER_TRACEBACK = "VFY_DEVELOPER_TRACEBACK"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="vfy", description="A local, deterministic action gate for consequential software.")
    parser.add_argument("--version", action="version",
                        version="verify-run " + __version__)
    parser.add_argument("--workspace", default=".",
                        help="workspace root (default: the current directory)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print one canonical JSON object on stdout")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    initialize = commands.add_parser("init", help="create a workspace from a template")
    initialize.add_argument("--template", default="agent-guard", choices=workflow.TEMPLATES,
                            help="which rulebook to start from")

    checker = commands.add_parser("check", help="evaluate a candidate without executing anything")
    checker.add_argument("candidate", help="path to a candidate JSON document")

    runner_parser = commands.add_parser("run", help="gate a command")
    runner_parser.add_argument("--identity", action="append", default=[], metavar="NAME=VALUE",
                               help="a value for one of the rulebook's track fields; repeatable")
    runner_parser.add_argument("argv", nargs=argparse.REMAINDER,
                               metavar="-- command [args...]",
                               help="the exact command, after --")

    replayer = commands.add_parser("replay", help="verify and recompute a stored decision")
    replayer.add_argument("receipt", help="path to a stored receipt")

    receipts = commands.add_parser("receipts", help="list or show local receipts")
    actions = receipts.add_subparsers(dest="action", required=False, metavar="action")
    actions.add_parser("list", help="list committed receipts")
    show = actions.add_parser("show", help="load, verify, and replay one receipt")
    show.add_argument("receipt_id", help="the receipt id")
    return parser


def main(argv=None, clock=None, identifiers=None, out=None, err=None):
    """Return a process exit code. No import-time side effect produced any of this."""
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err

    parser = build_parser()
    # argparse writes usage errors straight to sys.stderr, so a caller that supplied its own
    # stream would never see them. Redirecting for the parse keeps every diagnostic on the
    # stream this function was given.
    previous_stderr, previous_stdout = sys.stderr, sys.stdout
    sys.stderr, sys.stdout = err, out
    try:
        options = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    except SystemExit as exit_request:
        # --help and --version exit 0. `code or EXIT_USAGE` would turn that 0 into a usage
        # error, which is exactly what a caller scripting `vfy --version` would trip over.
        code = exit_request.code
        return EXIT_USAGE if code is None else int(code)
    finally:
        sys.stderr, sys.stdout = previous_stderr, previous_stdout

    clock = workflow.Clock() if clock is None else clock
    identifiers = workflow.Identifiers() if identifiers is None else identifiers

    try:
        handler = {"init": _init, "check": _check, "run": _run,
                   "replay": _replay, "receipts": _receipts}[options.command]
        return handler(options, clock, identifiers, out, err)
    except VerifyError as typed:
        return _typed_failure(typed, options, out, err)
    except BrokenPipeError:  # pragma: no cover - a closed downstream pipe is not our failure
        return EXIT_OPERATIONAL
    except Exception as defect:  # an unexpected programming defect, never a declared failure
        if os.environ.get(_DEVELOPER_TRACEBACK):
            raise
        print("internal error: %s" % type(defect).__name__, file=err)
        return EXIT_OPERATIONAL


# --- commands -------------------------------------------------------------------------------

def _init(options, clock, identifiers, out, err):
    workspace = workflow.initialize(options.workspace, options.template, resources.schema_dir(), resources.template_dir(),
                                    identifiers)
    body = {"command": "init", "template": options.template,
            "runtime_id": workspace.config["runtime_id"],
            "workspace": str(workspace.root), "rulebook": workspace.config["rulebook"]}
    if options.as_json:
        _emit(body, out)
    else:
        print("initialized  %s" % workspace.root, file=out)
        print("  rulebook   %s   (template %s)"
              % (workspace.config["rulebook"], options.template), file=out)
        print("  runtime    %s" % workspace.config["runtime_id"], file=out)
        print("  store      %s" % (Path(workflow.VFY_DIR)), file=out)
        print("  keys were generated in %s; the private halves are never printed."
              % (Path(workflow.VFY_DIR) / "keys"), file=out)
    return EXIT_OK


def _check(options, clock, identifiers, out, err):
    workspace = workflow.open_workspace(options.workspace, resources.schema_dir())
    decision = workflow.check(workspace, options.candidate, clock)
    _render(decision, options, out, err, previewed=True)
    return _DECISION_EXIT[decision.outcome]


def _run(options, clock, identifiers, out, err):
    argv = list(options.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("run needs a command after `--`, for example: vfy run -- ./deploy.sh", file=err)
        return EXIT_USAGE

    identity = {}
    for pair in options.identity:
        name, separator, value = pair.partition("=")
        if not separator or not name:
            print("--identity takes NAME=VALUE, for example --identity branch=main", file=err)
            return EXIT_USAGE
        identity[name] = value

    workspace = workflow.open_workspace(options.workspace, resources.schema_dir())
    _warn_on_permissive_keys(workspace, err)
    try:
        decision = workflow.run(workspace, argv, clock, identifiers, identity or None)
    except VerifyError as typed:
        if typed.code == "execution_recording_failed":
            # The authorization is spent and the action may have happened. Say so plainly.
            print("the attempt finished and its record could not be written (%s)"
                  % getattr(typed, "stage", "unknown"), file=err)
            print("the authorization is consumed; nothing is retried automatically", file=err)
            return EXIT_RECORDING_FAILED
        raise
    _render(decision, options, out, err)
    if decision.outcome != "ALLOW":
        return _DECISION_EXIT[decision.outcome]
    # A non-zero child does not demote the decision; the code says the action failed.
    return EXIT_OK if decision.exit_status == 0 else EXIT_EXECUTION_FAILED


def _replay(options, clock, identifiers, out, err):
    workspace = workflow.open_workspace(options.workspace, resources.schema_dir())
    record = workflow.replay(workspace, options.receipt)
    body = {"command": "replay", "receipt_id": record.receipt_id, "outcome": record.outcome,
            "verified": True, "replayed": record.replay_verified,
            "authorization_verified": record.authorization_verified}
    if options.as_json:
        _emit(body, out)
    else:
        print("%-7s %s" % (record.outcome, record.receipt_id), file=out)
        print("  verification  signature verified", file=out)
        print("  replay        %s"
              % ("recomputed and identical" if record.replay_verified
                 else "not replayed"), file=out)
        if record.authorization_verified:
            print("  authorization verified against the recorded bindings", file=out)
    return _DECISION_EXIT[record.outcome]


def _receipts(options, clock, identifiers, out, err):
    workspace = workflow.open_workspace(options.workspace, resources.schema_dir())
    if getattr(options, "action", None) == "show":
        record = workflow.replay(
            workspace, workspace.vfy / "receipts" / (options.receipt_id + ".json"))
        body = {"command": "receipts.show", "receipt_id": record.receipt_id,
                "outcome": record.outcome, "verified": True,
                "replayed": record.replay_verified}
        if options.as_json:
            _emit(body, out)
        else:
            print("%-7s %s   verified and replayed" % (record.outcome, record.receipt_id),
                  file=out)
        return _DECISION_EXIT[record.outcome]

    listing = workflow.list_receipts(workspace)
    summaries, refused = listing.summaries, listing.refused
    body = {"command": "receipts.list",
            "receipts": [{"receipt_id": s.receipt_id, "created_at": s.created_at,
                          "outcome": s.outcome, "rulebook_id": s.rulebook_id,
                          "rulebook_version": s.rulebook_version,
                          "authorization_id": s.authorization_id, "key_id": s.key_id}
                         for s in summaries],
            "refused": [{"file": r.filename, "code": r.code} for r in refused]}
    if options.as_json:
        _emit(body, out)
    elif not summaries:
        print("no receipts yet" if not refused else "no receipt in this store could be read",
              file=out)
    else:
        for summary in summaries:
            print("%-7s %-28s %s  %s@%s"
                  % (summary.outcome, summary.receipt_id, summary.created_at,
                     summary.rulebook_id, summary.rulebook_version), file=out)
        print("listed from the committed records, which govern", file=out)
    # A damaged artifact is named on the diagnostic stream and never silently dropped. The
    # healthy records above are still listed: one unreadable file is a fact about that file.
    for entry in refused:
        print("refused %s (%s): %s" % (entry.filename, entry.code, entry.message), file=err)
    if refused:
        print("%d artifact(s) in the store could not be read; nothing was deleted"
              % len(refused), file=err)
        return EXIT_OPERATIONAL
    return EXIT_OK


# --- rendering ------------------------------------------------------------------------------

def _render(decision, options, out, err, previewed=False):
    if options.as_json:
        _emit({"command": "check" if previewed else "run",
               "outcome": decision.outcome,
               "matched_rule": decision.matched_rule,
               "reasons": [dict(reason) for reason in decision.reasons],
               "receipt_id": decision.receipt_id,
               "receipt_path": decision.receipt_path,
               "executed": decision.executed,
               "exit_status": decision.exit_status,
               "notes": list(decision.notes)}, out)
        return
    rule = ("   rule: " + decision.matched_rule) if decision.matched_rule else ""
    print("%-7s %s%s" % (decision.outcome, decision.summary, rule), file=out)
    for reason in decision.reasons:
        detail = reason.get("evidence_id")
        print("        %s%s: %s"
              % (reason["code"], (" " + detail) if detail else "", reason["message"]), file=out)
    for note in decision.notes:
        print("        %s" % note, file=out)
    if decision.receipt_path:
        print("        receipt %s" % decision.receipt_path, file=out)
    if previewed:
        print("        preview only: nothing was authorized, consumed, or executed", file=out)
    elif decision.outcome == "ALLOW":
        if decision.executed and decision.exit_status is not None:
            print("        executed, exit %d" % decision.exit_status, file=out)
        else:
            print("        the authorized command did not complete", file=out)
    else:
        print("        nothing executed", file=out)


def _emit(body, out):
    # Canonical because the frozen canonicalizer produced it, not because it is JSON.
    print(canon.canonicalize(body), file=out)


def _typed_failure(typed, options, out, err):
    """Every declared failure renders as one line. No traceback, no key material, no stack."""
    print("%s: %s" % (typed.code, typed), file=err)
    if typed.code in _DECISION_EXIT:  # pragma: no cover - reason codes are not outcome names
        return _DECISION_EXIT[typed.code]
    if getattr(options, "as_json", False):
        _emit({"command": options.command, "error": typed.code}, out)
    return EXIT_OPERATIONAL


def _warn_on_permissive_keys(workspace, err):
    for which in ("authorization", "receipt"):
        _, permissive = workflow.load_signing_seed(workspace, which)
        if permissive:
            print("warning: the %s signing key is readable beyond its owner" % which, file=err)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
