"""Gated local execution, per spec/execution.md.

Spends one already-issued authorization on exactly the command it names: verify, consume, launch,
acknowledge, receipt, store. Nothing here decides anything. The evaluation happened before this
boundary and is not repeated, reinterpreted, or overridden by anything the process does.

No clock, no randomness, no shell, no network, no evidence acquisition, no retry.
"""

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from vfy import authorization as auth_module
from vfy import canon, load, receipt as receipt_module, schema
from vfy.errors import (
    AuthorizationOutcomeIneligible,
    ExecutionCandidateUnsupported,
    ExecutionConfigurationInvalid,
    ExecutionRecordingFailed,
    VerifyError,
)

EXECUTION_VERSION = 1

MAX_STDOUT_BYTES = 1048576
MAX_STDERR_BYTES = 65536
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 3600

# The whole vocabulary an acknowledgment may carry. A note holding a path, a pid, a duration, or
# an error message would put host data and nondeterminism into a signed artifact.
NOTE_TIMED_OUT = "timed out"
NOTE_SIGNALLED = "terminated by signal"
NOTE_COULD_NOT_START = "could not start"
NOTES = (NOTE_TIMED_OUT, NOTE_SIGNALLED, NOTE_COULD_NOT_START)

_READ_CHUNK = 65536


@dataclass(frozen=True)
class ExecutionRecord:
    """What one spent authorization produced. Canonical text is the authority for the signed part.

    stdout and stderr are operational output: bounded, returned here, and deliberately absent
    from the acknowledgment, the receipt, and the store.
    """

    authorization_id: str
    nonce_consumed: bool
    started: bool
    exit_status: int | None
    timed_out: bool
    signal_number: int | None
    stdout: bytes
    stderr: bytes
    output_truncated: bool
    acknowledgment_canonical: str
    receipt: object
    stored_receipt_id: str

    def acknowledgment(self):
        return load.load_json_bytes(self.acknowledgment_canonical.encode("utf-8"))


def executable_argv(candidate):
    """Return the argv this candidate authorizes, or refuse to guess one.

    spec/candidate.schema.json admits kinds that name no process and permits an empty argv, so
    executability is decided here and never inside the launcher.
    """
    if not isinstance(candidate, dict):
        raise TypeError("a candidate must be a mapping")
    if candidate.get("kind") != "command":
        raise ExecutionCandidateUnsupported(
            "Only a command candidate names a process; this one is " + repr(candidate.get("kind")))
    action = candidate.get("action")
    if not isinstance(action, dict):
        raise ExecutionCandidateUnsupported("A command candidate needs an action.")
    argv = action.get("argv")
    if not isinstance(argv, list) or not argv:
        raise ExecutionCandidateUnsupported(
            "A command candidate needs a non-empty argv; the schema permits neither to be there.")
    for member in argv:
        if not isinstance(member, str):
            raise ExecutionCandidateUnsupported("Every argv member must be a string.")
    program = argv[0]
    if not program:
        raise ExecutionCandidateUnsupported("argv[0] names nothing.")
    if os.sep not in program and (os.altsep is None or os.altsep not in program):
        # A bare name would be looked up along the interpreter's compiled-in default path, so one
        # action_digest could run a different program on every machine. Resolving a name belongs
        # to whoever composes the candidate, before the digest is taken.
        raise ExecutionCandidateUnsupported(
            "argv[0] must name a path, not a name to search for: " + program)
    return list(argv)


def execute_authorized_command(pinned, candidate, snapshot, result, authorization, *,
                               runtime_id, verification_time,
                               store, authorization_keys, registry,
                               receipt_id, receipt_key_id, receipt_key_version,
                               receipt_private_key, cwd,
                               acknowledged_at=None, receipt_created_at=None,
                               completion_clock=None,
                               environment=None, timeout_seconds=300):
    """Verify, consume, execute, acknowledge, receipt, and store one authorized command.

    The order is the guarantee: every refusal above the consume leaves nothing spent and nothing
    started, and every failure below it leaves the authorization spent and says so.

    The two completion instants — the acknowledgment's and the receipt's — arrive one of two
    ways, never both. A caller that already knows them passes `acknowledged_at` and
    `receipt_created_at` as strings, which is what a fixture, a replay harness, or any caller
    reproducing a run byte for byte does. A caller running a real command passes
    `completion_clock`, a callable this reads **once**, after the child has exited: the instant a
    command finished is not knowable before it starts, and a caller forced to name one in advance
    can only name the instant the run began. Either way the runtime holds no clock of its own,
    constructs no timestamp, and reads nothing outside what it was handed.
    """
    for name, value in (("runtime_id", runtime_id), ("verification_time", verification_time),
                        ("receipt_id", receipt_id), ("receipt_key_id", receipt_key_id)):
        if not isinstance(value, str):
            raise TypeError(name + " must be a string")
    if completion_clock is None:
        for name, value in (("acknowledged_at", acknowledged_at),
                            ("receipt_created_at", receipt_created_at)):
            if not isinstance(value, str):
                raise TypeError(name + " must be a string")
    else:
        if not callable(completion_clock):
            raise ExecutionConfigurationInvalid("completion_clock must be callable.")
        if acknowledged_at is not None or receipt_created_at is not None:
            # Silently preferring one would let a caller believe it had pinned an instant that
            # the run then overwrote.
            raise ExecutionConfigurationInvalid(
                "Supply the completion instants or the clock that reads them, never both.")

    if result.outcome != "ALLOW":
        # Checked here rather than left to verification, so a caller holding a negative decision
        # gets the reason for it instead of a failure about a missing argument.
        raise AuthorizationOutcomeIneligible(
            "Only ALLOW is executable; this decision is " + result.outcome)

    argv = executable_argv(candidate)
    directory = _check_working_directory(cwd)
    child_environment = _check_environment(environment)
    _check_timeout(timeout_seconds)

    # Verification against the objects actually in hand, never against an earlier process's word
    # for it. The consumed view makes an already-spent nonce report its own reason; consume_once
    # below is what actually closes the window.
    verified = auth_module.verify_authorization(
        authorization.value(), pinned, candidate, snapshot, result, runtime_id,
        verification_time, authorization_keys, registry,
        consumed_nonces=_ConsumedView(store))

    # --- the line. Nothing above spends anything; nothing below is free. --------------------
    store.consume_once(verified)

    outcome = _launch(argv, directory, child_environment, timeout_seconds)
    if completion_clock is not None:
        # Below the line: the authorization is spent and the command has already run, so a clock
        # that misbehaves is a recording failure and never a reason to pretend nothing happened.
        acknowledged_at = receipt_created_at = _completion_instant(completion_clock, outcome)
    acknowledgment = _acknowledge(outcome, acknowledged_at)

    try:
        signed = receipt_module.issue_receipt(
            pinned, candidate, snapshot, result, verified, acknowledgment, receipt_id,
            receipt_created_at, receipt_key_id, receipt_key_version, receipt_private_key,
            registry)
    except (VerifyError, TypeError, ValueError) as failure:
        raise ExecutionRecordingFailed(
            "The attempt finished and its receipt could not be issued: " + str(failure),
            stage="issue", receipt=None, execution=outcome) from None

    try:
        store.put_record(signed, pinned, candidate, snapshot, verified)
    except (VerifyError, OSError) as failure:
        # The action has happened and the authority is spent. Before reporting that the record
        # could not be committed, keep the signed account of it somewhere a person can still
        # find: handing the receipt back in an exception is only useful to a caller that reads
        # it, and losing it made the store answer "no receipts yet" about a command that ran.
        preserved = None
        try:
            preserved = str(store.preserve_unrecorded(signed))
        except (VerifyError, OSError):
            # Preservation is allowed to fail too — the store may be entirely unavailable. The
            # receipt still travels on the exception, and the caller is told which happened.
            preserved = None
        raise ExecutionRecordingFailed(
            "The attempt finished and its record could not be committed: " + str(failure),
            stage="store", receipt=signed, preserved_at=preserved, execution=outcome) from None

    return ExecutionRecord(
        authorization_id=verified.authorization_id,
        nonce_consumed=True,
        started=outcome["started"],
        exit_status=outcome["exit_status"],
        timed_out=outcome["timed_out"],
        signal_number=outcome["signal_number"],
        stdout=outcome["stdout"],
        stderr=outcome["stderr"],
        output_truncated=outcome["truncated"],
        acknowledgment_canonical=canon.canonicalize(acknowledgment),
        receipt=signed,
        stored_receipt_id=receipt_id,
    )


class _ConsumedView:
    """A read-only membership view over the store's consumption records."""

    def __init__(self, store):
        self._store = store

    def __contains__(self, nonce):
        return self._store.is_consumed(nonce)


def _check_working_directory(cwd):
    if not isinstance(cwd, Path):
        raise ExecutionConfigurationInvalid("The working directory must be a pathlib.Path.")
    if cwd.is_symlink() or not cwd.is_dir():
        raise ExecutionConfigurationInvalid(
            "The working directory must be an existing real directory: " + str(cwd))
    return cwd


def _check_environment(environment):
    """Empty unless the caller names what the child sees."""
    if environment is None:
        return {}
    if not isinstance(environment, dict):
        raise ExecutionConfigurationInvalid("environment must be a mapping when supplied.")
    for name, value in environment.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ExecutionConfigurationInvalid("environment names and values must be strings.")
    return dict(environment)


def _check_timeout(timeout_seconds):
    if (not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool)
            or not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS):
        raise ExecutionConfigurationInvalid(
            "timeout_seconds must be an integer from %d to %d."
            % (MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS))


def _completion_instant(completion_clock, execution=None):
    """Read the caller's clock once and require a date-time in the frozen grammar.

    Nothing is guessed if it misbehaves. The child has run and the nonce is spent, so the honest
    report is the same one a failed receipt issue gets: the attempt finished and its record could
    not be written.

    `execution` travels on the failure. No signed receipt can exist without a `created_at`, so
    none is fabricated — but the child's exit status is a fact the runtime already holds, and
    dropping it would report a completed action as though nothing had been observed at all.
    """
    try:
        instant = completion_clock()
    except Exception:
        raise ExecutionRecordingFailed(
            "The attempt finished and the completion instant could not be read.",
            stage="acknowledge", receipt=None, execution=execution) from None
    if not isinstance(instant, str) or not schema._is_date_time(instant):
        raise ExecutionRecordingFailed(
            "The attempt finished and the completion instant was not a date-time.",
            stage="acknowledge", receipt=None, execution=execution)
    return instant


def _acknowledge(outcome, acknowledged_at):
    """Build only the schema-supported execution object, from the closed note vocabulary."""
    if not outcome["started"]:
        return {"acknowledged": False, "acknowledged_at": acknowledged_at,
                "note": NOTE_COULD_NOT_START}
    body = {"acknowledged": True, "acknowledged_at": acknowledged_at}
    if outcome["timed_out"]:
        body["note"] = NOTE_TIMED_OUT
    elif outcome["signal_number"] is not None:
        # Signal death is not an exit status, and -15 would merge two different facts.
        body["note"] = NOTE_SIGNALLED
    else:
        body["exit_status"] = outcome["exit_status"]
    return body


def _launch(argv, directory, environment, timeout_seconds):
    """Run the authorized argv directly, bounded, with a timeout that can end its descendants."""
    try:
        process = subprocess.Popen(
            argv,                             # the authorized argv, verbatim
            shell=False,                      # no interpreter, no splitting, no expansion
            cwd=str(directory),
            env=environment,                  # nothing ambient is inherited
            stdin=subprocess.DEVNULL,         # the candidate contract carries no input
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,           # its own process group, so a timeout can end it
        )
    except OSError:
        return {"started": False, "exit_status": None, "timed_out": False,
                "signal_number": None, "stdout": b"", "stderr": b"", "truncated": False}

    limits = {process.stdout: MAX_STDOUT_BYTES, process.stderr: MAX_STDERR_BYTES}
    captured = {process.stdout: bytearray(), process.stderr: bytearray()}
    # A monotonic counter is an elapsed-time budget, not a clock reading: no time value reaches
    # the acknowledgment, which takes acknowledged_at from the caller alone.
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    selector = selectors.DefaultSelector()
    try:
        for stream in (process.stdout, process.stderr):
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(timeout=remaining):
                chunk = key.fileobj.read1(_READ_CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer, limit = captured[key.fileobj], limits[key.fileobj]
                room = limit + 1 - len(buffer)
                if room > 0:
                    buffer.extend(chunk[:room])
        if not timed_out:
            try:
                process.wait(timeout=max(deadline - time.monotonic(), 0))
            except subprocess.TimeoutExpired:
                timed_out = True
        if timed_out:
            _end_group(process)
        code = process.returncode
    finally:
        selector.close()
        if process.poll() is None:
            _end_group(process)
        for stream in (process.stdout, process.stderr):
            stream.close()

    stdout, stderr = bytes(captured[process.stdout]), bytes(captured[process.stderr])
    truncated = len(stdout) > MAX_STDOUT_BYTES or len(stderr) > MAX_STDERR_BYTES
    signal_number = None
    exit_status = None
    if timed_out:
        pass                                  # the kill was ours; it is not the program's status
    elif code is not None and code < 0:
        signal_number = -code
    else:
        exit_status = code
    return {"started": True, "exit_status": exit_status, "timed_out": timed_out,
            "signal_number": signal_number,
            "stdout": stdout[:MAX_STDOUT_BYTES], "stderr": stderr[:MAX_STDERR_BYTES],
            "truncated": truncated}


def _end_group(process):
    """End the child's whole process group. Measured: killing only the child leaves a
    backgrounded grandchild running, and killing the group does not.

    A descendant that starts its own session escapes, and a platform without process groups gets
    the direct child only. Full process-tree termination is not claimed.
    """
    killpg = getattr(os, "killpg", None)
    if killpg is not None:
        try:
            killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
    else:
        process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - an unkillable child
        pass
