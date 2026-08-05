"""Command evidence, per spec/evidence-adapters.md.

Runs one local executable, directly, with an empty environment and a bounded timeout, and reports
its stdout. No command interpreter is ever involved. This is not a sandbox: the child runs with the invoking
user's privileges and nothing here confines what it does. What is bounded is the interface.
"""

import selectors
import subprocess
import time
from pathlib import Path

from vfy.errors import EvidenceAdapterConfigInvalid, EvidencePathInvalid, VerifyError
from vfy.evidence._common import (MAX_ARGUMENT_LENGTH, check_declaration, check_instant,
                                  resolve_under_root)
from vfy.evidence.acquisition import ERROR, observed, unavailable
from vfy.load import load_json_bytes

MAX_STDOUT_BYTES = 1048576
MAX_STDERR_BYTES = 65536
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 30

_READ_CHUNK = 65536


def acquire_command(declaration, root, acquired_at, timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
                    environment=None, working_directory=None):
    """Return one acquisition result for an `exec` declaration.

    `ref` names one executable under the root and is run as a single-element argv. Arguments are
    not expressible in v1: nothing is split out of `ref`, so a ref containing `;`, `$(...)`, `*`,
    or spaces stays one literal path.
    """
    identifier, ref = check_declaration(declaration, "exec")
    check_instant(acquired_at)
    _check_timeout(timeout_seconds)
    environment = _check_environment(environment)
    executable = resolve_under_root(root, ref)
    directory = _check_working_directory(root, working_directory)

    if executable.exists() and not executable.is_file():
        raise EvidencePathInvalid(
            "An evidence command is declared at a path that is not a regular file: "
            + str(executable))
    argument = str(executable)
    if len(argument) > MAX_ARGUMENT_LENGTH:
        raise EvidenceAdapterConfigInvalid("The single argv argument exceeds the declared bound.")

    try:
        code, stdout, oversize = _run_bounded(argument, directory, environment, timeout_seconds)
    except OSError:
        # A missing or unrunnable executable is an evidence failure, not a malformed call.
        return unavailable(identifier, acquired_at, ERROR)

    if code != 0 or oversize or not stdout:
        return unavailable(identifier, acquired_at, ERROR)
    try:
        value = load_json_bytes(stdout)
    except VerifyError:
        return unavailable(identifier, acquired_at, ERROR)
    return observed(identifier, acquired_at, value)


def _check_timeout(timeout_seconds):
    if (not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool)
            or not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS):
        raise EvidenceAdapterConfigInvalid(
            "timeout_seconds must be an integer from %d to %d."
            % (MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS))


def _check_environment(environment):
    """Empty by default: nothing ambient from the parent process reaches an evidence command."""
    if environment is None:
        return {}
    if not isinstance(environment, dict):
        raise EvidenceAdapterConfigInvalid("environment must be a mapping when supplied.")
    for name, value in environment.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise EvidenceAdapterConfigInvalid("environment names and values must be strings.")
    return dict(environment)


def _check_working_directory(root, working_directory):
    if working_directory is None:
        return root
    if not isinstance(working_directory, Path):
        raise EvidenceAdapterConfigInvalid("working_directory must be a pathlib.Path.")
    resolved_root = root.resolve()
    settled = working_directory.resolve()
    if settled != resolved_root and resolved_root not in settled.parents:
        raise EvidencePathInvalid("The working directory is outside the root.")
    if working_directory.is_symlink() or not working_directory.is_dir():
        raise EvidencePathInvalid("The working directory must be a real directory.")
    return working_directory


def _run_bounded(argument, directory, environment, timeout_seconds):
    """Launch directly, read bounded output, and enforce the timeout.

    Returns `(returncode, stdout_bytes, oversize)`; a timeout is reported as a non-zero code.
    The elapsed-time budget uses a monotonic counter, which is not a clock reading: no time value
    reaches the result, and `acquired_at` still comes from the caller alone.
    """
    process = subprocess.Popen(
        [argument],                     # one literal argument; never a command string
        shell=False,                    # no interpreter: no pipes, redirects, globbing, expansion
        cwd=str(directory),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    limits = {process.stdout: MAX_STDOUT_BYTES, process.stderr: MAX_STDERR_BYTES}
    captured = {process.stdout: bytearray(), process.stderr: bytearray()}
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
                # Both pipes are drained so a full one cannot block the child, but only the
                # bound plus one byte is retained: enough to know oversize happened.
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
            process.kill()
            process.wait()
            return -1, b"", False
        stdout = bytes(captured[process.stdout])
        # stderr was read only to keep the child running and is discarded here. Nothing an
        # adapter learns about a failure enters the signed snapshot, and the output of a failing
        # command is exactly where secrets tend to appear.
        return process.returncode, stdout, len(stdout) > MAX_STDOUT_BYTES
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdout, process.stderr):
            stream.close()
