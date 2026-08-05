"""File evidence, per spec/evidence-adapters.md.

Reads one local file, once, bounded, and reports what was read. It follows no symlink, leaves no
root, and constructs no timestamp.
"""

import os
import stat

from vfy.errors import EvidencePathInvalid, VerifyError
from vfy.evidence._common import check_declaration, check_instant, resolve_under_root
from vfy.evidence.acquisition import ERROR, MISSING, observed, unavailable
from vfy.load import load_json_bytes

MAX_FILE_BYTES = 1048576

# O_NOFOLLOW refuses a symlink at the final component in the same operation that opens it, so the
# window between checking and reading cannot be used to substitute one. O_NONBLOCK keeps a named
# pipe substituted into that window from blocking the open until a writer appears. Both are POSIX;
# where they are absent, the symlink refusal in resolve_under_root is the floor — which is what
# every earlier version had, and what spec/evidence-adapters.md states rather than overclaims.
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def acquire_file(declaration, root, acquired_at):
    """Return one acquisition result for a `file` declaration."""
    identifier, ref = check_declaration(declaration, "file")
    check_instant(acquired_at)
    path = resolve_under_root(root, ref)

    if not path.exists():
        # Nothing to read, and that is a fact about the evidence rather than about the call.
        return unavailable(identifier, acquired_at, MISSING)
    if not path.is_file():
        raise EvidencePathInvalid(
            "Evidence is declared at a path that is not a regular file: " + str(path))

    descriptor = None
    try:
        descriptor = os.open(path, _OPEN_FLAGS)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            # The path was a regular file a moment ago and is not one now. That is the same
            # configuration fault as before, caught a step later.
            raise EvidencePathInvalid(
                "Evidence is declared at a path that is not a regular file: " + str(path))
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None  # the file object owns it now and closes it on the way out
            # One descriptor, one read, limit plus one so oversize is detected rather than
            # truncated silently. These bytes are the observation: no claim is made that the file
            # was unchanged before, during, or after, and no second read is taken to compare.
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return unavailable(identifier, acquired_at, ERROR)
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if len(raw) > MAX_FILE_BYTES:
        return unavailable(identifier, acquired_at, ERROR)

    try:
        # Strict JSON only. Type is never inferred from a filename extension. The loader
        # canonicalizes what it returns, so anything it accepts has a canonical form.
        value = load_json_bytes(raw)
    except VerifyError:
        return unavailable(identifier, acquired_at, ERROR)
    return observed(identifier, acquired_at, value)
