"""Declaration checking and path discipline shared by the local adapters.

Everything here belongs to failure level 1 of spec/evidence-adapters.md: the call itself is
malformed or unsafe, so no trustworthy observation is possible and nothing is returned.
"""

from pathlib import Path

from vfy import schema
from vfy.errors import EvidenceAdapterConfigInvalid, EvidencePathInvalid

MAX_ARGUMENT_LENGTH = 4096


def check_declaration(declaration, expected_source):
    """Return the id and ref of one evidence declaration this adapter may act on."""
    if not isinstance(declaration, dict):
        raise EvidenceAdapterConfigInvalid("An evidence declaration must be a mapping.")
    identifier = declaration.get("id")
    if not isinstance(identifier, str) or not identifier:
        raise EvidenceAdapterConfigInvalid("An evidence declaration needs a non-empty string id.")
    source = declaration.get("source")
    if source != expected_source:
        raise EvidenceAdapterConfigInvalid(
            "This adapter reads source %r, not %r: %s" % (expected_source, source, identifier))
    ref = declaration.get("ref")
    # The schema makes ref optional, so a declaration can be schema-valid and still name nothing
    # for an adapter to observe. That is a configuration fault, not an evidence gap.
    if not isinstance(ref, str) or not ref:
        raise EvidenceAdapterConfigInvalid(
            "A %s declaration needs a non-empty ref: %s" % (expected_source, identifier))
    return identifier, ref


def check_instant(acquired_at):
    """The caller records when the observation was taken; no adapter ever constructs one."""
    if not isinstance(acquired_at, str) or not schema._is_date_time(acquired_at):
        raise EvidenceAdapterConfigInvalid(
            "acquired_at must be a date-time string in the frozen grammar.")
    return acquired_at


def resolve_under_root(root, ref):
    """Resolve `ref` under `root`, refusing escape and refusing symlinks along the way.

    Containment is decided by resolution rather than by string inspection, so `../` sequences,
    doubled separators, and every other spelling that lands outside are refused the same way —
    and a spelling that lands back inside, such as `a/../b`, is not refused at all.
    """
    if not isinstance(root, Path):
        raise EvidenceAdapterConfigInvalid("The adapter root must be a pathlib.Path.")
    if not isinstance(ref, str) or not ref:
        raise EvidencePathInvalid("An evidence ref must be a non-empty string.")
    if Path(ref).is_absolute():
        raise EvidencePathInvalid("An absolute ref escapes the root by definition: " + ref)
    if root.is_symlink() or not root.is_dir():
        # A root that is not a real directory is a configuration fault. Reporting `missing`
        # instead would turn one mistyped root into an evidence gap for every declaration.
        raise EvidencePathInvalid("The adapter root is not an existing directory: " + str(root))

    resolved_root = root.resolve()
    segments = []
    for part in Path(ref).parts:
        if part == ".":
            continue
        if part == "..":
            if not segments:
                raise EvidencePathInvalid("The ref resolves outside the root: " + ref)
            segments.pop()
            continue
        segments.append(part)
    if not segments:
        raise EvidencePathInvalid("A ref must name something under the root: " + ref)

    # Refuse a symlink at every step, checked with lstat semantics so a link is seen rather than
    # followed. With no link on the path, the lexical join above and full resolution agree.
    target = resolved_root
    for part in segments:
        target = target / part
        if target.is_symlink():
            raise EvidencePathInvalid("A symlink may not stand in for evidence: " + str(target))

    settled = target.resolve()
    if settled != resolved_root and resolved_root not in settled.parents:
        raise EvidencePathInvalid("The ref resolves outside the root: " + ref)
    return target
