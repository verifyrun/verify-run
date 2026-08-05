"""The one shape an adapter may return."""

from dataclasses import dataclass

from vfy import canon, load

OK = "ok"
MISSING = "missing"
ERROR = "error"

# No adapter originates `stale`: neither a file read nor a command run has a local condition
# meaning "observed but no longer valid" independent of age, and age is the evaluator's.
STATUSES = (OK, MISSING, ERROR)


@dataclass(frozen=True)
class AcquisitionResult:
    """One observation. Canonical text is the authority; `value()` rebuilds a fresh copy.

    Carries no order, no source, and no diagnostic text: nothing an adapter learns about a
    failure enters the signed snapshot.
    """

    id: str
    status: str
    acquired_at: str
    canonical_value: str | None = None

    def value(self):
        if self.canonical_value is None:
            return None
        return load.load_json_bytes(self.canonical_value.encode("utf-8"))

    def as_acquisition(self):
        """Exactly the mapping `build_snapshot` accepts. No translation layer."""
        acquisition = {"id": self.id, "status": self.status, "acquired_at": self.acquired_at}
        if self.canonical_value is not None:
            acquisition["value"] = self.value()
        return acquisition


def observed(identifier, acquired_at, value):
    return AcquisitionResult(id=identifier, status=OK, acquired_at=acquired_at,
                             canonical_value=canon.canonicalize(value))


def unavailable(identifier, acquired_at, status):
    return AcquisitionResult(id=identifier, status=status, acquired_at=acquired_at)
