"""Bounded local evidence adapters, per spec/evidence-adapters.md.

An adapter makes one bounded local observation and reports it as one acquisition result. It builds
no snapshot, evaluates nothing, decides nothing, and reads no clock.

Only `file` and `exec` exist. `http` and `inline` are declared by the schema and not implemented;
evidence declared under them is simply never acquired, which `build_snapshot` records as `missing`.
"""

from vfy.evidence.acquisition import AcquisitionResult
from vfy.evidence.command import acquire_command
from vfy.evidence.file import acquire_file

__all__ = ["AcquisitionResult", "acquire_command", "acquire_file"]
