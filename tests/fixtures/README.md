# Public regression fixtures

`managed_capacity_r1.py` preserves the former r1 implementation solely to reproduce
its rejection of a distinct current inspection with the same original subject.
SHA-256: de244ec23488221853500789d571e5a022ab28d4937c391ad9c8ef8ffccb4642.
It is never selected as the installed runtime.

The adjacent `tests/child_observer_fixture.py` creates fresh synthetic START records
and a child that actually checks pinned snapshot bytes. It exercises capacity,
reservation and settlement controls without distributing private retained evidence.
It does not establish acceptance of the private Engineer workload. Production
observer profiles and their acceptance requirements are unchanged.
