# Release — what ships, and what must be true before it does
    release_version: 1

This unit packages the closed product. It changes no runtime semantics and adds no product
surface. Everything here is about the boundary between a source checkout and an installed package.

## Alpha scope, frozen

**Included:** the local CLI (`init`, `check`, `run`, `replay`, `receipts`); `file` and `exec`
evidence; deterministic rulebook evaluation with four outcomes; frozen evidence snapshots;
action-bound single-use authorizations; direct command execution; signed receipts; the local
store; replay; receipt listing.

**Excluded, and no documentation may imply otherwise:** HTTP acquisition, hosted registry, hosted
vault, fleet, `watch`, `serve`, login, billing, browser interface, robotics device pack, the npm
runtime, and generalized plugins.

## Version
`0.1.0a2`, PEP 440. One authoritative source: `vfy/__init__.py.__version__`, which
`pyproject.toml` and `vfy --version` must agree with. A test asserts all three.

The package version and the artifacts' `spec_version` are different things and move
independently. A receipt written today must still be readable when the package is at 0.4.

## Python
`requires-python = ">=3.11"`, which is what the syntax actually needs. Developed and fully tested
on CPython 3.14; CI runs 3.11, 3.12, and 3.13 on Linux. **The README states exactly that range and
claims nothing wider.** Windows is untested and is not claimed.

## Dependencies
`PyYAML>=6.0,<7` and `cryptography>=42,<52`. Upper bounds exclude the next major release, which is
where breaking changes are permitted to land; they do not pin a patch, which would make the package
uninstallable beside anything else.

No test framework: the suite is standard-library `unittest`. No optional networking or telemetry
dependency exists, and none may be added.

## Runtime resources
The runtime reads exactly two things from its own distribution: the six `*.schema.json` files and
the three templates. Everything else it touches belongs to the user's workspace.

There is **one copy of each in the repository**, at its authoritative path — `spec/` and
`templates/`. Packaging maps those directories into the installed package as `vfy._schemas` and
`vfy._templates` rather than duplicating them, so the bytes that ship are the bytes the
specifications name and no drift is possible.

`vfy/resources.py` resolves through `importlib.resources` first and falls back to the checkout
only for running the tests out of a clone. **An installed package must never depend on a source
tree**, and a release test proves an installed wheel takes the resource path and never the
fallback.

The `.md` specifications ship in the source distribution and not in the wheel: they are authority
for humans, not loaded at runtime.

## What may not enter a release
`.venv/`, `.vfy/` workspaces, generated `*.key` files, `__pycache__`, `.DS_Store`, logs, the
`verify-run/` npm namespace placeholder, `verify-run-kickoff.zip`, and any credential. The wheel
additionally excludes `tests/`, `fixtures/`, and the `.md` specifications.

The source distribution **includes** tests and fixtures: a project whose golden vectors cannot be
audited from its own sdist is asking to be trusted rather than checked.

## Committed gates
Three scans run in the suite and in CI, so no release depends on someone remembering to grep:

1. **Vocabulary** — banned theory and legacy terms across every public surface: `vfy/`, `spec/`,
   `templates/`, `fixtures/`, the README, the docs, and rendered CLI help. Acronyms are matched
   case-sensitively as whole words; ordinary words case-insensitively. The only exclusion is the
   scanner itself, which necessarily contains the list.
2. **Legacy** — no import, path, package, subprocess call, or installation instruction referencing
   the legacy tree. `docs/EXTRACTION_GUIDE.md` may describe historical salvage boundaries; it may
   not create linkage.
3. **Secrets** — PEM private keys, PyPI/GitHub/Stripe/AWS credentials, `.env` files, and generic
   secret assignments. The published test seeds are permitted only in files that mark themselves
   `TEST_ONLY`.

## Build and inspection
`python -m build` produces a wheel and a source distribution. Both are inspected against a frozen
manifest expectation before any release.

**Byte-identical archives are not claimed.** Wheel and tar containers embed timestamps, so two
builds differ in container metadata. What is proven and reported instead: the same file list, the
same file bytes, the same metadata fields, the same version, the same dependency declarations, and
the same entry point.

## Clean-machine proof
The workflow must complete from installed bytes, in a fresh environment, outside the repository,
using the real `vfy` console script, with no `PYTHONPATH`: install → `--version` → `--help` →
`init` → `run` → `receipts` → `replay`, for both the wheel and the source distribution.

## Publication
Nothing is published in this unit. `docs/release-checklist.md` records what remains, and a step is
marked done only when it has actually been performed.
