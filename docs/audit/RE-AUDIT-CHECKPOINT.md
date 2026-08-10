# Re-audit checkpoint — F-AUDIT-01..19

Working notes for the closure arc. Not a public document: it records what was reproduced, what was
repaired, and what the next session does not need to re-derive. Delete before a stable release.

Local HEAD `37830db`, 18 commits ahead of `origin/main` `58c49dd`, unpushed, clean tree.
`pyproject` version `0.1.0a3` — **unchanged on purpose**; `v0.1.0a3` is published and these
repairs mean the next release needs a new version.

## Ledger

| # | Finding | Reproduced | Status | Commit |
|---|---|---|---|---|
| 01 | decimal operand host-limit / raw ValueError | yes | CLOSED | `0b2129c` |
| 02 | executed signed receipt lost after record failure | yes | CLOSED | `7cd7a1d`, `ea8305c` |
| 03 | non-regular / oversized committed receipt | **yes** | **CLOSED** | `cdffbd3` |
| 04 | executable identity fidelity | **yes** | **CLOSED** | `d90d9c6` |
| 05 | result ↔ kit binding | **yes** | **CLOSED** | `86523cb` |
| 06 | conducted FAIL laundered into INCOMPLETE | yes | CLOSED | `2feb303` |
| 07 | release scanners skipping by substring | yes | CLOSED | `fc0cfb9` |
| 08 | self-auditable sdist | **yes** | **CLOSED** | `2d083db` |
| 09 | artifact-bound reference result | **yes** | **CLOSED** | `30e92cd` |
| 10 | canonical base64 signatures | **yes** | **CLOSED** | `a7b5372` |
| 11 | completion timeline after a backward clock | **yes** | **CLOSED** | `edbd854` |
| 12 | outcome survival after completion-clock failure | **yes** | **CLOSED** | `edbd854` |
| 13 | dangling index symlink read as absence | **yes** | **CLOSED** | `cdffbd3` |
| 14 | read-only listing that writes | **yes** | **CLOSED** | `cdffbd3` |
| 15 | secret-leak verdict asymmetry | yes | CLOSED (re-proved) | `2feb303` |
| 16 | docs / spec drift | **yes** | **CLOSED** | `edbd854`, `7aa765d` |
| 17 | F9 nonce scope across store clones | not yet | **FOUNDER_DECISION_REQUIRED** (unreproduced) | — |
| 18 | implementation identity behind a banner | **yes** | **PARTLY CLOSED** — banner/module_location and the checker artifact join done; RECORD-to-wheel binding not | `37830db` |
| 19 | CI matrix / supply-chain cluster | not yet | **KNOWN_DEFERRED** | — |

## Baselines, taken twice with no edit between them

Both: `ea8305c`, clean tree, 673 tests OK, 0 skips, Python 3.14.2, 1017 tracked files,
`requires-python >=3.11`.

Conformance PASS 30/30, manifest `756029f681ad7587…`. Note for the next session: the repo `.venv`
has **no** `vfy` installed, so the conformance runner needs a separate venv —

```sh
python -m venv /tmp/cenv && /tmp/cenv/bin/pip install .
python tools/run_conformance.py --profile conformance/decision-replay-v1/profile.json \
  --adapter-arg /tmp/cenv/bin/python --adapter-arg tools/conformance_adapter.py \
  --adapter-arg=--vfy --adapter-arg /tmp/cenv/bin/vfy --out out.json
```

`--adapter tools/conformance_adapter.py` fails with `PermissionError`: the file is mode 644 and is
not meant to be executed directly.

F-AUDIT-01 battery re-proved under `sys.set_int_max_str_digits` of both 640 and 100000, identical
results. F-AUDIT-02 fallback battery: 11 hostile cases, all typed, no hang.

## What was reproduced in this arc

### F-AUDIT-03 — before repair
A **FIFO** at `receipts/<id>.json` hung `listing()`, `get_record()`, `_refresh_index()` **and**
`rebuild_index()` — one planted file froze reading the store *and* recording a new action into it.
A directory and a unix socket escaped `get_record()` as raw `IsADirectoryError` / `OSError`. An
oversized file was read in full and then refused structurally. A dangling symlink was reported as
`store_record_missing`.

### F-AUDIT-13 — before repair
A dangling symlink at `index.json` gave `rows=1 refused=0`: reported as **absent**, so a hostile
object was invisible precisely by pointing at nothing. A FIFO hung the listing.

### F-AUDIT-14 — before repair
On an *initialized* workspace (the CLI refuses earlier when `.vfy/config.json` is gone, so the
damage has to be inside a real workspace), `vfy receipts list`:

| damage | before | after |
|---|---|---|
| `store.json` removed | exit 0, **created `.vfy/store.json`** | exit 0, no delta |
| `receipts/` removed | exit 0, **created `receipts/`** | typed refusal, no delta |
| `consumed/`+`tmp/` removed | exit 0, **created both** | exit 0, no delta |
| `receipts/` is a plain file | `internal error: FileExistsError` | typed refusal |
| `receipts/` unreadable | **exit 0 `no receipts yet`** | typed refusal |
| `store.json` is a directory | exit 0, accepted as marker | typed refusal |

The unreadable case was the worst: `Path.glob` returns an empty iterator on a directory it cannot
open, so *I cannot see* was answered as *there is nothing here*.

### F-AUDIT-05 — before repair
`fixtures: []`, all counts 0, `overall: PASS`, `fixture_manifest_sha256` = 64 zeroes, pristine kit
→ **`acceptable`, exit 0**. 10 of the 13 forgeries now in the gate were accepted.

## Repairs

`read_store_file` in `vfy/store.py` — `os.open` with `O_NOFOLLOW | O_NONBLOCK`, then `fstat` on the
descriptor, regular-file requirement, size bound from the descriptor, bounded read. The open *is*
the classification, so absence means "no directory entry" and a dangling link is a link. Used by
every committed-receipt read, the index read, `is_consumed`, and the F-AUDIT-02 fallback.

`LocalStore(root)` writes and may create the layout; `LocalStore.for_reading(root)` creates
nothing. `receipts list`, `receipts show` and `replay` use the reading form.

`tools/check_conformance_result.py` now checks the result *against* the kit: digests, profile
identity, exact fixture-id set, and `counts`/`overall` recomputed from the rows.

## Traps found in this arc's own work

- The first negative proof for the F-AUDIT-05 gate was **vacuous**: `git stash push` on the
  checker changed a file `MANIFEST.json` covers, so the kit-digest check refused every forgery for
  the wrong reason. The control case ("the untouched result is still accepted") caught it. Any
  negative proof touching a kit file must regenerate `MANIFEST.json` first.
- `MANIFEST.json` records `tests/test_conformance.py`, so editing that test invalidates the kit
  until `tools/build_conformance_manifest_of_record.py` is re-run. Friction worth flagging under
  F-AUDIT-19; the frozen *fixture* manifest digest is unaffected.
- `addCleanup` runs **after** `tearDown`, so a test that patches `os.unlink` must restore in a
  `finally`, not a cleanup, or `tearDown`'s `rmtree` trips the patch.
- `AF_UNIX` paths are ~104 bytes; bind relative to the containing directory when planting a socket
  under a `tempfile` root.
- `tests/test_store.py:677` prints an `AuthorizationNonceReused` traceback from a worker thread.
  Pre-existing and by design — it is the losing writer in the concurrency proof, not a failure.

## Traps found in the release-integrity arc

- **`dist/` held `0.1.0a2` for the whole `0.1.0a3` line**, and `PackageContents` selected
  `sorted(glob("*.whl"))[-1]`. Three artifact tests had been passing green against bytes nobody
  built from this tree. Artifacts are now selected by declared version and a mismatch fails.
- The **version-bump reproduction poisoned `__pycache__`**: `0.1.0a3` and `0.1.0a4` are the same
  length, so restoring the file inside one mtime second left Python using bytecode compiled from
  the bumped source. `vfy/__init__.py` read `a3` while the import reported `a4`. Clear
  `__pycache__` after any in-place version experiment.
- A first `decode_signature` enforced 64 bytes and broke two golden fixtures
  (`reject_truncated_signature`, `reject_invalid_signature` expect `signature_invalid`, not
  `signature_malformed`). Length is Ed25519's question. The fixtures were not edited.
- The artifact credential scan first used a bare `-----BEGIN` prefix — stricter than the source
  gate — and flagged `tools/run_conformance.py`, whose leak detector legitimately names that
  marker. Both corpora now share `SecretGate.PATTERNS`.
- The `sdist-self-audit` CI step first asserted `vfy` resolves inside site-packages. Running a
  shipped suite from an unpacked tree puts that tree's own `vfy/` first, and those are the
  artifact's bytes. The honest assertion is that nothing came from the *checkout*.

## F-AUDIT-11 / 12 — what was reproduced

Both through the real runner and the real verifier, not from code reading.

- **11**: `completion_clock` returning `2020-01-01T00:00:00Z` produced a **signed receipt created
  six years before the `issued_at` of the authorization it records** and before the `frozen_at` of
  the evidence it evaluated. Signature valid, replay identical, authorization verified — reported
  as entirely ordinary. Note `created_at` and `acknowledged_at` come from the *same* completion
  reading, so they are always equal; the anomaly is only visible against instants recorded above
  them.
- **12**: a completion clock that raised gave `ExecutionRecordingFailed(stage='acknowledge',
  receipt=None)` and **nothing about the child**, which had exited 0. `.outcome` on that exception
  is `VerifyError.outcome` (`'ERROR'`), not an execution outcome — easy to misread as coverage.

Classification: 11 is **valid-but-anomalous**, surfaced via `ReplayVerification.timeline_anomalies`
(a verification result object, not a signed payload — no protocol identity change). 12 preserves
`execution` on the failure at all three stages below the launch line and fabricates no receipt.

## F-AUDIT-16 — what was reproduced, and what was refuted

**Confirmed and closed** (`7aa765d`): `spec/cli.md` advertised a `--json` field set containing
`exit_code`, which the CLI has never emitted, and omitted `notes`, which it always does. It also
gave one list where four different sets exist. The witness in `tests/test_cli.py` parses the
documented table **out of the spec** and compares it to real output, so spec and CLI cannot drift
apart again.

**Refuted — do not "fix" these**, they were reproduced and found accurate:

- `docs/release-checklist.md` "30 byte-identical fixture bundles" — `check_manifest` compares every
  fixture file's SHA-256 to the recorded digest.
- `docs/receipts-and-replay.md` index narration — describes exactly the post-F-AUDIT-13/14
  behaviour.
- `spec/release.md` "a release test proves an installed wheel takes the resource path" —
  `RuntimeResources` plus the package CI job assert it.

The temporal half of 16 closed earlier in `edbd854` (the "readings are monotone" claim).

## F-AUDIT-18 — reproduced, NOT repaired

A harmless local shell script that answers `--version` with `verify-run 0.1.0a3` and does nothing
else is **accepted by the adapter as the implementation under test**. Worse than the finding
stated: the capabilities reply reports
`implementation.module_location = <checkout>/vfy/__init__.py` — the adapter describes *the Python
module it can import*, which in that invocation is the repository checkout, while the executable
under test is the stand-in. So the reply asserts "verify-run 0.1.0a3" about a program that is not
verify-run at all.

Reproducer (harmless, local only):

```sh
printf '#!/bin/sh\ncase "$1" in --version) echo "verify-run 0.1.0a3";; esac\n' > /tmp/spoof/vfy
chmod +x /tmp/spoof/vfy
echo '{"operation":"capabilities","profile":"decision-replay-v1"}' \
  | python tools/conformance_adapter.py --vfy /tmp/spoof/vfy
```

**Do not invent a second identity system.** `tools/build_reference_result.py` already hashes the
wheel *before* install and passes `--vfy <env>/bin/vfy` as an absolute path, so a PATH-prepended
fake cannot reach it. What is missing is that (a) the result document does not carry the
orchestrator-measured wheel digest, and (b) nothing asserts the executable came from that wheel.
The repair is to have the **orchestrator** write the digest it measured into the result and to
prove the installed distribution's `RECORD` corresponds to it — the implementation keeps
self-reporting only descriptive fields.

## F-AUDIT-18 — what closed and what did not

**Closed** (`37830db`): `module_location` was probed with `sys.executable` — the *adapter's* own
interpreter — so it always reported the checkout regardless of `--vfy`. Now read from the
interpreter the tested executable runs on, `None` when undeterminable. The reply is marked
`self_attested`. `check_conformance_result.py --artifact` measures the file itself and joins it to
`reference-result.json`; one-byte change, zero-byte file and missing file all fail, identical bytes
pass under any name.

**Not closed**: nothing asserts the executable *came from* the measured wheel. The orchestration
makes it true (hash, install that file, invoke by absolute path) but does not assert it. Next step
is binding the installed distribution's `RECORD` to the wheel digest.

The binding must stay out of the result document: `decision-replay-v1`'s result schema is frozen
with `additionalProperties: false`.

## Traps in this arc

- `echo $?` after a pipe reads the **last** command's status. Two hostile cases reported exit 0
  while failing.
- **zsh does not word-split unquoted parameters.** `$A` holding `--artifact path` reached argparse
  as one malformed argument, producing exit 2 that looked like a checker defect.
- Editing any file under the kit MANIFEST invalidates the kit until
  `tools/build_conformance_manifest_of_record.py` is re-run — including the checker itself.

## Next dependency

**F-AUDIT-18's remaining step** — assert the installed distribution's `RECORD` corresponds to the
measured wheel. Then `19` (three separate subfindings: TTL-at-spend reachability, the Python matrix
claim, CI action mutability), then `17`/F9 reproduction-only.

Note on the governing mandates: their prose uses several words this repository's own vocabulary
gate bans. None were written into any source, spec, or doc file — the gate fails the build if they
are, which it did once when this very note tried to quote one of them. The product-role statement it asks for is recorded here in permitted
vocabulary: verify-run is the deterministic decision-and-receipt runtime; anything conversational,
tenanted, billed, or administrative belongs above it and none of it exists in this tree.

F-AUDIT-17/F9 is **unreproduced** in this session. It stays `FOUNDER_DECISION_REQUIRED` on the
existing analysis rather than being downgraded on no evidence.

F9 / F-AUDIT-17 stays fenced: reproduce and classify only, and stop for a founder decision if
closing it would change authorization identity.
