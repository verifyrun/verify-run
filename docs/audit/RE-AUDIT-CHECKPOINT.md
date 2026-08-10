# Re-audit checkpoint — F-AUDIT-01..19

Working notes for the closure arc. Not a public document: it records what was reproduced, what was
repaired, and what the next session does not need to re-derive. Delete before a stable release.

Local HEAD `86523cb`, 7 commits ahead of `origin/main` `58c49dd`, unpushed, clean tree.
`pyproject` version `0.1.0a3` — **unchanged on purpose**; `v0.1.0a3` is published and these
repairs mean the next release needs a new version.

## Ledger

| # | Finding | Reproduced | Status | Commit |
|---|---|---|---|---|
| 01 | decimal operand host-limit / raw ValueError | yes | CLOSED | `0b2129c` |
| 02 | executed signed receipt lost after record failure | yes | CLOSED | `7cd7a1d`, `ea8305c` |
| 03 | non-regular / oversized committed receipt | **yes** | **CLOSED** | `cdffbd3` |
| 04 | executable identity fidelity | not yet | OPEN | — |
| 05 | result ↔ kit binding | **yes** | **CLOSED** | `86523cb` |
| 06 | conducted FAIL laundered into INCOMPLETE | yes | CLOSED | `2feb303` |
| 07 | release scanners skipping by substring | yes | CLOSED | `fc0cfb9` |
| 08 | self-auditable sdist | not yet | OPEN | — |
| 09 | artifact-bound reference result | not yet | OPEN | — |
| 10 | canonical base64 signatures | not yet | OPEN | — |
| 11 | completion timeline after a backward clock | not yet | OPEN | — |
| 12 | outcome survival after completion-clock failure | not yet | OPEN | — |
| 13 | dangling index symlink read as absence | **yes** | **CLOSED** | `cdffbd3` |
| 14 | read-only listing that writes | **yes** | **CLOSED** | `cdffbd3` |
| 15 | secret-leak verdict asymmetry | yes | CLOSED (re-proved) | `2feb303` |
| 16 | docs / spec drift | not yet | OPEN | — |
| 17 | F9 nonce scope across store clones | not yet | **FENCED** | — |
| 18 | implementation identity behind a banner | not yet | OPEN | — |
| 19 | CI matrix / supply-chain cluster | not yet | OPEN | — |

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

## Next dependency

**F-AUDIT-10 (canonical base64) or F-AUDIT-08 (self-auditable sdist)** — 08 next per the mandate
order, which is `08 → 09 → 04 → 10 → 11/12 → 16 → 18/19 → 17`.

F9 / F-AUDIT-17 stays fenced: reproduce and classify only, and stop for a founder decision if
closing it would change authorization identity.
