# Keyless historical child report transport, edition 2

This is a separately selected **read-only historical report verifier**, not the
complete dev3 distribution, admission, original custody recovery or hosted CI
acceptance. The original manifest, 44-member archive and evidence remain unchanged.
Root owns consumer wiring. Do not replace MANIFEST_SHA, change old pins, or make
old admission tests pass by substituting this interface.

## Delivery

Private evidence branch `codex/run-service-session-evidence-20261016`, directory
`recovery/child-measured-keyless-20261016/` contains the archive, standalone checker,
exact inventory, validation, negative controls, current-loader refusal and receipt.
Source branch `codex/run-service-session-cli-20261016` contains packaging/check tools.

Archive `child-measured-keyless.zip`: 367380 bytes, SHA256
`871665be52e8be723604816d61f8a97b21080d3b7be9a7660cf9cdaf8fc600ef`.
Checker `check_child_measured_keyless.py` SHA256
`e54e9683053d378f2feb1e0a2ed2c4e51d3da2eb88069d38a335953945febfdf`.

Exactly 49 regular members: the previous 44 members byte-for-byte, plus original
`source/vfy/{__init__,canon,load,errors,child_ledger}.py`. All five match the exact
original manifest `29a068926de05684569b57555996b6d963c4e1ad596741c8a933937192547926`.
The manifest is retained as original provenance, NOT represented as fully supplied.
No signing keys, mutable state, pending files, pools or owner capabilities included.
The 45 prohibited key-bearing source fixture names are enumerated without key bytes.

## Hosted consumer command

Fetch this private checkpoint with existing authorized private read credentials;
verify archive and checker digests independently before running. Use Python 3.12+
on POSIX with cryptography and PyYAML installed in an isolated environment. The
local checked dependency versions were cryptography50.0.2 and PyYAML6.0.3; this
is not a dependency lock or Linux acceptance receipt.

```
python -I -B check_child_measured_keyless.py child-measured-keyless.zip \
  --sha256 871665be52e8be723604816d61f8a97b21080d3b7be9a7660cf9cdaf8fc600ef \
  --self-test
```

No stdin. Selected archive bounded to2MiB, expanded bytes to2MiB, exactly49 members;
duplicates, nonregular/compressed/traversing members and changed original code refuse.
The checker extracts only selected bytes to a new temporary directory, then forbids
writes, launches/network and original `/Users/devinbostick/` reach-through. Temporary
extraction is retained for inspection; read-only describes verification after setup,
not zero setup I/O. These audit checks are defenses for this trusted selected code,
not a general hostile-code sandbox or complete lifecycle accounting claim.

stdout is JSON `run.child-measured-keyless-check/1`, with `reports` indexed first,
follow-on, interrupted. Original report return values are preserved verbatim.
Exit0 means this selected historical verification completed; it never grants action
permission or freshness. `authority_granted:false`, `automatic_retry:false`,
`freshness:UNKNOWN`, `full_cost:UNKNOWN`, `hosted_ci_closure:false` are explicit.
Companion correspondence and admission/custody are NOT_CHECKED. Exit2 returns UNKNOWN
on selection, integrity or verification failure. Root must retain report UNKNOWN
children and exposure values; do not translate exit0 into execution/CI/full-target closure.

## Validation and exact remaining dependence

A fresh isolated process verified all three reports using transported source only,
with original-host reads prohibited.15 report tamper controls refused. A separate
process harness verified wrong selected archive digest, rebound changed source,
missing member and duplicate member refusal. All49 retained bytes remained unchanged.
Validation ran on macOS, not Linux; no hosted CI success is claimed.

Current Engineer measured_children source remains SHA
`0be1cadd8c4dbc1fb9ef0ab4871c49147100000f99bc9d54225b0013e3f16476`.
Its actual load_reviewed_source refused this relocated subset before importing Run,
at missing `.github/workflows/ci.yml`. Its loop requires all1060 original members,
including45 files containing literal signing keys. This cannot simultaneously satisfy
exact unchanged manifest loading and no-key transport. Adding all nonkey members
would still fail on the key-bearing members; redaction/manifest rewriting is forbidden.

Additionally, old inspect_request requires the original macOS executable hash/path,
original START and payload paths; recovery requires excluded mutable original custody.
Transport alone cannot close those tests. Root can integrate the new historical check
as its explicitly scoped contract, while keeping original-runtime/custody-dependent
claims unresolved. Admission would need a separately reviewed fresh portable producer
contract and synthetic fixture, not reconstructed original effects. No such admission
or test exemption is authorized by this packet. No claim that52setup/166failuresclosed.
