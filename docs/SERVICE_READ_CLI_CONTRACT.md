# Public bounded service reading CLI / 1

Engineer must invoke the installed `vfy` executable, never import any vfy module.
These commands expose only reading. No audit exception/allowlist, source-isolation
relaxation, service execution, action adoption or live accounting interface.

```
vfy verify-service-receipt --request-sha256 HEX
vfy reconcile-service-repair --request-sha256 HEX
```

One UTF-8 strict JSON document on stdin, closed at EOF. Hash HEX is the caller's
independently selected SHA256 of EXACT stdin bytes, including any newline. Hard
stdin maximum 16MiB, read at most limit+1 before parsing. Every embedded value is
`{"base64":"<canonical padded RFC4648>","sha256":"<64 lowercase hex>"}`.
Duplicates, unknown fields, invalid/noncanonical base64, wrong hashes and versions
refuse. Each decoded input <=4MiB; combined decoded inputs (including trust) <=
selected input_bytes <=8MiB. No private key field exists. Public trust must be
independently selected, not taken from an embedded receipt. Encoder/caller code
uses standard JSON/base64/SHA256 only; no vfy import is required.

## Historical receipt request

```
{
  "schema": "vfy.verify-service-receipt-request/1",
  "inputs": {"receipt": {"base64": "...", "sha256": "..."},
             "trace": {"base64": "...", "sha256": "..."},
             "request": {"base64": "...", "sha256": "..."},
             "ticket": {"base64": "...", "sha256": "..."},
             "policy": {"base64": "...", "sha256": "..."},
             "trust": {"base64": "...", "sha256": "..."}},
  "module_sha256": "99c42d7d4ba0b00432a452fccaa744ef5b20f4a85f04d86375441f4b18a4d8cb",
  "owner_issuer": "<independently selected accounting receipt issuer>",
  "limits": {"input_bytes": 8388608, "trace_entries": 3000, "output_bytes": 65536}
}
```

Delegates to unchanged service_review_receipt.verify_receipt. Exact historical
result is returned without source/pool traversal, current key claims or spending
keys. trace_entries <=100000; receipt verifier retains its existing tighter per-input
bounds. Historical UNKNOWN and absence of settlement/freshness remain unchanged.

## Selected read-only reconciliation request

```
{
  "schema": "vfy.reconcile-service-repair-request/1",
  "root": "<canonical retained operation root>",
  "inputs": {"plan": {"base64": "...", "sha256": "..."},
             "trust": {"base64": "...", "sha256": "..."}},
  "module_sha256": "0c98ad29c930d7a772ebe2203ab0c7a1c12f958ddaa4abb5f14e70d04826be66",
  "limits": {"input_bytes": 8388608, "read_bytes": 67108864,
             "read_calls": 10000, "output_bytes": 65536}
}
```

Root must match the selected plan. Public trust selects the original completion
receipt owner. No caller-supplied Python code or module path is executable: the
module is the hash-checked installed sibling at the fixed above identity.
Reconcile runs in private globals with bounded read_file and fail-closed directory
enumeration, as in the accepted paid wrapper. A cached identity describes the exact
loaded bytes, avoiding additional self-file reads. No shared-module monkeypatch.
No fixture, pool, operation, service or history writes and no reconciliation retry.
Changed/unreadable/partial content, missing receipt or exhausted read limits remain
UNKNOWN, never readiness. Original module and plan identities are unchanged.

read_bytes/read_calls bound payload access through the reconciliation reader:
max64MiB and10000 calls, requested size charged before reading, failed/short reads
conservatively counted. Limits do not reserve a paid pool. Module hash-check/loading
is separately capped at4MiB; stdin already supplied plan/trust bytes are bounded
separately. Imports, metadata/locks, CPU/wall/physical I/O and all lifecycle costs
remain excluded/UNKNOWN. Callers impose their own process timeout. These are explicit
uncharged reader operations, not a substitute for paid-review or full-cost closure.

## Exact response and status contract

Always one canonical JSON response plus newline on stdout, <=selected output_bytes
(1024..65536), hard max64KiB. No human text on successful stdout. Shape:

```
{
 "schema":"vfy.service-read-cli-response/1", "command":"<command>",
 "request_sha256":"<stdin hash>", "state":"READ_COMPLETED",
 "mode":"HISTORICAL_RECEIPT | SELECTED_READ_ONLY_RECONCILIATION",
 "result":{...unchanged underlying result...},
 "read_usage":null | {"read_bytes":N,"read_calls":N},
 "read_incomplete":false, "error":null, "full_cost":"UNKNOWN",
 "read_cost_charged":false, "authority_granted":false, "automatic_retry":false
}
```

Read budget/enumeration failure sets read_incomplete=true and result UNKNOWN.
Exit0 means transport/read response completed, INCLUDING UNKNOWN; never ALLOW,
readiness, action authority or current acceptance from historical evidence. Engineer
historical display should preserve its own exit2 convention. Invalid selection,
bad signature/input, module mismatch or oversized response returns exit12 with
state REFUSED, result null and bounded error class; no source contents are echoed.
Malformed CLI arguments/help retain standard argparse exit2/0 behavior. Stdout I/O
failure exits1. Parser errors go to stderr; request refusals use the JSON response.
The global --execution-report option is incompatible. --json is unnecessary.

No receipt, nonce or live capability is exported/imported as a spending substitute.
Installed development acceptance is separate from public release, all-command a7
compatibility, complete CI and ordinary Engineer/Platform product acceptance.
