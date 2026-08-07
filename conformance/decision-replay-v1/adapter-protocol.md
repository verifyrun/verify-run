# Adapter protocol

> **What is frozen, and what this file is.** The profile's normative requirements are the `DR-*`
> statements in `../../docs/conformance/decision-replay-v1.md`, together with the fixture set and
> its manifest digest. Those are frozen at the `conformance-v1.0.0` tag and are byte-identical on
> current `main`. **This file describes the harness**, not the implementation under test, and on
> current `main` it has gained *additive* clarification since that tag — the `accepted` section and
> the `adapter_error` section below. Nothing here changes which observations conform, and no
> fixture verdict depends on it: `0.1.0a2` passed 30/30 before and after, and `0.1.0a1` still fails
> the same four. To reproduce the claim exactly as it was frozen, read this file at the tag:
> `git show conformance-v1.0.0:conformance/decision-replay-v1/adapter-protocol.md`.
>
> A future change that altered what an implementation must *do* would require a new profile
> version, not an edit here.

The runner is vendor-neutral and speaks to an implementation only through an adapter: a command
that reads one JSON request on standard input and writes one JSON envelope on standard output.
Any language, any transport underneath.

## Request

    {"operation": "replay", "bundle": "<absolute path to a fixture bundle>", "profile": "decision-replay-v1"}
    {"operation": "capabilities", "profile": "decision-replay-v1"}

## Envelope

    {
      "adapter": "your-adapter-name",
      "implementation": {"name": "...", "version": "..."},
      "operation": "replay",
      "accepted": true,
      "terminal": "ALLOW",
      "signature_verified": true,
      "recomputed": true,
      "bindings_verified": true,
      "error_category": null,
      "implementation_reason": null,
      "raw": {"exit_status": 0, "stdout_sha256": "...", "stderr_sha256": "..."}
    }

`accepted` is false for a refusal, and then `error_category` MUST name one of the profile's neutral
categories and `implementation_reason` SHOULD carry the implementation's own code, unmapped.

### `accepted` is not "the command exited zero"

`accepted` means **the implementation took the artifact and produced a terminal**. A refusal is
`accepted: false`. Reaching BLOCK or HOLD is `accepted: true` — those are terminals, not errors,
and an adapter that treats them as refusals collapses two different observations into one and
fails every negative fixture for the wrong reason.

Most command-line implementations carry the terminal in the exit status, which means the mapping
from exit status to `accepted` is implementation-specific and belongs in the adapter's declared
table. For the reference implementation:

| `vfy replay` exit | `accepted` | `terminal` |
|---|---|---|
| 0 | true | ALLOW |
| 10 | true | BLOCK |
| 11 | true | HOLD |
| 1 | false | none — `error_category` from the reason code on stderr |

`spec/cli.md` states this for the implementation; it is repeated here because getting it wrong is
the most common way a new adapter produces a confident and meaningless result.

### An adapter that cannot conduct a call

An adapter that cannot run at all — no implementation installed, wrong interpreter, unreadable
bundle — MUST NOT report that as a refusal. It emits `{"adapter_error": "<what went wrong>"}` in
the envelope, and the runner records the run as INCOMPLETE rather than as a failure of the
implementation. A run that did not happen is not a test that failed.

## What an adapter may and may not do

An adapter **may** normalize transport shape: locate the implementation, lay a bundle out in
whatever directory structure the implementation expects, and map the implementation's own reason
codes onto the profile's neutral error categories. That mapping MUST be declared in the adapter, in
one table an auditor can read.

An adapter **may not** decide conformance. It reports observations; the runner compares them against
the fixture manifest. It **may not** collapse terminal classes, invent an observation the
implementation did not make, retry in a way that changes meaning, or emit private key material.

## Capabilities

The `capabilities` operation answers DR-9.1. It declares `accepted_profiles`,
`accepted_artifact_versions`, `historical_replay_supported`,
`migration_rewrites_protected_bytes`, `retired_keys_verify_history`, and `live_spend`.

`tools/conformance_adapter.py` is a worked example for `verify-run`, and is not normative.
