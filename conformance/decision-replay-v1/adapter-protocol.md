# Adapter protocol

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
