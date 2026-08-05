# Quickstart

Ten minutes end to end; the gated part takes about a second. Everything is local.

## 1. Install

```bash
python -m pip install verify-run
vfy --version
```

```
verify-run 0.1.0a1
```

## 2. Create a workspace

```bash
mkdir demo && cd demo
vfy init --template pipeline-gate
```

This writes exactly two things: `rulebook.yaml`, copied byte for byte from the template, and
`.vfy/`, which holds your configuration, two freshly generated signing keys, and the local store.

```
demo/
  rulebook.yaml
  .vfy/
    config.json          delivery configuration
    keys/
      authorization.key  Ed25519 seed, mode 0600, never printed
      receipt.key        Ed25519 seed, mode 0600, never printed
      trust.json         the public half — what this workspace verifies against
    store.json
    index.json           derived, subordinate
    receipts/
    consumed/
    tmp/
```

The keys are yours and are generated locally. Nothing is uploaded, and no private byte is ever
printed by any command. Re-running `init` over an unchanged workspace changes nothing; if you have
edited `rulebook.yaml`, it refuses rather than overwriting your work.

## 3. Give the rulebook something to work with

`pipeline-gate` gates a deploy on a tracked `branch` and on fresh, passing tests. It declares one
piece of evidence — a command whose stdout is JSON:

```yaml
evidence:
  - {id: tests, source: exec, ref: "./ci/last-test-result.sh", max_age_seconds: 900}
```

Create that, and a harmless program to gate:

```bash
mkdir -p bin ci
printf '#!/bin/sh\nprintf "deployed %s\\n" "$1"\n' > bin/deploy.sh && chmod +x bin/deploy.sh
printf '#!/bin/sh\nprintf %s "\\"passed\\""\n' '' > ci/last-test-result.sh && chmod +x ci/last-test-result.sh
```

## 4. Gate a command

```bash
vfy run --identity branch=main -- bin/deploy.sh v1.2.3
```

```
ALLOW   bin/deploy.sh v1.2.3   rule: tests-green-on-main
        rule_allow: Tests green on main within freshness bound.
        receipt .vfy/receipts/r-b4b83611eecc18cf00ca07a0.json
        executed, exit 0
```

Everything after `--` is the command, verbatim. `--identity` supplies the rulebook's `track`
fields; a track field with no value simply cannot satisfy a rule that needs it, which is a HOLD
rather than an error.

### About the program path

`bin/deploy.sh` contains a separator, so it names a path. A **bare** name like `deploy.sh` is
resolved along `search_path` in `.vfy/config.json` — never `PATH`, never your shell's environment
— and the resolved path is what gets recorded and authorized. That matters: without it, one
receipt could mean different programs on different machines.

Nothing resolves? You get `cli_executable_not_found` before anything is evaluated or run.

## 5. See the other three outcomes

```bash
vfy run --identity branch=feature -- bin/deploy.sh v1.2.3
```

```
BLOCK   bin/deploy.sh v1.2.3   rule: wrong-branch
        rule_block: Deploys only from main.
        receipt .vfy/receipts/r-075c672f2cb9c2fc2c859194.json
        nothing executed
```

Break the evidence command and try again:

```bash
printf '#!/bin/sh\nexit 3\n' > ci/last-test-result.sh
vfy run --identity branch=main -- bin/deploy.sh v1.2.3
```

```
HOLD    bin/deploy.sh v1.2.3
        evidence_unsettled tests: Evidence could not settle this rule.
        receipt .vfy/receipts/r-940642b37391e90eba0091c8.json
        nothing executed
```

The tests did not fail — they could not be read. `verify-run` holds instead of guessing, and the
receipt says which evidence was unsettled.

ERROR appears when the request itself is malformed: an invalid candidate, an unparseable rulebook.
It is not a decision, so it emits no receipt.

## 6. Preview without running anything

```bash
cat > candidate.json <<'JSON'
{"candidate_id": "c-1", "kind": "command",
 "action": {"summary": "deploy", "argv": ["./bin/deploy.sh", "v1.2.3"]},
 "identity": {"branch": "main"}}
JSON
vfy check candidate.json
```

`check` reaches a decision and stops. It authorizes nothing, consumes nothing, starts no process,
and writes no receipt — the last line of its output says so. Use it to try a rulebook change
before letting it govern anything.

## 7. List and replay

```bash
vfy receipts list
```

```
BLOCK   r-075c672f2cb9c2fc2c859194   2026-08-05T18:04:14Z  pipeline-gate@1.0.0
HOLD    r-940642b37391e90eba0091c8   2026-08-05T18:04:14Z  pipeline-gate@1.0.0
ALLOW   r-b4b83611eecc18cf00ca07a0   2026-08-05T18:04:14Z  pipeline-gate@1.0.0
listed from the committed records, which govern
```

```bash
vfy replay .vfy/receipts/r-b4b83611eecc18cf00ca07a0.json
```

```
ALLOW   r-b4b83611eecc18cf00ca07a0
  verification  signature verified
  replay        recomputed and identical
  authorization verified against the recorded bindings
```

Replay reads the receipt and the bodies stored beside it, verifies the signature against your
trust file, and recomputes the decision. It runs nothing and fetches nothing.

## 8. Machine-readable output

Every command takes `--json` and prints one canonical JSON object on stdout, with diagnostics on
stderr:

```bash
vfy --json run --identity branch=main -- bin/deploy.sh v1.2.3
```

```json
{"command":"run","executed":true,"exit_status":0,"matched_rule":"tests-green-on-main","notes":[],"outcome":"ALLOW","reasons":[{"code":"rule_allow","message":"Tests green on main within freshness bound.","rule_id":"tests-green-on-main"}],"receipt_id":"...","receipt_path":".vfy/receipts/....json"}
```

Exit codes: `0` ALLOW, `10` BLOCK, `11` HOLD, `12` ERROR, `13` ALLOW but the command failed,
`14` ALLOW but the record could not be written, `1` operational failure, `2` usage error.

A non-zero command does **not** turn ALLOW into BLOCK. The decision stays what it was; the exit
code tells you the authorized action failed.

## The other templates

- `agent-guard` — gate an AI agent's tool calls and shell commands.
- `claims-gate` — an insurance claims workflow. It declares HTTP evidence, which this alpha does
  not acquire, so it holds locally and names the source. That is the honest local behavior, not a
  broken rulebook.
