# verify-run

**A local, deterministic gate that decides whether a consequential command is allowed to run —
and leaves a signed receipt you can replay offline.**

Alpha. Everything runs on your machine. No account, no database, no browser, no network call, no
telemetry.

## The problem

Software is increasingly allowed to act: agents run shell commands, pipelines deploy, workflows
move money. The usual controls are a code review before the fact and a log line after it. Neither
tells you *why* a specific action was permitted, under which rules, against which evidence — and
neither lets anyone check that answer later without trusting whoever wrote the log.

`verify-run` puts one deterministic decision between the intent and the action, and records it in
a form that can be recomputed from its own inputs.

## Where verify-run fits

This is one layer, deliberately: the local boundary that settles a consequential action and leaves
a record anyone can recompute. It is not the whole of VERIFY, and reading it as a complete
operating plane for a large organization will make it look strangely small.

The things such an organization also needs — distributing rulebooks across many machines, retaining
receipts somewhere durable, managing keys at organizational scale, acquiring evidence from remote
systems, authoring the rules in the first place — are built *around* this runtime rather than
inside it. None of them is in this repository, and that is the design rather than an omission. Each
one would put a clock, a network, a database, or an account inside the component whose entire value
is having none of them. A decision is not more trustworthy because the thing that reached it was
larger; it is more trustworthy because you can recompute it offline from its own recorded inputs.

The evidence contract is what keeps the split honest. Something outside may acquire and govern an
input; what reaches `verify-run` is a frozen value with a recorded acquisition instant. The runtime
settles the decision. Whatever fetched the input never does.

## Install

```bash
python -m pip install verify-run
```

Requires Python 3.11 or newer. Two dependencies: PyYAML and cryptography.

## 90-second quickstart

```bash
mkdir demo && cd demo
vfy init --template pipeline-gate
```

```
initialized  .
  rulebook   rulebook.yaml   (template pipeline-gate)
  runtime    local-033506d02ab8629c
  store      .vfy
  keys were generated in .vfy/keys; the private halves are never printed.
```

The template gates a deploy on two things: the branch, and fresh passing tests. Provide both —
a program to gate, and the command that reports test status:

```bash
mkdir -p bin ci
printf '#!/bin/sh\nprintf "deployed %s\\n" "$1"\n' > bin/deploy.sh && chmod +x bin/deploy.sh
printf '#!/bin/sh\nprintf %s "\\"passed\\""\n' '' > ci/last-test-result.sh && chmod +x ci/last-test-result.sh
```

Now gate the deploy:

```bash
vfy run --identity branch=main -- bin/deploy.sh v1.2.3
```

```
ALLOW   bin/deploy.sh v1.2.3   rule: tests-green-on-main
        rule_allow: Tests green on main within freshness bound.
        receipt .vfy/receipts/r-b4b83611eecc18cf00ca07a0.json
        executed, exit 0
```

Try it from the wrong branch, and from a state where the tests cannot be read:

```
BLOCK   bin/deploy.sh v1.2.3   rule: wrong-branch
        rule_block: Deploys only from main.
        receipt .vfy/receipts/r-075c672f2cb9c2fc2c859194.json
        nothing executed

HOLD    bin/deploy.sh v1.2.3
        evidence_unsettled tests: Evidence could not settle this rule.
        receipt .vfy/receipts/r-940642b37391e90eba0091c8.json
        nothing executed
```

List what happened, and recompute any of it:

```bash
vfy receipts list
vfy replay .vfy/receipts/r-b4b83611eecc18cf00ca07a0.json
```

```
ALLOW   r-b4b83611eecc18cf00ca07a0
  verification  signature verified
  replay        recomputed and identical
  authorization verified against the recorded bindings
```

Every transcript above is real output from this version. Full walkthrough:
[docs/quickstart.md](docs/quickstart.md).

## Four outcomes, never collapsed

| Outcome | Meaning | Exit code |
|---|---|---|
| **ALLOW** | The rulebook and the evidence authorize this exact action. | 0 (13 if the command itself failed) |
| **BLOCK** | The rulebook reached a negative result. The receipt names which rule. | 10 |
| **HOLD** | The rulebook *cannot settle it* — evidence missing, stale, or conflicting. Not a failure. | 11 |
| **ERROR** | The request was malformed; evaluation never validly began. Not a decision. | 12 |

HOLD is the one most systems get wrong. "I don't know" is a different answer from "no", and
merging them is how a gate starts silently guessing.

## The workflow

```
vfy init      create a workspace from a template
vfy check     evaluate a candidate without running it (evidence is still acquired)
vfy run       gate a command
vfy replay    verify and recompute a stored decision
vfy receipts  list, or show one with verification and replay
```

`check` is a preview: it reaches a decision and writes nothing. It does acquire the evidence the
rulebook declares, which for an `exec` declaration means running that evidence command — it is the
candidate's own action that never starts. `run` is the governed path — it
evaluates, and on ALLOW it issues a single-use authorization bound to that exact command, consumes
it, launches, records what happened, signs a receipt, and stores everything replay needs.

## The rulebook

```yaml
rulebook_id: pipeline-gate
version: 1.0.0
adopted_at: "2026-08-05T00:00:00Z"
track: [branch]
evidence:
  - {id: tests, source: exec, ref: "./ci/last-test-result.sh", max_age_seconds: 900}
rules:
  - id: tests-green-on-main
    when: 'identity.branch == "main" and fresh(tests) and evidence.tests == "passed"'
    outcome: ALLOW
    reason: Tests green on main within freshness bound.
  - id: tests-red
    when: 'fresh(tests) and evidence.tests == "failed"'
    outcome: BLOCK
    reason: Tests failed.
default_outcome: HOLD
authorization: {ttl_seconds: 300, single_use: true}
```

Rules are tried in order; the first one that is *true* decides. A rule that cannot be settled
stops the walk and holds. See [docs/rulebook-reference.md](docs/rulebook-reference.md).

## Supported evidence

- **`file`** — a local JSON file.
- **`exec`** — a local command whose stdout is JSON.

**`http` is not implemented in this alpha.** A rulebook may declare it — the bundled `claims-gate`
template does — and nothing is faked: the item is recorded as missing, the rulebook holds, and the
CLI names the source. That is the correct answer for evidence nobody acquired, not a defect.

Nor does a remote fact require an HTTP client *in here*. Anything that can print JSON is an `exec`
source, so a caller that fetches a remote value and prints it supplies evidence the runtime freezes
and evaluates like any other, with the runtime stamping when it was acquired. Teaching this
evaluator about TLS, retries, redirects, credentials, and timeouts would enlarge the one component
that is worth keeping small — and it would put a network read inside a function whose determinism
is the reason replay works at all.

## Not in this alpha

HTTP evidence, `watch` mode, `serve` mode, hosted registry or vault, fleets, accounts, billing, a
browser interface, device/GPIO support, and the npm runtime. None of these exist here.

## What replay does and does not mean

Replay **recomputes the decision** from the exact recorded rulebook, candidate, and evidence
snapshot, and compares the result byte for byte. It also verifies the receipt's signature against
a key registry *you* supply.

Replay does **not** re-run the command, re-acquire evidence, contact any system, or establish that
the world changed. A receipt records that a runtime reported an exit status — not that a deploy
succeeded. See [docs/receipts-and-replay.md](docs/receipts-and-replay.md).

## Security model, briefly

- Trust roots are key registries you control. An artifact never certifies itself.
- An authorization is issued only on ALLOW, bound to the exact command, rulebook, and evidence
  digests, and is single-use — consumed **before** the process starts.
- No shell is ever involved. Arguments are passed literally.
- The parent environment is not inherited; a gated command sees only what your config names.
- **This is not a sandbox.** The command runs with your privileges.
- **Exactly-once external execution is not claimed.** A crash after consumption and before launch
  spends the authority without acting; a crash after launch may change the world without a stored
  receipt. Both are stated plainly rather than papered over.

Full boundaries, including what is deliberately *not* guaranteed:
[docs/security.md](docs/security.md).

## Determinism

Evaluation is a pure function of the pinned rulebook, the candidate, and the frozen evidence
snapshot. It reads no clock, no randomness, no environment, no network, and no locale. The same
canonical inputs produce byte-identical outputs — which is what makes replay checkable at all.

Timestamps, key generation, and nonces live at the command-line edge and enter the trusted layers
only as recorded values.

## Python support

Requires `>=3.11`. Developed and fully tested on CPython 3.14 (macOS, arm64); continuous
integration covers 3.11, 3.12, and 3.13 on Linux. Other platforms are expected to work but are
not yet proven — see [docs/security.md](docs/security.md) for the exact platform caveats.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -t .
```

Standard-library `unittest`, no test-framework dependency. The `spec/` directory is the authority
and `fixtures/` holds the golden vectors; implementations conform to them, never the reverse.

## Decision replay conformance

> The same declared inputs deterministically settle to one of four non-collapsible terminal
> classes; an exact ALLOW creates action-bound authority; and the resulting artifact permits the
> recorded decision to be independently verified and fully recomputed without trusting the
> platform database.

That claim is now written down as a public, vendor-neutral contract with fixtures anyone can run:
[Decision Replay Conformance Profile v1](docs/conformance/decision-replay-v1.md), profile id
`decision-replay-v1`. `verify-run` is its first reference implementation, not its definition.

```bash
sh tools/conformance_reference_run.sh
```

That installs the version this checkout declares — currently `0.1.0a3` — from PyPI into a clean
environment, runs the 30 fixtures against it, and writes a result document. Name any published
version to test it instead: `sh tools/conformance_reference_run.sh out 0.1.0a2`. The profile and
its fixtures are the same either way; only the implementation under test changes.

That script needs the version to be *published*, so it cannot test a candidate that only exists on
your machine. For that, `tools/build_reference_result.py` builds the wheel from this tree, hashes
it, installs that exact file into a clean environment, runs the kit against it, and records the
artifact digest beside the result. The reference claim below is generated from that record rather
than written by hand — a claim about an artifact has to come from the artifact.

**Replay recomputes the recorded decision. It does not re-execute the action**, does not reacquire
evidence, and does not prove the action's effects occurred in the world. A result is a *self-test*,
not certification: nobody accredits this profile, and a PASS is meaningful only together with the
profile version and fixture-manifest digest it names. See
[docs/conformance/claims.md](docs/conformance/claims.md) for exactly what a result lets you say,
and §16 of the contract for what it deliberately does not establish.

Current reference result: **PASS**, 30/30 fixtures, `verify-run 0.1.0a3`, fixture manifest
`756029f681ad7587…`.

That sentence is checked against [`conformance/reference-result.json`](conformance/reference-result.json),
which names the exact wheel it was measured against by SHA-256. A version number alone would not
distinguish two artifacts that print the same banner.

## Alpha status

Version `0.1.0a3`. The decision semantics, canonical form, and receipt format are frozen and
covered by golden vectors — neither `0.1.0a2` nor `0.1.0a3` changed any of them, and every
`0.1.0a1` and `0.1.0a2` receipt still verifies and replays. The command surface is the five
commands above. Interfaces may still change before 1.0; recorded artifacts carry a `spec_version`
so a future change cannot silently reinterpret an old receipt.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
