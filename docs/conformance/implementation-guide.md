# Implementing the Decision Replay profile

A guide for someone building a second implementation. The normative contract is
`decision-replay-v1.md`; this is the practical companion.

## 1. Map your objects onto the declared inputs

The profile names four: the rulebook (the policy that governed), the candidate (the action
proposed), the evidence snapshot (what was observed, frozen), and — on ALLOW — the authorization.
If your system calls these something else, that is fine. What matters is that each one is
**recorded** and that recomputation needs nothing beyond them.

The usual failure here is a decision that quietly depends on a database row, a live lookup, or a
default that lives in code. If removing your database would break replay, you do not yet satisfy
DR-1.3.

## 2. Keep four terminal classes

ALLOW, BLOCK, HOLD, ERROR. The pressure to collapse them is constant and always comes from a
sympathetic place: dashboards want two colours, and HOLD is awkward to explain. Collapse them and
the contract is gone, because "we could not settle this" and "the rulebook said no" are different
facts with different consequences, and ERROR is not a decision at all.

## 3. Produce exact authority on ALLOW

Bind the candidate, the rulebook, and the evidence snapshot by digest. Carry a validity interval
and a single-use identifier. Scope the single-use claim to the store you can actually enforce it
in, and say so — a claim of global uniqueness you cannot enforce is worse than a modest one you can.

## 4. Emit a portable protected artifact

Canonicalize, sign the artifact with its own signature member omitted, and record the key identity.
Then check the property that matters: hand the artifact and a public key to someone who has none of
your software running, and see whether they can verify it.

## 5. Expose verify and replay

Verification answers "is this authentic and unaltered". Replay answers "does the recorded decision
follow from the recorded inputs". They are different claims and should be reported separately.

## 6. Do not reacquire, and do not re-execute

Replay reads recorded inputs. It does not call the evidence source again, does not rerun a model,
and does not perform the action. The cheapest way to prove this to yourself is the way the fixtures
do it: delete the evidence sources and the executable, then replay. If it still works, you have it.

## 7. Separate present spendability from historical validity

This is the requirement implementations most often get wrong, including the reference one, which
shipped it wrong in `0.1.0a1` and repaired it in `0.1.0a2`.

A validity interval bounds when an authorization may be **spent**. Replay spends nothing. If your
replayer compares the recorded interval against the current clock, every ALLOW record you hold will
stop verifying minutes after you wrote it — and those are precisely the records of actions that
actually happened. Check that the interval was well-formed and bound to these inputs. Do not check
it against now.

## 8. Write an adapter

See `conformance/decision-replay-v1/adapter-protocol.md`. One JSON request in, one JSON envelope
out. Declare your error-category mapping in one readable table. Do not let the adapter decide
anything.

## 9. Run the fixtures

The runner needs Python 3.8 or newer and says so plainly if it does not have it. The
*implementation* under test may need something else entirely; that is your adapter's business, and
the reference adapter states its own floor — Python 3.11, from `verify-run`'s package metadata —
the same way.

```bash
python3 tools/run_conformance.py \
    --profile conformance/decision-replay-v1/profile.json \
    --adapter "your-adapter-command" \
    --out result.json
```

`--adapter` is split with shell-like quoting rules. If any path in your command contains a space,
give the command as repeated `--adapter-arg`, one argv token each, which is never split — and use
the attached form for a token that starts with a dash:

```bash
python3 tools/run_conformance.py \
    --profile conformance/decision-replay-v1/profile.json \
    --adapter-arg "/opt/My Tools/python3" \
    --adapter-arg "/opt/My Tools/adapter.py" \
    --adapter-arg=--verbose \
    --out result.json
```

Then check the result, and the kit that produced it, in one step:

```bash
python3 tools/check_conformance_result.py result.json
```

### Reading the verdict

| Exit | `overall` | What it means |
|---|---|---|
| 0 | PASS | every required fixture behaved as the manifest says |
| 1 | FAIL | at least one did not — that is a statement about your implementation |
| 2 | INCOMPLETE | the run could not be conducted; **nothing was measured** |
| 3 | — | the runner itself could not start: no profile, no adapter, wrong interpreter |

**INCOMPLETE is not a soft PASS, and it is not a quiet FAIL.** It means a required fixture was
skipped, the fixture manifest did not match the bytes on disk, or the harness never actually put
the fixtures to your implementation — the adapter would not start, timed out, did not speak the
protocol, or reported an `adapter_error` of its own. The runner prints what stopped it on stderr.
Fix the harness and run again; there is no verdict to argue with yet.

## 10. Publish honestly

`docs/conformance/claims.md` states exactly what a result lets you say. It is shorter than you
expect.

## A worked example, not insurance-specific

A build system gates a deploy. The rulebook says: deploy only from the release branch, and only
when the test report is fresh and green. The candidate is `deploy v1.2.3`. The snapshot records
the branch and the test report as they were at one instant. The terminal is ALLOW, an authorization
binds those three by digest, the deploy runs, and the runtime reports back an exit status.

Six months later an auditor asks why that deploy was allowed. They take the artifact and the public
key, and they recompute: the same rulebook, the same candidate, the same snapshot, the same ALLOW.
They do not need the build system, the CI database, or the company. Nothing redeploys. That is the
whole claim, and it is worth exactly as much as the evidence that was recorded — no more.
