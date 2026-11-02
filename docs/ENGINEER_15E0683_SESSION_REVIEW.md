# Run independent review — Engineer15e0683 public session consumer

Reviewed source at 15e06833a9309bfce1b99a3adbd5b2a22324f41a in
/private/tmp/verify-engineer-continuation-20261013. No Engineer edits/imports/tests,
service launches, retained C7 reads or used tmps5ogg2r3 operations replayed.
The reported31 source checks and actual synthetic Session acceptance belong to
Root; installed Engineer pair/actual service acceptance remain pending.

## Findings before the fresh actual-service run

P2 — cleanup exception leaks caller lock and masks the original failure.
service_observation.py:279-283 calls session.close() before os.close(lockfd), without
an inner finally. service_accounting_client.py:101-108 calls proc.wait(timeout=5)
before closing either pipe. A wait timeout or other shutdown exception skips both
cleanup steps. In the long-lived agent, the flock descriptor remains open and an
interrupted attempt stays locked beyond this function; the original failure is
replaced by cleanup failure. Use nested finally to unconditionally close lockfd,
and close pipes in a finally around bounded reap. Preserve the original exception
when already failing, while retaining cleanup failure as diagnostic/UNKNOWN. Also
put post-Popen nonblocking setup inside construction's protected cleanup region.

Deterministic reproduction: review-engineer-session-cleanup-20261016.py extracts
only execute_accounted's AST, substitutes all I/O/session interfaces, makes the
observation fail and shutdown time out. Output: TimeoutError, caller_lock_closed=false.
No real process, pool or Engineer module is invoked. This is a control-flow proof,
not a claim that an actual accepted service hung.

P2 — the client implements an I/O deadline, not the promised hard process deadline.
Session.deadline is checked only in _receive/exchange. Between ADMIT and CONSUME,
_execute does source/examiner/environment validation; between CONSUME and SETTLE it
performs observation and retention. No independent timer/watchdog kills the Run
process at the selected deadline during these intervals. Normally the Run pipe
reader enforces its own timeout, but Run's contract explicitly excludes blocked
filesystem validation/publication from that deadline and requires a caller hard
process timeout. A stalled caller interval plus a stalled Run cleanup/publication
has no client deadline enforcement. Add a bounded independent process watchdog
(or an outer supervised lifetime with equivalent guarantees), make expiration
terminal, and check expiration before launch. Do not reconnect or turn timeout into
a refund. This requirement is specific to the advertised process-lifetime bound;
it is not a claim of total physical-I/O or complete lifecycle accounting.

## Boundaries inspected as correct

- Reader residual incomplete-content finding is closed: both result.state and
  result.content_state must UNKNOWN when read_incomplete is true.
- Direct vfy imports removed from the reviewed accounting adapter/client. Only
  public vfy subprocess selection is used; no new key serialization into Engineer.
- Shared caller flock spans accounting marker, admission, _execute's fsynced START,
  matched CONSUME reply and durable ACCOUNTING_CONSUMPTION, launch and settlement.
- _consume failure prevents Popen; missing acknowledgment, malformed output and
  timeout terminate the session; no reconnect/resend path. ACCOUNTING/START block
  fallback or retry. Interrupted Run records may remain ADMITTED/CONSUMED with all
  reservations held; this is UNKNOWN/no-live-capability, not permission to retry.
- Wire sizes, exact outer fields, profile/session/sequence/frame hash, expected
  state/error and false flags are checked. SETTLED is not promoted to semantic
  success; terminal exit is checked. Installed executable trust remains an explicit
  prerequisite; matching echoes are not authentication of a malicious replacement.

The test named test_foreign_ack_is_refused only exercises broken=True, not a foreign
wire acknowledgment. Before installed pair acceptance, add actual _receive controls
for wrong session/profile/hash/state/sequence/authority and process stalls, plus
shutdown timeout and lock-release failure paths. Existing producer controls do not
substitute for the new consumer's control-flow acceptance.

No Run wire or wheel change is required by these findings. Root owns Engineer
corrections. After final adapter bytes are frozen, Root supplies exact fresh
PREVIEW.json path/hash; Run can prepare a new explicitly selected disposable
accounting context/profile/request/approval for those bytes. Do not reuse five-second
synthetic-example profiles: select a session deadline covering validation, the
60-second service reservation and settlement, with the caller hard bound explicit.
Old C7 pools/operations remain untouched; preparation must not admit/consume/launch.
Public release, current production authority, complete costs and full V1 remain OPEN.
