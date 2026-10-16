# Development service accounting pipe / 1

Candidate implementation, NOT consumer accepted. Engineer execution remains gated.
Public command: `vfy service-accounting-session --profile PATH --profile-sha256 HEX`.
No daemon, execution, pool creation/attachment/reset/grant, or key export. One existing
Run-owned service epoch and one new attempt per process. Run takes the existing pool
lock nonblocking for the entire bounded session; other writers cannot interleave.
The selected head must match exactly. A changed head cannot be reopened with the old
profile; selecting a newer head cannot reconstruct any previous live capability.

Profile installation is a Run-owner responsibility. Schema
`vfy.service-accounting-profile/1`, exact fields:
- `schema`, `scope` = `DISPOSABLE_DEVELOPMENT_ONLY`
- `inputs`: canonical base64+sha256 objects, same encoding as SERVICE_READ_CLI_CONTRACT:
  `snapshot`, `config`, `predecessor`, `policy`, `managed_legacy` (empty bytes for common predecessor).
- `selection`: exact public arguments of load_service_pool except raw byte arguments:
  expected_snapshot_sha256, expected_pool_root, owner_trust, child_trust,
  selected_observer, expected_child_trusts, minimum_revision,
  selected_callback_identity, selected_managed_identity (null for common predecessor).
- `key_file`: canonical Run-controlled 32-byte raw development owner seed file,
  regular/single link/current uid/mode0600. Never supplied in Engineer messages.
  Its public key must match independently selected owner trust. This is a local
  development key provider, NOT OS isolation from another process with the same uid.
- `session_seconds`: integer1..900, `service_identity`: exact service_attempt.identity().
Profile <=16MiB, each payload <=4MiB, total decoded <=8MiB. Caller selects exact
profile hash. No network key lookup or implicit current organizational authority.

JSON newline framing. Max wire frame16MiB including newline; <=4MiB per decoded
input and <=8MiB combined. One OPEN response emitted first, then up to three request
frames (ADMIT, CONSUME, SETTLE) or UNKNOWN instead of either latter frame. No CLOSE
needed; terminal response exits. EOF/timeout/invalid frame ends session without retry.
Response max8MiB; selected pipe deadline <=900s, including blocked pipe reads/writes. It is checked
at transport boundaries, not a preemptive CPU/filesystem deadline. Caller MUST
enforce a hard process timeout and terminate on uncertainty; process startup,
profile validation and filesystem stalls are outside the pipe deadline.

Each request has exactly schema=`vfy.service-accounting-frame/1`, session_id (from
OPEN), sequence (1,2,3), operation, inputs. Request binding is SHA256 of exact frame
bytes including newline. `inputs` maps the following names to base64+sha256:
- ADMIT: request, preview, approval. Response includes signed original admission
  snapshot; the live admission capability stays only inside this Run process.
- CONSUME: start. Only after Engineer holds its shared caller lock, durably records
  exact START, and immediately before launch. Run checks the actual START and PREVIEW
  and consumes its live capability exactly once before response. Engineer must
  verify the session/sequence/frame hash/status and retain the signed consumption
  before launching once under that same caller lock. No retransmission/reconnect.
- SETTLE: result, stdout, stderr. Exact retained RESULT/streams verified by existing
  pool. Signed response is accounting evidence, never semantic/action authority.
- UNKNOWN: inputs={} at sequence2 or3. Conservative terminal hold, no refund.

Response exact fields: schema=`vfy.service-accounting-response/1`, profile_sha256,
session_id, sequence, request_sha256 (null for OPEN), state, record (signed service
snapshot, null on refusal), error (null or bounded class), authority_granted=false,
automatic_retry=false, full_cost=UNKNOWN. OPEN sequence0 state=OPEN; subsequent
states ADMITTED, CONSUMED, SETTLED, UNKNOWN_HOLD_RETAINED. SETTLED does not promote the
entry classification (which can remain UNKNOWN). Exit0 only for SETTLED/explicit
UNKNOWN. Exit12 when refusal/EOF/timeout can be reported; exit1 when the pipe/deadline
prevents reporting; argparse2 on misuse.

Any missing/uncertain consumption ack means NO LAUNCH, UNKNOWN/no retry. Graceful
failure attempts mark_unknown under held lock; SIGKILL can leave ADMITTED/CONSUMED
but full reservations remain charged and capabilities are lost. No restart recovery
of live tokens, no implicit retry or refund. Signed snapshots retain old exact pool,
request, approval, PREVIEW, START and result bindings. Unchanged service accounting
charges cumulative slots/output plus declared wall/cpu/output/file/descriptors.
Profile/key/transport/validation/import/journal CPU/I/O/storage and lifecycle costs
are not metered by those declared service resources; full cost stays UNKNOWN.

Existing callers remain responsible for durable START ordering/shared caller lock,
service bounds and output retention. Run does not launch or verify physical fsync,
and a pipe ack is not native execution custody or Platform authority. Full V1 and
ordinary Platform connection remain OPEN. Public release remains held.

Consumer acceptance requirements: pin this installed development wheel/executable
independently; never derive trust/profile selection from a response. Validate exact
response fields, profile/session/sequence and exact request-frame hash, error=null,
false authority/retry and expected state before treating an ack as completed.
Authenticate/bind saved snapshots through Run where needed; a signature is not a
new live capability. Owner key correspondence is selected development trust, not
current revocation, human approval or production identity. Current effect approval
and adapter/runtime validation remain separate caller obligations before START.
Historical read-only public commands and all prior plan/module identities remain
unchanged; this session is explicitly stateful and must never be used for reading
an exhausted retained pool or hidden as a side effect of a view.
