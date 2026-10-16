# Service accounting lifecycle CLI — proposal only, execution remains gated

Status: NOT_IMPLEMENTED / NOT_ACCEPTED. No new daemon or writer is created by this
work. Engineer's direct ServicePool import cannot be replaced by stateless commands
that reconstruct live tokens or exchange private signing seeds. Root owns migration
and must keep actual execute_accounted gated until this interface is accepted.

Proposed Run-owned endpoint: `vfy service-accounting-session --profile PATH
--profile-sha256 HEX`. A single existing Run owner starts a bounded pipe session.
The Run profile selects the existing shared owner/root/head, public trust, service
policy and Run-controlled key-provider reference. Private key bytes stay inside
Run; neither argv, stdin/stdout, request records nor Engineer receive them. Profile
installation/current authority is separately selected, never inferred from tests.

Proposed framed messages (exact schemas require bilateral agreement):
- OPEN: bind existing root/head/policy and a fresh session identity; refuse a changed
  head or competing writer. No pool creation, reset, grants or historical replay.
- ADMIT: exact service request/PREVIEW/approval bytes and hashes. Run reserves on the
  original common allocator and retains the live capability in process memory.
  Return a signed admission receipt and opaque session-local reference, not a key
  or exportable/reconstructible spending capability.
- CONSUME: only after Engineer holds its shared caller lock and has fsynced its exact
  START. Run checks durable START/request/PREVIEW correspondence, consumes once and
  commits before acknowledging. Engineer may launch once only after that exact ack
  in the same locked attempt. Failed consume prevents launch. Ack loss, process loss
  or uncertain delivery leaves UNKNOWN/no replay; no reconnect-and-resend shortcut.
- SETTLE/UNKNOWN: link exact retained RESULT/stdout/stderr and declared resource
  bounds; all failed/interrupted holds remain conservative. No duplicate settlement,
  implied action/semantic authority or refund. Separate read-only inspection can
  authenticate saved results but cannot recover live capabilities.
- CLOSE/EOF/crash: terminate capabilities. Durable admissions/consumption remain
  held; reopening permits historical observation only, never restoration of tokens.

Each frame needs hard decoded/wire/output bounds, sequence/request identities,
strict JSON parsing, exact peer/session binding, and bounded process lifetime. The
specific caps and key-provider/owner attachment must be selected by the existing
runtime owner, not smuggled into Engineer's manifest or new standalone account.

Acceptance must cover actual START fsync ordering, two callers/one lock, wrong START,
version/approval/source, shared exhaustion, child/session death before consume,
after durable consume/before ack and after ack/before launch, refused restart/replay,
retained output linkage and fresh-process read-only accounting. Scope remains service
accounting only; scheduling/native custody, full costs, current organization/Platform
authority and full V1 are distinct OPEN responsibilities. Public release stays held.
