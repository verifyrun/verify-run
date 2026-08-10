# Local store — making the computation survive a process boundary
    store_format_version: 1

Persists the exact artifacts a later process needs to verify and replay a decision. It is
transport and durability, nothing else.

**The store is not a trust anchor.** A file being local proves nothing. Every load re-verifies
signatures and re-runs replay against caller-supplied keys, exactly as if the bytes had arrived
over a wire from a stranger.

The store never evaluates a decision, issues an authorization, issues a receipt, executes an
action, reads a clock, draws randomness, inspects the environment, infers a home directory, or
touches a network. It is the first unit permitted to use the filesystem, and only under the root
the caller supplies.

## Layout
`spec/execution-chain.md` §9 already declares the shape, and this is that shape:

    <root>/store.json                      format version
    <root>/index.json                      rebuildable, subordinate
    <root>/receipts/<receipt_id>.json      the receipt, exactly as signed
    <root>/receipts/<receipt_id>.inputs/   the bodies replay needs
        rulebook.json
        candidate.json
        snapshot.json
        authorization.json                 ALLOW records only
    <root>/consumed/<sha256-of-nonce>.json
    <root>/tmp/                            staging, store-owned

`authorization.json` **extends** §9's enumerated three. §9 names the bodies replay strictly
requires; Unit 9 additionally cross-binds a referenced authorization when one is supplied, and
without persisting it an ALLOW record could never have that check performed again after a restart.
The extension is stated here rather than assumed, and it adds a file to the set without changing
any existing one.

`store.json` carries the format version so a future layout change cannot silently reinterpret old
records.

## Stored bytes
Every file contains **exactly** the canonical UTF-8 bytes of its artifact: no BOM, no insignificant
whitespace, no trailing newline. The receipt file equals `FrozenReceipt.canonical_bytes` byte for
byte, and each body equals its own frozen canonical representation.

Trusted artifacts are never pretty-printed. A human-readable export is a different job for a
different layer, and mixing the two would make "the stored bytes" ambiguous.

The rulebook body is stored as **canonical JSON**, not the original YAML. Canonical JSON is valid
input to the strict YAML loader, so replay reproduces the identical pinned digest from it, and
canonical bytes carry no presentation to disagree about. Original source is not retained; nothing
in the current contract requires it, and the digest — not the formatting — is what governs.

## Receipt identity
The local identity is `receipt_id`, and there is no receipt digest to use instead: the schema
declares none and this unit invents none.

`receipt_id` has no schema pattern, so it **cannot be trusted as a filename**. A storable
receipt id matches `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` and is never `.` or `..`. Anything else is
refused with `store_path_invalid`. That is a constraint on what this store can persist, not on
what a receipt may contain: a receipt with an unstorable id is still a perfectly valid receipt.
Deriving names only from that grammar means path traversal is impossible by construction rather
than by filtering.

Identity is case-sensitive, because the values are compared as canonical strings everywhere else.
Two ids differing only in case are two records, and on a case-insensitive filesystem the second
write is refused as a conflict rather than silently merged.

## Commit
Two objects must become visible together: the receipt file and its inputs directory. One rename is
atomic; two are not. So the **commit point is the receipt file's rename**, and it happens last.

1. create `<root>/tmp/<receipt_id>.staging/` with exclusive creation — an existing one means
   another writer holds this id, or a previous run abandoned it, and either way this is
   `store_commit_conflict`, not something to overwrite;
2. write every body and the receipt inside it;
3. verify the bytes and bindings that were just written;
4. rename the staging inputs into place;
5. **rename the receipt file into place — the record is now committed**;
6. update the index, which is subordinate and may be rebuilt at any time.

A reader treats a record as committed if and only if the receipt file exists. Crash before step 5
leaves an orphaned inputs directory and no receipt: **not committed**, and correctly invisible.

### What durability actually means here
Three different guarantees, kept apart because conflating them is how storage claims become false:

- **Process-crash atomicity** — provided. A crash at any point leaves either no committed record
  or a complete one.
- **Filesystem rename atomicity** — provided on POSIX and NTFS for same-directory renames, which
  is why staging lives under the same root.
- **Full power-loss durability** — **not claimed.** This implementation does not fsync directories,
  so a power cut may lose a rename the operating system reported as complete. Claiming otherwise
  would be a lie that only surfaces during an outage.

Abandoned staging directories are **reported, never silently deleted**. A leftover staging tree may
be the only evidence of an interrupted or hostile write, and destroying it to make a retry
convenient destroys that evidence.

## Index
The index is an optimization and never an authority. It is derived entirely from committed
receipts, may be deleted at any time, and is rebuilt by scanning `receipts/`.

Each summary carries only what the signed receipt already states: `receipt_id`, `created_at`,
`outcome`, `rulebook_id`, `rulebook_version`, `authorization_id`, and the signing `key_id`.
Ordering is by `(created_at, receipt_id)`, both from the receipt, so ties are deterministic and
insertion order is irrelevant.

If the index disagrees with the records, **the records govern**. A malformed index is never
believed: it is reported by name with `store_index_invalid`, in the `refused` list a listing
returns, and rebuilding is always available. Reporting it is not the same as raising it — see
**Listing** below, where the one rule that governs every artifact this store reads is stated.

## Listing
A listing answers two questions at once, and it answers both from the committed records:

- **which records it could read** — `summaries`, ordered by `(created_at, receipt_id)`;
- **which artifacts it could not** — `refused`, each naming the artifact's **filename**, the
  reason code that refused it, and the message.

One rule governs it: **no single damaged artifact makes a listing unavailable, and no damaged
artifact passes as healthy.** A file that is not canonical, not readable, not a receipt, or not a
regular file is refused by name; every other record is still listed; nothing is deleted, repaired,
or written. A caller that sees a non-empty `refused` knows precisely which file to look at.

The index is not consulted, and that is a correction rather than an oversight. Reconciliation
compares *identities*, which a record damaged after it was indexed still has — so a listing that
answered from the cache reported a receipt it had no way of knowing was unreadable, while a single
unreadable file anywhere ended the whole listing and made every healthy record unreachable through
that command. Only a scan can answer both questions truthfully, so a listing scans. This costs one
read per committed record, which is what a local store bounded by one workspace's runs can afford;
`get_record`, which is where anything is actually verified, is unchanged and still refuses a
damaged record by name.

The index itself is subject to the same rule. A malformed, unreadable, symlinked, non-regular, or
oversized `index.json` appears in `refused` — it is never believed, and it never silences the
records either. A **dangling** symlink is refused like any other: it is a directory entry that is
a link, not an absence, and reporting it as *no cache* would make a hostile object invisible
precisely by having it point at nothing. Writing is where a symlinked cache is dangerous, and
writing still refuses: `rebuild_index` raises `store_path_invalid` rather than renaming over the
link.

One further consequence of reading records rather than the cache: **the index refresh a commit
performs walks the same files a listing does.** A hostile object planted under `receipts/` must
therefore not be able to block *recording* either. It cannot: the refresh reads through the same
primitive, refuses the entry, and — as [Subordinate, operationally](#subordinate-operationally)
requires — never propagates a cache problem onto a record the rename already committed.

### Subordinate, operationally
    store_format_version: 1 — clarified after Unit 12's concurrency proof; no guarantee changed.

"Never an authority" has to hold at runtime, not only in principle. Three consequences, each of
which the implementation failed until this was written down:

- **A listing derives from the records.** It never omits a readable committed record and never
  names one that does not exist, because it reads the records themselves — an index entry may not
  substitute for a receipt. Until the 0.1.x hardening pass a listing reconciled identities against
  the cache and answered from it when they agreed; see **Listing** above for why comparing
  identities was not enough.
- **Index maintenance may not revoke a commit.** The receipt rename is the commit point and index
  maintenance follows it, so a failure there is a cache failure, not the record's. `put_record`
  returns the committed record. This is not error suppression: nothing about the committed
  artifact is concealed, and the next listing corrects the cache from the records.
  The refresh reads **every** committed receipt, so it can fail for a reason belonging to some
  other record entirely — a historical file that is unreadable or not canonical. That failure is
  a cache failure too, and since 0.1.0a2 it is tolerated like any other rather than travelling
  outward onto the record just written. It previously did travel: an unrelated corrupt artifact
  made a run that had executed, consumed its nonce, and committed a complete record report
  `execution_recording_failed`, sending an operator to look for a receipt already on disk. The
  corrupt artifact is still never deleted, still refused by name on any attempt to load it, and
  now named by every listing rather than ending one.
- **Concurrent writers do not publish over each other.** Every index write stages at
  `index.<n>.staging`, a slot found by the same exclusive creation used elsewhere here, so two
  callers committing different records never rename each other's file. One shared staging name
  meant the loser of that race renamed a file already moved away and a raw error escaped from a
  cache write onto an already committed record.

Two writers can still each rebuild from their own scan instant, so a published index may lag the
records it describes. That is exactly what a subordinate cache is permitted to do, and it is
invisible to callers because a listing reads the records rather than the cache.

## Loading
`get_record` trusts nothing:

- refuses a missing record distinctly from an incomplete one;
- refuses any symlink in the layout;
- requires every body the record's terminal class needs;
- strict-loads each file through the closed loader;
- requires the stored bytes to equal the canonical bytes of what they parse to — a body that is
  valid JSON but not canonical is `store_artifact_noncanonical`;
- runs Unit 9's replay with caller-supplied key registries.

A BLOCK or HOLD record requires no authorization and must not carry one. An ALLOW record follows
Unit 9's shape exactly.

## Writing the same id twice
Writing a record whose id already exists, with **byte-identical** receipt and bodies, is
idempotent and succeeds. Any differing byte is `store_record_conflict`. There is no overwrite
operation in this version, and a partially present record is never treated as idempotent — one
receipt id can never come to mean two contents.

## Single-use consumption
`spec/authorization.schema.json` settles the key: the nonce is "Single use. Store consumed nonces;
reuse must be rejected." **The consumption key is the nonce**, not the authorization id and not a
tuple.

The file is named by the SHA-256 of the nonce, because a nonce is a caller-supplied string with no
pattern and must never reach the filesystem as a path. The record inside binds `authorization_id`,
`nonce`, `action_digest`, `rulebook_digest`, and `evidence_digest`, so a second authorization
reusing a nonce under different bindings is detectable as `store_consumption_conflict` rather than
merely "already consumed".

No `consumed_at` is recorded. No clock is read, and inventing a timestamp would be fabricating
evidence.

Consumption uses exclusive creation, which is atomic on POSIX and on Windows. First call succeeds.
**Every later call fails**, including an exact repeat of an identical consumption: it raises
`authorization_nonce_reused` and never grants a second execution right. Retry convenience is not
worth a duplicate action.

### The record and its content are published together
    store_format_version: 1 — clarified after Unit 12's concurrency proof; no guarantee changed.

Exclusive creation is necessary and was not sufficient. Creating the entry and then writing into
it are two steps, and a second caller arriving between them finds a name whose content does not
exist yet — so instead of the `authorization_nonce_reused` above, it reported a source error about
an empty file, and could not compare the bindings it is required to compare.

So the record is written in full to a staging path under `tmp/` and then **linked** into
`consumed/`. The link is the consumption point: it either creates a complete entry or fails
because one is already there. A caller therefore observes the record as absent or as complete,
never as partial, and the two guarantees above — one winner, and a loser that can tell reuse from
`store_consumption_conflict` — hold under contention rather than only in sequence.

The staging slot is found by that same exclusive creation, probing `consume-<nonce-sha256>.<n>`,
so concurrent callers never share one and nothing names it from a clock, a process id, or
randomness. An abandoned slot is reported by the scan and never silently reused, like every other
staging path here; exhausting the slots is `store_commit_conflict`, which says to scan the store.

This assumes `consumed/` and `tmp/` share a filesystem that supports hard links, which the
declared concurrency class — one local filesystem — already assumes. Where linking is unavailable
the commit fails loudly as `store_commit_conflict` rather than falling back to a weaker write.

### The execution race, stated honestly
> Atomic nonce consumption before execution prevents a second local consumer from receiving the
> same authorization right. It does **not** make an external action exactly-once. A crash after
> consumption but before the action leaves the right spent with no proof of execution.

That is the safe trade. Moving consumption after execution would make retries convenient and
permit duplicate action, so it is not done.

## Concurrency
Declared class: **multiple processes and threads on one machine, sharing one root on a local
filesystem.**

Provided by exclusive creation (`O_CREAT|O_EXCL`) for consumption records and staging directories,
and by same-directory rename for commit. No lock files, no daemon, no database.

Not provided, and explicitly out of scope: correctness over NFS or another network filesystem
where `O_EXCL` and rename atomicity are weaker; coordination across machines; and any ordering
guarantee between two processes writing different records at once — they simply do not interfere.

## Symlinks and traversal
Rejected everywhere in the trusted layout, checked with `lstat` rather than `stat` so a symlink is
seen rather than followed. Applies to the root, `receipts/`, each record file, the inputs
directory and every body in it, the index, and every consumption record.

Filenames are derived only from the storable-id grammar and from SHA-256 hex, so `../`, absolute
paths, and separators cannot appear in a derived name at all. Nothing is deleted recursively, and
no path outside the caller's root is ever touched.

## Reading an untrusted entry
Every file the store reads is untrusted local input, and each one is read the same way: **one
object is classified, opened, and read.**

The open *is* the classification. `O_NOFOLLOW` settles the symlink question while the descriptor
is being acquired, and kind, size, and contents are then asked of that descriptor and never of
the path again. `O_NONBLOCK` keeps a FIFO from parking the process in the open itself.

This ordering is the requirement, not a detail. `is_file()` followed by `read_bytes()`, or
`stat()` followed by `open()`, are two separate looks at one name, and a name can be made to
refer to two different objects between them.

Two consequences follow, and both are load-bearing:

- **A directory entry that is a symlink is an entry, not an absence.** `exists()` answers for
  what a link points at, so a dangling symlink reports as nothing being there. Absence therefore
  means *no directory entry*, and every question about presence — a committed record, the index,
  a consumption record, a preserved unrecorded receipt — is asked that way.
- **Size is refused from the descriptor, before allocation.** A store entry above the byte bound
  is refused without a read proportional to it, and a file that grows past the bound while being
  read is refused too.

`MAX_RECEIPT_BYTES` is 1 MiB. It is a **product bound, not a derived one**: a receipt is a small
bounded document — identifiers, three digests, a result with its reason trace, one signature —
and 1 MiB is orders of magnitude above any of them. Nothing computes it from the schema, and it
should be read as the largest thing this store will call a receipt rather than as a proof about
the largest receipt that exists.

Non-regular entries are refused as a class: FIFOs, directories, sockets, and devices. What the
guarantee narrows to on a host lacking `O_NOFOLLOW` or `O_NONBLOCK` is stated below.

### The race this closes, and the one it does not
Closed: the window between deciding what a name refers to and reading it. There is no such
window; there is one descriptor.

Not closed: a **parent directory** component may still be replaced while a path is being
resolved. The store does not claim otherwise, and a caller who does not control the enclosing
directory does not get a stronger guarantee from anything here.

On a host without `O_NOFOLLOW`, the symlink refusal falls back to what a single `lstat` can say,
which is a check-then-open pair again. On a host without `O_NONBLOCK`, a FIFO can block the open.
Both flags are POSIX and present on every platform this alpha is tested on; the fallback is
recorded because a narrower guarantee should be written down rather than assumed away.

## Opening the store
A store is opened **either to write to or only to look at**, and these are different
constructions rather than one construction in two moods.

- **Opened for writing** — creates the declared layout if it is not there, writes the format
  marker, refreshes the index on commit.
- **Opened for reading** — creates nothing, repairs nothing, migrates nothing, normalizes
  nothing. A missing or replaced layout member is *reported*, never supplied.

A command that only reads must be unable to leave a trace, and that has to be a property of which
constructor ran rather than of auditing every path a listing might take.

Opened for reading, the store requires a real directory at the root and at `receipts/`, and
refuses a format marker that is not a regular file. An **absent** `store.json` is tolerated —
the committed records are the authority and a marker going missing is not a reason to make a
listing unavailable — but an object standing in its place is refused.

A directory that cannot be listed is refused by name. It is not reported as an empty store: `I
cannot see` and `there is nothing here` are different sentences, and this product does not merge
them here either.

## Recovery
- **abandoned staging** — reported by an explicit scan, never auto-deleted;
- **committed record missing from the index** — invisible to a listing, which reads the records;
- **index entry with no committed record** — the index is wrong; `rebuild_index` corrects it;
- **corrupt index** — named in a listing's `refused`, then rebuilt from records;
- **corrupt committed record** — named in a listing's `refused` by filename, never deleted, and
  still refused by `get_record`; every other record is still listed;
- **interrupted consumption** — the record either exists atomically or does not; there is no
  partial state to recover;
- **orphaned inputs with no receipt** — not committed, and reported by the same scan.

Nothing that could be evidence of a collision or a tamper attempt is silently removed.
