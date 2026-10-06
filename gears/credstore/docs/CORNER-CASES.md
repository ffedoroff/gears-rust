# CredStore: corner cases

What can go wrong in CredStore's secret writes, reads and deletes: the faults the service tolerates and those it accepts as risks, their effects, and the scenarios that combine them.
A secret write goes: announce (a write intent in the DB) → store the value in Vault → commit (switch the record's pointer) → clean up (execute cleanup debts).

## Tolerated faults (support now: 9)

Handled by the request itself, with no background work: leftovers are healed by a later request, a definitely rolled-back transaction is retried up to 3 times, an ambiguous commit of a write or a delete is verified once. Faults are handled alone and in the combinations of "Failure scenarios: tolerated". Guarantees:

- the pointer always references an existing version with the exact bytes written; a confirmed write is not lost while the store keeps its versions (`201-STORAGE-EVICT`);
- the client gets success or a safely retryable error (404, 409, 503), or a dropped connection on a crash (`149-APP-CRASH`);
- leftovers are tracked in the DB and removed by a later request to the same record or reference; a `purge` debt of a deleted key waits for an external job (R4b);
- every failure shows in logs or metrics; a crash only later, through the heal counters.

Faults:

- `149-APP-CRASH` — the process stopped or was killed between two steps of a request.
- `178-DB-DOWN` — PostgreSQL is unavailable or the connection was lost during a step; the outcome of the step is definite: nothing was written.
- `168-DB-COMMIT-LOST` — the connection was lost around COMMIT: the DB client does not know whether the transaction committed.
- `151-DB-CONTENTION` — serialization conflict, deadlock or SQLite busy: the transaction definitely rolled back and is retried up to 3 times (pauses of ~10 and 20 ms).
- `130-STORAGE-DOWN` — Vault is unavailable or returns an error.
- `161-STORAGE-TIMEOUT` — the request to Vault got no answer within 5 s: the client gave up, and Vault may or may not have applied the request. An apply within Vault's maximum request duration (90 s by default) is still covered by the writer's intent.
- `169-RACE-WRITE` — a concurrent write to the same record (or the same reference) by another request or instance.
- `142-RACE-DELETE` — a concurrent delete of the record by another request.
- `182-AUDIT-DOWN` — the audit broker is unavailable or rejected the event: the event is simply not written, the request is unaffected (log and metric).

## Out-of-model faults (accepted risks: 12)

Known, not handled in this version; scenarios in "Failure scenarios: out-of-model". They are:

- rare: a long VM freeze, a late apply by the store, version eviction;
- outside the service: manual changes in Vault or the DB, backup restore, misconfiguration, mixed rollout, backend quirks;
- functional gaps: leftovers cannot be counted (no `COUNT`).

Their effects are worse: untracked leftovers, an unreadable record, silent wrong behavior. Covered by the runbook and monitoring; a code that starts to matter goes to a future version or a ticket.

Faults:

- `218-VM-DELAY` — the process or VM froze (VM freeze, a long process pause, CPU starvation) for a time comparable to the lease (300 s) or longer.
- `267-DB-STORAGE-NOT-SYNCED` — the DB and Vault diverged: a row points to a version that is not in Vault, or Vault holds versions and keys that the DB does not track. Causes: the DB or Vault was restored from a backup separately from the other (or to a different point in time), data in Vault or in the DB was changed bypassing the service, a version was evicted or a request was applied late.
- `239-STORAGE-LATE-APPLY` — Vault applied a write after the writer's lease expired, when its intent may already have been healed.
- `201-STORAGE-EVICT` — Vault evicted the oldest versions of a key by its `max_versions` limit (10 by default; destroyed versions still count): ten or more versions were written under the key while the record's pointer stayed put — failed writes in a row, or a burst of concurrent writers whose losing versions land after the winner's.
- `276-STORAGE-EXTERNAL-CHANGE` — data in Vault was deleted, replaced or lost bypassing the service: a Vault administrator deleted or destroyed a version, `delete_version_after` on the mount expired it, someone with direct access to Vault storage replaced the bytes of a version or wrote a version, or a non-durable store (the in-memory plugin) lost its data on a process restart.
- `230-DB-EXTERNAL-CHANGE` — rows of the gear's tables in PostgreSQL (records, write intents, cleanup debts) were changed or deleted bypassing the service: manual SQL, a hand-written migration.
- `284-RACE-TYPE` — two creates of non-private records of one reference with different types, one in an ancestor tenant and one in its descendant, overlap in time: each passes its type check before the other's row exists (an ancestor deleting and re-creating its record while a descendant's create is in flight included).
- `220-CLIENT-NO-RETRY` — the client did not retry the request and no longer touches the record or reference.
- `291-OPS-BLIND` — the operator cannot see the state: open intents and cleanup debt rows are not measured (COUNT is forbidden).
- `248-OPS-CONFIG` — a configuration error by the operator (Vault mount, lease, plugin timeout, limits).
- `250-OPS-ROLLOUT` — instances of the old and new service versions run at the same time.
- `258-TENANT-CHANGE` — a tenant changed in Account Management, and the service is not told (Account Management sends no events, and the service checks nothing when it happens): the tenant was moved under another parent (re-parenting, not offered by Account Management yet); it was deleted; it or one of its ancestors was suspended or soft-deleted (the service ignores tenant status, so an ancestor's `shared` values keep resolving for its descendants); an isolation barrier was set or removed (inheritance ignores barriers by design, so values keep resolving; only the PDP's authority changes, and it is evaluated on every request).

## Failure effects (9)

What remains after a failure and what the client sees; a scenario lists every effect that applies. Ordered by importance: correctness and security first (wrong behavior, type mismatch, lost audit), then leftovers and client errors, then internal overhead (logs, extra DB and Vault calls). Leftovers (`*-LEFTOVER`) never corrupt primary data; they are removed by a later request (see the tolerated guarantees; a dead key's `purge` debt waits for an external job), and in out-of-model scenarios they may stay forever (stated per scenario).

- `382-WRONG-BEHAVIOR` — the service behaves differently from what the client or operator expects: the record's metadata in the DB is lost or stale (404 or the old state); the secret value in Vault cannot be read (500 until overwritten or deleted); tampering that goes unnoticed.
- `347-TYPE-MISMATCH` — non-private records of one reference in an ancestor tenant and in its descendant carry different secret types: a consumer that reads by reference gets a secret of another shape than it expects, depending on the tenant it reads in. Nothing fails; the mismatch stays until one of the records is deleted and re-created.
- `367-AUDIT-LOST` — an audit event is lost or recorded with a wrong operation label.
- `350-STORAGE-LEFTOVER` — an extra version or key remains in Vault: a leftover, the primary data is not corrupted.
- `336-EXTERNAL-ERROR` — the client sees an error code and has to make another request.
- `372-DB-LEFTOVER` — an extra service row remains in the DB (an intent or a cleanup debt): a leftover, the primary data is not corrupted.
- `395-INTERNAL-ERROR` — the client does not learn about the error, but we write it to the logs.
- `374-INTERNAL-STORAGE-EXTRA-CALL` — an extra Vault call beyond the usual path (a repeated `get`, executing a cleanup debt on the next access).
- `356-INTERNAL-DB-EXTRA-CALL` — an extra query or transaction in the DB beyond the usual path (a repeated row read, a verification transaction, a transaction retry, healing on access).

## Failure scenarios: tolerated (13)

### CC-679

PostgreSQL is down at any step of a read, a write or a delete. The client gets 503 and can retry. If nothing was written yet, nothing is left. After the value is stored in Vault, the new version and its write intent stay (the old value keeps serving); after the lease the next write to the record removes both (for a create: the next create or read of the same reference).

- **Faults:** `178-DB-DOWN`
- **Effects:** `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`, `372-DB-LEFTOVER`, `356-INTERNAL-DB-EXTRA-CALL`

### CC-773

A DB transaction is rolled back by contention (serialization failure, deadlock, SQLite busy) and retried up to 3 times. Usually one attempt succeeds: the client notices nothing but an extra query. If all 3 fail, the client gets 503 and can retry (a failed removal of a cleanup-debt row is only logged, and the debt runs again on the next access to the record). What the request had already done stays as in CC-679.

- **Faults:** `151-DB-CONTENTION`
- **Effects:** `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`, `372-DB-LEFTOVER`, `395-INTERNAL-ERROR`, `374-INTERNAL-STORAGE-EXTRA-CALL`, `356-INTERNAL-DB-EXTRA-CALL`

### CC-673

The connection is lost around a write's commit, so it is unknown whether it committed. For the commit that switches the pointer the service checks once and then answers success, or, if a concurrent write won, removes its own version and answers 503. A lost announce or secret-removal commit is not checked: the client gets 503, and anything it did commit is finished by a later request to the record.

- **Faults:** `168-DB-COMMIT-LOST` + `169-RACE-WRITE`
- **Effects:** `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`, `372-DB-LEFTOVER`, `374-INTERNAL-STORAGE-EXTRA-CALL`, `356-INTERNAL-DB-EXTRA-CALL`

### CC-750

The connection is lost during the commit of a record delete. The service checks once: if the delete committed, it removes the key and the client gets 204; if not, it repeats the delete (409 if the record changed meanwhile) and removes the key. Nothing is left; an extra DB query remains.

- **Faults:** `168-DB-COMMIT-LOST`
- **Effects:** `356-INTERNAL-DB-EXTRA-CALL`

### CC-710

A write's commit was lost and the check fails too, because PostgreSQL is still down. The client gets 503 and nothing more is done; whatever the commit did or did not leave stays tracked (as in CC-679) and is finished by a later request. Retrying is safe: a replace with the same `If-Match` gets 409 if the first attempt did commit.

- **Faults:** `168-DB-COMMIT-LOST` + `178-DB-DOWN`
- **Effects:** `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`, `372-DB-LEFTOVER`, `374-INTERNAL-STORAGE-EXTRA-CALL`, `356-INTERNAL-DB-EXTRA-CALL`

### CC-762

The cleanup debt that deletes the key of a record with no row (a deleted record, a lost create, a healed failed create) cannot run: Vault is down, the process crashes, or a delete with a lost commit cannot be checked because PostgreSQL is down (503, a repeated delete gives 404). The client's answer is otherwise unchanged. No request ever comes back to that record, so the debt and the key stay forever, tracked in the DB, until an external cleanup (R4b).

- **Faults:** `130-STORAGE-DOWN`, `149-APP-CRASH`, `168-DB-COMMIT-LOST` + `178-DB-DOWN`
- **Effects:** `350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER` + `395-INTERNAL-ERROR` + `336-EXTERNAL-ERROR`

### CC-730

Vault is down or returns an error at any step. Storing a value: the client gets 503 and the pointer is untouched; the write intent stays, and an unserved version too if Vault applied the value anyway; the next write to the record removes them (for a create: the next create or read of the reference). Reading a secret: 503, nothing is left. Cleanup: the client's answer is unchanged, the error is logged, and the debts stay until the next read or write of the record executes them; if it is never touched, they stay forever (a deleted record's key: CC-762).

- **Faults:** `130-STORAGE-DOWN`
- **Effects:** `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`, `372-DB-LEFTOVER`, `395-INTERNAL-ERROR`, `374-INTERNAL-STORAGE-EXTRA-CALL`, `356-INTERNAL-DB-EXTRA-CALL`

### CC-661

Vault applies the write but the answer is lost (5 s timeout, network drop). The client gets 503 and the old value keeps serving. The new version and the write intent stay; after the lease the next write to the record removes both (for a create: the next create or read of the reference; deleting the record also removes the key).

- **Faults:** `161-STORAGE-TIMEOUT`
- **Effects:** `350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

### CC-570

The process crashes at any step; the client gets a dropped connection. Whatever the request already did (a write intent, an unserved new version, cleanup debts with the old versions) stays tracked in the DB: the next write to the record removes intents and versions after the lease (for a create: the next create or read of the reference), and the next read or write runs the debts.

- **Faults:** `149-APP-CRASH`
- **Effects:** `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`, `372-DB-LEFTOVER`, `395-INTERNAL-ERROR`, `374-INTERNAL-STORAGE-EXTRA-CALL`, `356-INTERNAL-DB-EXTRA-CALL`

### CC-566

Concurrent writes to one record or reference (or a secret removal in between): one wins, and each loser's commit finds the record changed. The loser gets 409 and can retry (a replace with `If-Match: *` is first retried once by the service); a secret removal that loses its check gets 409 before storing anything. The loser's version (for a create: its key) is removed by a cleanup debt, the winner is untouched, nothing is left.

- **Faults:** `169-RACE-WRITE`
- **Effects:** `336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

### CC-522

A write stores its value while another request deletes the record. The write's commit finds no record and the client gets 409. The service removes the key that the late value re-created; nothing is left.

- **Faults:** `142-RACE-DELETE`
- **Effects:** `336-EXTERNAL-ERROR`

### CC-775

A read finds its version removed by a rotation, re-reads the pointer once and tries again, and a second rotation makes the second try miss too. The client gets 503 (never an empty or stale value; 500 only when the pointer has not moved, CC-897) and can retry. Nothing is left; an extra DB read and Vault call remain.

- **Faults:** `169-RACE-WRITE`
- **Effects:** `336-EXTERNAL-ERROR` + `374-INTERNAL-STORAGE-EXTRA-CALL` + `356-INTERNAL-DB-EXTRA-CALL`

### CC-794

The audit broker is unavailable or rejects an event of a secret read or write (publishing is best effort, 500 ms). The request is unaffected and the client gets the usual answer. The event is lost; an error is logged and counted by `audit_publish_failed`.

- **Faults:** `182-AUDIT-DOWN`
- **Effects:** `367-AUDIT-LOST` + `395-INTERNAL-ERROR`

## Failure scenarios: out-of-model (16)

### CC-970

Vault applies a write late (the client gave up, or the plugin timeout is set close to the lease) after another write healed the expired intent and moved the pointer. The client got 503. The late version lands above the new pointer with no intent and no debt; it is never served, and the next successful write to the record or deleting the record removes it.

- **Faults:** `239-STORAGE-LATE-APPLY` + `169-RACE-WRITE`
- **Effects:** `350-STORAGE-LEFTOVER`

### CC-864

Vault applies a write late, after the record's key was already cleaned up (a healed failed create or a deleted record). The key exists again with that version, and no row, intent or debt points to it; the record id is never reused. The leftover stays forever.

- **Faults:** `239-STORAGE-LATE-APPLY` + `142-RACE-DELETE`
- **Effects:** `350-STORAGE-LEFTOVER`

### CC-887

Vault evicts the version under the record's pointer (`max_versions` is 10 by default, destroyed versions count) after ten or more versions piled up above it. They come from failed writes in a row, or from a burst of concurrent writers on one record with no failure at all (the winner commits first, the losers' versions land above it). Reads answer 500 until the record is overwritten or deleted. A larger `max_versions` raises the threshold; a single writer per record or a conditional `put` would prevent it, neither is in this version.

- **Faults:** `201-STORAGE-EVICT`
- **Effects:** `382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR`

### CC-897

The version under the pointer is missing in Vault: deleted or expired bypassing the service, lost by a non-durable store on restart, or the DB was restored from a backup newer than Vault. A read gets 500 (logged, after one re-read) until the record is overwritten or deleted; the service does not detect the divergence. A non-durable store also reuses version numbers after a restart, so a wrong version can be served under an old pointer; such a store is forbidden in production.

- **Faults:** `276-STORAGE-EXTERNAL-CHANGE`, `267-DB-STORAGE-NOT-SYNCED`
- **Effects:** `382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

### CC-902

The DB was restored from an old backup while Vault is newer. Pointers may reference versions already destroyed (reads give 500 until overwritten or deleted). Records created after the backup have no row, so their keys, intents and debts stay in Vault untracked, forever; the behavior is undefined.

- **Faults:** `267-DB-STORAGE-NOT-SYNCED`
- **Effects:** `382-WRONG-BEHAVIOR` + `350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR`

### CC-884

The operator sets Vault mount options (`max_versions`, `delete_version_after`, `cas_required`) and the service neither reads nor checks them. A `max_versions` below 10 brings the eviction of CC-887 closer; `delete_version_after` expires versions under pointers (reads give 500, as in CC-897); with `cas_required` every `put` is rejected, so no secret can be written. It lasts until the operator fixes the mount.

- **Faults:** `248-OPS-CONFIG`
- **Effects:** `382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR`

### CC-967

Someone with direct access to Vault storage replaced the bytes of a version or wrote a new one. The service does not detect it: a tampered version under the pointer is served as an ordinary value. A version written above the pointer is not served or tracked; the next write or delete removes it, while the tampering stays unnoticed forever.

- **Faults:** `276-STORAGE-EXTERNAL-CHANGE`
- **Effects:** `382-WRONG-BEHAVIOR`, `350-STORAGE-LEFTOVER`

### CC-998

Someone changed the gear's PostgreSQL tables bypassing the service. A deleted record row: the record is gone (404) and its key stays in Vault forever. An edited pointer: a read serves another existing version without noticing, or gives 500. Deleted intents or debts: the versions they tracked stay untracked (removed by the next write or delete of a live record, never for a key without a row). The service detects none of this.

- **Faults:** `230-DB-EXTERNAL-CHANGE`
- **Effects:** `382-WRONG-BEHAVIOR`, `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`

### CC-961

Two creates of one reference with different types, one in a tenant and one in its descendant, run at the same time. Each type check misses the other's row, which appears only after the value is stored (normally milliseconds). Both succeed and the records carry different types; nothing is left, nobody gets an error, listings stay correct. The mismatch stays until one record is deleted and re-created.

- **Faults:** `284-RACE-TYPE`
- **Effects:** `347-TYPE-MISMATCH`

### CC-893

Instances of the old and new service versions run at the same time on the same DB and Vault. They use different protocols and do not know each other's state; a mixed rollout is not supported (the migration expects the old version to stop). The outcome is undefined: untracked intents, debts and versions are possible in the DB and Vault.

- **Faults:** `250-OPS-ROLLOUT`
- **Effects:** `350-STORAGE-LEFTOVER`, `372-DB-LEFTOVER`

### CC-805

Write intents and cleanup debts pile up in the DB and the operator cannot see how many: counting rows is forbidden and metrics count only events. Growth shows only through failure metrics. Leftovers stay while nobody touches the record or reference.

- **Faults:** `291-OPS-BLIND`
- **Effects:** `372-DB-LEFTOVER`

### CC-995

The process or VM freezes for longer than the lease at any step; nothing in the process checks the elapsed time. A write whose intent another write healed meanwhile rolls back on waking and gets 503; its version stays above the pointer untracked, and for a create the key it re-creates stays forever. A frozen create widens the type-check race (CC-961); a frozen audit publish times out and the event is lost; requests to the same record wait on the frozen transaction's row locks. Safety holds: no pointer to a missing version is committed.

- **Faults:** `218-VM-DELAY`
- **Effects:** `347-TYPE-MISMATCH`, `367-AUDIT-LOST`, `350-STORAGE-LEFTOVER`, `336-EXTERNAL-ERROR`, `395-INTERNAL-ERROR`, `356-INTERNAL-DB-EXTRA-CALL`

### CC-925

A write crashed or lost its answer (CC-661, CC-679, CC-570) and the client never retries; nobody writes to or deletes that record, or creates or reads that reference, again. Reads do not clean up, so the unserved version and the expired intent stay, tracked in the DB (R1, R4a). If the record or reference is never touched, they stay forever.

- **Faults:** `220-CLIENT-NO-RETRY`
- **Effects:** `350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

### CC-938

A tenant with its own non-private record of reference X (type A) is moved under a parent that shares a record of X with type B. No create runs, so no type check runs: descendants now get type A or B depending on the branch. Inheritance follows the new hierarchy at once. Nothing is left and nobody gets an error; the mismatch stays until one record is deleted and re-created.

- **Faults:** `258-TENANT-CHANGE`
- **Effects:** `347-TYPE-MISMATCH`

### CC-913

Account Management deletes a tenant that still holds records; the service is not notified and has no offboarding. Its rows, intents and debts stay in the DB and the keys with all versions stay in Vault. No request can reach them, so they stay forever unless an operator or a future external job removes them.

- **Faults:** `258-TENANT-CHANGE`
- **Effects:** `350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

### CC-881

A tenant that holds a `shared` record is suspended or soft-deleted while its descendants stay active. The service never looks at tenant status, so the descendants keep resolving the reference to that record. Whether a suspended ancestor's credentials should stop being inherited is not decided; today they are served until the record is deleted or the tenant leaves the chain.

- **Faults:** `258-TENANT-CHANGE`
- **Effects:** `382-WRONG-BEHAVIOR`

## Numbering and notation

In a scenario, `+` joins codes that combine and `,` separates alternatives; a code is not repeated.

An ID is assigned once and never renumbered or reused; a new one is a random free number in its range: tolerated faults 100–199, out-of-model faults 200–299, effects 300–399, tolerated scenarios CC-500–CC-799, out-of-model scenarios CC-800–CC-999. Lists are ordered by meaning, not by number.
