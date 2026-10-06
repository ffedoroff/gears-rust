# CredStore: corner cases

What can go wrong in CredStore's secret writes, reads and deletes: the faults the service tolerates and those it accepts as risks, their effects, and the scenarios that combine them.

## Tolerated faults (support now: 9)

Handled by the request itself, with no background workers, timers or deferred jobs: a crash's leftovers are healed by a later request to the same record or reference, a transaction that definitely rolled back is retried up to 3 times, and an ambiguous commit of a secret write or a delete is verified once with a locking read. Handled one at a time and in the combinations of "Failure scenarios: tolerated". Guarantees:

- the record's pointer always references an existing version with exactly the bytes written; a confirmed write is not lost while fewer versions than the store keeps pile up above the pointer (`201-STORAGE-EVICT`);
- the client gets success or an error after which a retry is safe (404, 409, 503); if the process stops (`149-APP-CRASH`), the connection drops, and a retry is safe too;
- leftovers (an intent, a debt row, an extra version) are tracked in the DB and removed by a later request, with no background processes: debts by the next read or write of the record, an expired intent and its version by the record's next successful secret write or its delete, a failed create's leftovers by the next create or read of its reference; a `purge` debt of a key that has no row stays until a possible external cleanup job (residual R4b);
- the failure is visible in logs or metrics; a crash (`149-APP-CRASH`) only later, through the heal and cleanup counters.

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

- `218-VM-DELAY` — the process or VM froze (VM freeze, a long process pause, CPU starvation) for a time comparable to the lease (300 s) or longer.
- `267-DB-STORAGE-NOT-SYNCED` — the DB and Vault diverged: a row points to a version that is not in Vault, or Vault holds versions and keys that the DB does not track. Causes: the DB or Vault was restored from a backup separately from the other (or to a different point in time), data in Vault or in the DB was changed bypassing the service, a version was evicted or a request was applied late.
- `239-STORAGE-LATE-APPLY` — Vault applied a write after the writer's lease expired, when its intent may already have been healed.
- `201-STORAGE-EVICT` — Vault evicted the oldest versions of a key by its `max_versions` limit (10 by default; destroyed versions still count): ten or more versions were written under the key while the record's pointer stayed put — failed writes in a row, or a burst of concurrent writers whose losing versions land after the winner's.
- `276-STORAGE-EXTERNAL-CHANGE` — data in Vault was deleted, replaced or lost bypassing the service: a Vault administrator deleted or destroyed a version, `delete_version_after` on the mount expired it, someone with direct access to Vault storage replaced the bytes of a version or wrote a version, or a non-durable store (the in-memory plugin) lost its data on a process restart.
- `230-DB-EXTERNAL-CHANGE` — rows of the gear's tables in PostgreSQL (records, write intents, cleanup debts) were changed or deleted bypassing the service: manual SQL, a hand-written migration.
- `284-RACE-TYPE` — two creates of one reference with different types, one in an ancestor tenant and one in its descendant, overlap in time: each passes its type check before the other's row exists (an ancestor deleting and re-creating its record while a descendant's create is in flight included).
- `220-CLIENT-NO-RETRY` — the client did not retry the request and no longer touches the record or reference.
- `291-OPS-BLIND` — the operator cannot see the state: open intents and cleanup debt rows are not measured (COUNT is forbidden).
- `248-OPS-CONFIG` — a configuration error by the operator (Vault mount, lease, plugin timeout, limits).
- `250-OPS-ROLLOUT` — instances of the old and new service versions run at the same time.
- `258-TENANT-CHANGE` — a tenant changed in Account Management, and the service is not told (Account Management sends no events, and the service checks nothing when it happens): the tenant was moved under another parent (re-parenting, not offered by Account Management yet); it was deleted; it or one of its ancestors was suspended or soft-deleted (the service ignores tenant status, so an ancestor's `shared` values keep resolving for its descendants); an isolation barrier was set or removed (inheritance ignores barriers by design, so values keep resolving; only the PDP's authority changes, and it is evaluated on every request).

## Failure effects (9)

What remains after a failure and what the client sees; a scenario lists every effect that applies. Ordered by importance: correctness and security first (wrong behavior, type mismatch, lost audit), then leftovers and client errors, then internal overhead (logs, extra DB and Vault calls). Leftovers (`*-LEFTOVER`) never corrupt primary data; they are removed by a later request (see the tolerated guarantees; a dead key's `purge` debt waits for an external job), and in out-of-model scenarios they may stay forever (stated per scenario).

- `382-WRONG-BEHAVIOR` — the service behaves differently from what the client or operator expects: the record's metadata in the DB is lost or stale (404 or the old state); the secret value in Vault cannot be read (500 until overwritten or deleted); tampering that goes unnoticed.
- `347-TYPE-MISMATCH` — records of one reference in an ancestor tenant and in its descendant carry different secret types: a consumer that reads by reference gets a secret of another shape than it expects, depending on the tenant it reads in. Nothing fails; the mismatch stays until one of the records is deleted and re-created.
- `367-AUDIT-LOST` — an audit event is lost or recorded with a wrong operation label.
- `350-STORAGE-LEFTOVER` — an extra version or key remains in Vault: a leftover, the primary data is not corrupted.
- `336-EXTERNAL-ERROR` — the client sees an error code and has to make another request.
- `372-DB-LEFTOVER` — an extra service row remains in the DB (an intent or a cleanup debt): a leftover, the primary data is not corrupted.
- `395-INTERNAL-ERROR` — the client does not learn about the error, but we write it to the logs.
- `374-INTERNAL-STORAGE-EXTRA-CALL` — an extra Vault call beyond the usual path (a repeated `get`, executing a cleanup debt on the next access).
- `356-INTERNAL-DB-EXTRA-CALL` — an extra query or transaction in the DB beyond the usual path (a repeated row read, a verification transaction, a transaction retry, healing on access).

## Failure scenarios: tolerated (40)

CC-679 Record R exists (replace) or a new one is created under reference X (create); the request has not changed anything yet. The writer reads the record row with its flags (replace) or checks the reference (create), and at that moment PostgreSQL is unavailable or the connection is lost. The outcome of the step is definite: nothing was written, and the flow never reached tx0 and `put`. The protocol answers 503 immediately. Nothing appeared in the DB or Vault, there are no leftovers; the client safely retries the request.
`178-DB-DOWN`
`336-EXTERNAL-ERROR`

CC-673 The writer passed the row read and sends tx0 (insert of its own write intent) to the DB. The connection is lost around the COMMIT of tx0, and the writer does not know whether the transaction committed. Transaction retry does not help here (only a definite rollback is retried), and no verification after an ambiguous commit is done for tx0, so `put` is not called and the client gets 503. If tx0 did commit after all, an intent without a version in Vault remains in the DB: it is harmless and is never served. It is removed by healing after the lease (300 s): the next successful write to the same record in its own tx1, and for create (no row) a create or a read of the same reference; the client's retry also makes an extra row read.
`168-DB-COMMIT-LOST`
`336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-730 The writer passed tx0 and calls `put` in Vault, and Vault is unavailable or returns an error (an answer was received). The plugin does not retry `put`, so the writer answers the client 503, the row and the pointer are untouched, and tx1 is not executed. If the error is ambiguous (Vault may have applied the write and then failed), a version above the pointer may remain in Vault that nobody serves. The intent stays in the DB and tracks the key; the client retries the request and re-reads the row along the way. The intent is removed by healing after the lease (the next successful write to the same record in its own tx1, for create a create or a read of the same reference), and the possible version is removed by `destroy below` of that record or by deleting the record.
`130-STORAGE-DOWN`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-661 The writer passed tx0 and sent `put`; Vault applied it and created a version above the pointer, but the answer did not arrive: the plugin's 5 s HTTP timeout, a network drop or a lost response. `put` is not retried, the writer does not know the version number, tx1 is not executed, and the client gets 503. A version above the pointer remains in Vault (it is not served, clients read the previous value), and an intent that tracks the key remains in the DB. After the lease the intent is removed by the next successful write to the same record in its own tx1, and its `destroy below` removes the version; for create, by a create or a read of the same reference (with a `purge` of the key), and deleting the record also cleans the key. The client's retry also makes an extra row read.
`161-STORAGE-TIMEOUT`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-619 The writer passed tx0 and `put`, version v is created in Vault and the answer was received, but on the way to tx1 PostgreSQL is unavailable or the connection is lost; the outcome is definite: tx1 was not executed. The new pointer is not set, and the writer answers 503. Version v remains in Vault above the pointer (not served), and the writer's own intent remains in the DB. For a live record: the next successful write in its own tx1 removes the expired intent, and its `destroy below` removes v; for create, a create or a read of the same reference after the lease, or deleting the record (`purge`). The client retries the request.
`178-DB-DOWN`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-773 Any protocol transaction (tx0, tx1, secret removal, record delete, cleanup debt, verification transaction) rolls back on serialization failure 40001, deadlock 40P01 or SQLite busy. Such a rollback is definite, so the platform's transaction retry runs the transaction body again (up to 3 attempts with pauses of ~10 and 20 ms); the body contains only SQL, no Vault calls. One of the attempts succeeds, and the request completes with the usual answer. The client notices nothing, there are no leftovers, only an extra DB query remains.
`151-DB-CONTENTION`
`356-INTERNAL-DB-EXTRA-CALL`

CC-733 The writer runs tx0, and it rolls back on 40001, 40P01 or SQLite busy three times in a row (attempts with pauses of ~10 and 20 ms). The transaction definitely did not commit, the intent is not inserted, `put` was not called, so the writer answers 503. Nothing is written in the DB or Vault, there are no leftovers; the client safely retries the request.
`151-DB-CONTENTION`
`336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

CC-714 The writer passed tx0 and a successful `put` (version v above the pointer), but tx1 rolls back on 40001, 40P01 or SQLite busy three times in a row. The rollback is definite, so no verification after an ambiguous commit is needed: the pointer did not move, and the client gets 503. Version v remains in Vault above the pointer (not served), and the writer's own intent remains in the DB. For a live record: v is removed by `destroy below` of the next successful write, whose tx1 also removes the expired intent; for create, by a create or a read of the same reference after the lease (with a `purge` of the key), or by deleting the record.
`151-DB-CONTENTION`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-563 The writer executed `put` (version v) and tx1, but the connection was lost around the COMMIT of tx1, and the outcome is unknown. The protocol does not answer 503 right away but runs a verification transaction with a locking read once: it waits for a possibly delayed tx1 to resolve, takes its own intent `FOR UPDATE` by `attempt_id` and reads the row. Its own intent is still there, so tx1 did not commit. In the same transaction the verification repeats tx1 with the same `vv` and the same base row version and commits; then it proceeds as after a normal commit (executes the cleanup debts, answers). The client gets the usual success, there are no leftovers, only an extra DB query remains.
`168-DB-COMMIT-LOST`
`356-INTERNAL-DB-EXTRA-CALL`

CC-631 The writer executed `put` (version v) and tx1, but the connection was lost around the COMMIT of tx1, and the outcome is unknown. A verification transaction with a locking read runs once: it takes its own intent `FOR UPDATE` by `attempt_id` and reads the row. The intent is gone and the pointer is at v: so tx1 committed, and its cleanup debts were written in the same transaction. The protocol executes the record's cleanup debts (for example `destroy below v`), deletes the debt rows and answers success; the ETag is taken from the row that was read. The client sees the usual success, there are no leftovers (if executing a debt fails, the leftover is described in CC-646).
`168-DB-COMMIT-LOST`
`356-INTERNAL-DB-EXTRA-CALL`

CC-527 The writer executed `put` (version v) and tx1, the connection was lost around the COMMIT of tx1, and the outcome is unknown. The verification transaction with a locking read sees: its own intent is absent, and the pointer is not at v. So the attempt did not take effect: its intent was removed by a committed CAS loss. If no row points to v, this transaction records the cleanup debt `destroy exact v` (or `purge` if there is no row with this record_id), it is executed after the commit, and the client gets 503 (a retry is safe). The writer's version is removed, no leftovers remain in the DB; an extra DB query remains.
`168-DB-COMMIT-LOST`
`336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

CC-710 The writer executed `put` (version v) and tx1, the connection was lost around the COMMIT of tx1, and the verification transaction itself also failed because the DB is still unavailable. It runs once, so the client gets 503 and nothing is executed. The state depends on whether tx1 committed. If it did, the DB already holds the new pointer and the cleanup debts (for example `destroy below v`); they are executed on the next read or write of this record (an extra Vault call), and until then the old versions stay in Vault. If it did not, the intent and version v above the pointer remain, as in CC-619; they are removed by the next successful write or by deleting the record, for create by a create or a read of the same reference after the lease.
`178-DB-DOWN` + `168-DB-COMMIT-LOST`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `374-INTERNAL-STORAGE-EXTRA-CALL` + `356-INTERNAL-DB-EXTRA-CALL`

CC-647 The previous replace ended as in CC-710: unknown tx1 outcome, verification failed, the client got 503. The client retries the replace with the same `If-Match`, and the DB is available again. If tx1 did commit, the row already has a new version, and the answer is 409 because of the stale `If-Match` (the cleanup debts of the earlier tx1 are executed during this row read). If it did not commit, the retry goes through as a normal write, and its `destroy below` covers the version of the earlier attempt; the earlier intent is removed after the lease by the next successful write (the leftover is described in CC-710).
`178-DB-DOWN` + `168-DB-COMMIT-LOST`
`336-EXTERNAL-ERROR`

CC-737 A create under reference X inserted the row in tx1, but the ambiguous outcome and the verification ended as in CC-710: the client got 503. The client retries the create of the same reference, and the DB is available. At step 1 the protocol reads the row with its flags and finds its own record: a create over an existing row answers 409 `ALREADY_EXISTS` before tx0 and `put`. The row read sees the "has cleanup debts" flag, executes the remaining cleanup debts of the earlier tx1 (an extra Vault call) and deletes their rows. The client sees 409 (the record is already created and needs to be read), there are no leftovers.
`178-DB-DOWN` + `168-DB-COMMIT-LOST`
`336-EXTERNAL-ERROR` + `374-INTERNAL-STORAGE-EXTRA-CALL`

CC-525 A create under reference X: the row was not inserted in tx1, the ambiguous outcome and the verification ended as in CC-710, the client got 503, an intent (with the reference and record_id but no row) remained in the DB, and version v in Vault. The client retries the create: the new record needs a new record_id, and it goes through its own protocol (tx0, `put`, tx1) and is created. The earlier attempt's intent has not expired yet (lease 300 s), so it stays together with version v. When the lease expires, the first create or read of the same reference finds the expired intent without a row, deletes it, and records and executes a `purge` of the key (failed-create heal; extra DB and Vault calls). Until then the leftover is tracked in the DB.
`178-DB-DOWN` + `168-DB-COMMIT-LOST`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER` + `374-INTERNAL-STORAGE-EXTRA-CALL` + `356-INTERNAL-DB-EXTRA-CALL`

CC-694 The writer executed `put` (version v) and tx1, but a concurrent writer of the same record managed to commit first, and the writer's CAS is lost: tx1 committed as a definite loss (intent deleted, cleanup debt `destroy exact v` recorded), but the connection was lost around the COMMIT, and the outcome is unknown. The verification transaction sees: the intent is gone, the pointer is not at v. It records `destroy exact v` (again), executes it and answers 503 instead of 409 (a retry is safe). The writer's version is removed, the redundant cleanup debt is harmless, there are no leftovers.
`168-DB-COMMIT-LOST` + `169-RACE-WRITE`
`336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

CC-566 Two writers change one record at the same time (or the row was changed between the read and tx1); both read the row with version n and did `put`. The winner committed tx1 first, and the row version became n+1. For the loser, tx1 deletes its intent, but the conditional UPDATE (CAS on version n) affects 0 rows: a definite loss. In the same transaction it records the cleanup debt `destroy exact v`, executes it after the commit, and answers 409 `OPTIMISTIC_LOCK_FAILURE` (the client retries with a new `If-Match`; for the loser this is an extra DB query). The loser's version is removed, the winner's pointer is untouched, there are no leftovers.
`169-RACE-WRITE`
`336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

CC-788 Two creates with the same reference run at the same time; each has its own record_id and intent, and both passed `put`. The winner inserted the row in tx1. For the loser the insert violates the unique key `(tenant, reference, class)`: a definite loss. The insert is conflict-tolerant, so the deletion of its intent and the cleanup debt `purge` of the key of its record_id (a row with this id will never appear) are committed together. The protocol executes the `purge` and answers 409 `ALREADY_EXISTS`. The loser's key is cleaned up, there are no leftovers.
`169-RACE-WRITE`
`336-EXTERNAL-ERROR`

CC-522 The writer read the row of record R, did tx0 and `put` (version v) and is going to tx1, but between the read and tx1 another request deleted R: the row and the key (`purge`) are gone. Its `put` landed after the `purge`, and the key with version v exists in Vault again. In tx1 the writer's intent is deleted normally, but the UPDATE affects 0 rows; since there is no row with such a record_id, the same transaction records a cleanup debt `purge` of the key, which is executed after the commit. The client gets 409 `OPTIMISTIC_LOCK_FAILURE`. The writer's version is cleaned up, there are no leftovers.
`142-RACE-DELETE`
`336-EXTERNAL-ERROR`

CC-620 Two writers change one record with `If-Match: *`; both read the row with version n and do `put`. The first attempt loses the CAS (a competitor has already changed the row), and the version of this attempt goes to `destroy exact`. The protocol retries the write exactly once with a new attempt: it re-reads the row, a new intent, a new `put`, a new tx1. The retry loses too, because yet another write intervenes. The writer answers 409 `OPTIMISTIC_LOCK_FAILURE` (an extra row read and extra transactions in the DB). The versions of both losing attempts are removed by `destroy exact` cleanup debts, there are no leftovers.
`169-RACE-WRITE`
`336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

CC-570 The writer (replace or create) accepted the request, and the process shuts down before tx0: neither an intent nor `put` appeared. The client gets a connection drop and does not know whether the request was executed. Nothing is written in the DB or Vault, there are no leftovers; the client safely retries the request.
`149-APP-CRASH`
`336-EXTERNAL-ERROR`

CC-615 The writer passed tx0: its intent (record_id, reference, lease 300 s) is in the DB, but the process shuts down before `put`. The client gets a connection drop. There is nothing in Vault, so the pointer and the value are unaffected, and the intent tracks a key without versions and is harmless. After the lease expires it is removed by the next successful write to the same record in its own tx1; for create (no row), by a create or a read of the same reference: they delete the intent and record and execute a `purge` of the empty key. The client's retry makes an extra row read with flags.
`149-APP-CRASH`
`372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-691 The writer passed tx0 and `put` (version v above the pointer), but the process shuts down before tx1. The client gets a connection drop, and the pointer did not move. An orphan version v remains in Vault (not served, clients read the previous value), and an intent that tracks the key and has expired after the lease remains in the DB. A live record is healed by the next successful write: its tx1 removes the intent and `destroy below` removes v. For create, this is a create or a read of the same reference after the lease (`purge` of the key), and for any record, deleting it.
`149-APP-CRASH`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-624 The writer executed `put` (version v) and tx1: the new pointer is committed together with the cleanup debt `destroy below v`. The process shuts down before the debts are executed, the client gets a connection drop and does not know the outcome. The new pointer is already in effect and is read: all readers are served from it. Old versions remain in Vault, and the debt is tracked in the DB. The next read or write of this record sees the debts flag, executes `destroy below v` (an extra Vault call) and deletes the debt row. If the record is never touched again, the leftover (the debt and the old versions) remains forever.
`149-APP-CRASH`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER` + `374-INTERNAL-STORAGE-EXTRA-CALL`

CC-509 A cleanup debt (for example `destroy below v` or `purge`) was executed successfully in Vault, but before the debt row is deleted the process shuts down or the DB loses the network. The client has already received the usual answer (a connection drop if the process crashed), and if the network was lost, the deletion of the debt row simply failed: the error is logged, the answer does not change. The debt row remains in the DB. The next access to the record repeats the Vault call (idempotent, an extra call) and deletes the row. If the record is never touched again, the row remains.
`149-APP-CRASH`
`372-DB-LEFTOVER` + `395-INTERNAL-ERROR` + `374-INTERNAL-STORAGE-EXTRA-CALL`

CC-651 Writer A passed tx0 and `put` (version v above the pointer) and crashed before tx1; its intent remained in the DB. Before the next write, the record's secret is removed (`PATCH secret=null`): the pointer becomes NULL, and the cleanup debts `destroy below old` and `destroy exact old` are recorded, where old is the removed pointer. These debts are executed and do not touch version v, because it is above old; A's intent remains. Version v is not served (there is no secret). It and the intent are removed by the next successful secret write to this record (its tx1 removes the expired intent, `destroy below` removes v) or by deleting the record (`purge`); while the record is not touched, they remain.
`149-APP-CRASH`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

CC-646 A transaction with cleanup debts definitely committed (a rotation with `destroy below`, a lost CAS with `destroy exact`, a secret removal with two `destroy` debts), and the request executes the debts. Vault is unavailable (or the process shuts down) at this step. The error is logged and counted, the client's answer does not change (success, 204 on secret removal, 409 on a lost CAS). The debt rows remain in the DB, the old versions remain in Vault. The next read or write of this record repeats the execution (an extra Vault call) and deletes the rows. If the record is never touched again, the leftover remains.
`130-STORAGE-DOWN`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER` + `395-INTERNAL-ERROR` + `374-INTERNAL-STORAGE-EXTRA-CALL`

CC-537 The client removes the secret (`PATCH secret=null`) with an `If-Match` that carries a value. The writer read the row (version n), but before the removal transaction another request changed the row (version n+1). The removal transaction does a CAS on version n, affects 0 rows and rolls back; `put` was not called, no cleanup debts were recorded. The client gets 409 and has to re-read the row (an extra DB read). Vault and the pointer are untouched, there are no leftovers.
`169-RACE-WRITE`
`336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

CC-536 The client removes the secret: the removal transaction (CAS on `value_version = NULL` and the cleanup debts `destroy below old` and `destroy exact old`) was sent, but the connection was lost around the COMMIT. There is no verification transaction for secret removal, so the client gets 503 and nothing is executed. If it committed, the pointer is empty and the debts are in the DB: they are executed by the next read or write of the record (an extra Vault call), and until then the old versions remain in Vault. If it did not, the record stayed as it was, and the client retries the removal; there are no leftovers.
`168-DB-COMMIT-LOST`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `374-INTERNAL-STORAGE-EXTRA-CALL`

CC-687 A concurrent writer W read the row (pointer at old) and did `put` (version v above old). Then a secret removal committed before W's tx1: the pointer is NULL, the row version grew, and the cleanup debts `destroy below old` and `destroy exact old` do not touch v. W's tx1 deletes its intent, but the CAS on the earlier row version affects 0 rows: a loss. In the same transaction it records `destroy exact v`, executes it after the commit and answers 409. Version v is removed, the secret is removed, there are no leftovers; this is why secret removal never uses `delete_key`.
`169-RACE-WRITE`
`336-EXTERNAL-ERROR`

CC-750 The client deletes a record: the delete transaction (the row and the cleanup debt `purge`) was sent, but the connection was lost around the COMMIT, and the outcome is unknown. The protocol runs a verification transaction once with a locking read of the row by record_id (a delayed delete holds the lock). There is no row, so the delete committed, and the `purge` debt is already in the DB. The protocol executes the `purge` (`delete_key`), deletes the debt row and answers 204. There are no leftovers, an extra DB query remains (if `delete_key` fails, the leftover is described in CC-786).
`168-DB-COMMIT-LOST`
`356-INTERNAL-DB-EXTRA-CALL`

CC-587 The client deletes a record: the connection was lost around the COMMIT of the delete transaction, and the outcome is unknown. The verification transaction with a locking read of the row by record_id finds the row: the delete did not commit. In the same transaction the delete is repeated with the same precondition (`If-Match`) and committed, then the `purge` of the key is executed. The client gets the usual 204 answer; if the row was changed in the meantime, the answer is the one for a failed precondition (409). There are no leftovers, an extra DB query remains.
`168-DB-COMMIT-LOST`
`356-INTERNAL-DB-EXTRA-CALL`

CC-762 The client deletes a record: the outcome of the delete COMMIT is unknown, and the verification transaction also failed (the DB is unavailable). It runs once, so the client gets 503 and nothing is executed. If the delete rolled back, the record is intact and the client retries the delete. If it committed, there is no row, while the `purge` debt and the key in Vault remain: there is nobody to execute the debt (there is no record, nothing to be accessed), and a repeated delete gives 404. The leftover (the debt and the key) remains for good: no request ever touches that record id again, and the failed-create heal by reference covers only expired write intents, not debts of a deleted record.
`178-DB-DOWN` + `168-DB-COMMIT-LOST`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `356-INTERNAL-DB-EXTRA-CALL`

CC-709 The commit of a secret removal, a record delete or a debt row deletion rolls back on 40001, 40P01 or SQLite busy three times in a row (pauses of ~10 and 20 ms). The rollback is definite, so for secret removal and delete the client gets 503, the record stays as it was, `put` was not called, and a retry is safe. For the debt row deletion, Vault has already performed the call, the error is only logged, and the client's answer does not change. The debt row remains and will be executed again (idempotently) on the next access to the record; after a record delete this will not happen, and in that case the leftover remains.
`151-DB-CONTENTION`
`336-EXTERNAL-ERROR` + `372-DB-LEFTOVER` + `395-INTERNAL-ERROR` + `374-INTERNAL-STORAGE-EXTRA-CALL`

CC-775 A reader reads a record: the row with the pointer at v, then the secret `get`. In between, a successful rotation happened: its `destroy below` removed v, and the `get` missed. The reader re-reads the row once (the pointer moved to v2) and does a second `get`. But in the meantime a second rotation with a new `destroy below` happened, and the second `get` misses too. The second failure is 503, not an empty value and not a stale one (500 only when the pointer has not moved). The client retries the read. There are no leftovers, an extra row read and an extra `get` call remain.
`169-RACE-WRITE`
`336-EXTERNAL-ERROR` + `374-INTERNAL-STORAGE-EXTRA-CALL` + `356-INTERNAL-DB-EXTRA-CALL`

CC-771 The client reads a record (metadata or secret), and PostgreSQL is unavailable or the connection is lost on the row read. Nothing was changed and nothing is modified, and no Vault call was made. The protocol answers 503. There are no leftovers, the client retries the read.
`178-DB-DOWN`
`336-EXTERNAL-ERROR`

CC-668 The client reads a secret: the row is read, the pointer is at v, and Vault is unavailable or returns an error on `get` (an ordinary error, not a version miss). The reader does not retry (re-reading happens only on a version miss) and answers 503. The read audit records `read/failure`. The DB and Vault state did not change, there are no leftovers; the client retries the read.
`130-STORAGE-DOWN`
`336-EXTERNAL-ERROR`

CC-786 A `purge` cleanup debt is recorded for a key that has no row: the record was deleted; a create lost to the unique key or to a CAS when the row had disappeared; a failed create was healed. The transaction committed, and the request executes the `purge` (`delete_key`), but Vault is unavailable. The error is logged and counted, the client's answer does not change (204, 409 or the usual create/read answer). The debt row remains in the DB, the key with its versions remains in Vault. There is nobody to execute the debt: there is no row with this record_id, the record_id is not reused, and neither a read nor a write will come to it. The leftover (the debt and the key) is tracked in the DB, but remains forever (R4b) unless there is external cleanup.
`130-STORAGE-DOWN`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER` + `395-INTERNAL-ERROR`

CC-533 A `purge` cleanup debt is recorded for a key without a row, as in CC-786 (the record was deleted; a create lost; a failed create was healed), and the transaction committed. The process shuts down before it manages to execute the `purge`; the client gets a connection drop. The debt remains in the DB, the key with its versions in Vault. Nobody will come to this record_id (there is no row, the id is not reused), so the leftover remains forever (R4b) unless there is external cleanup.
`149-APP-CRASH`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

CC-794 A secret read or write request has completed, and the service publishes an audit event, but the audit broker is unavailable or rejected the event. Publishing is best effort with a 500 ms timeout: the error is logged without the secret and counted by the `audit_publish_failed` metric, while the request itself is neither aborted nor rolled back. The client gets the usual answer, the DB and Vault are untouched. The audit event is lost forever, only the log and the counter remain.
`182-AUDIT-DOWN`
`367-AUDIT-LOST` + `395-INTERNAL-ERROR`

## Failure scenarios: out-of-model (22)

CC-970 Writer A passed tx0 and sent `put`, but the client gave up (5 s timeout, the process crashed), while the request is still on its way to Vault. The lease passed, and writer B successfully writes the same record: its tx1 moves the pointer to v6, removes A's expired intent and records `destroy below 6`. Then Vault applies A's `put`: version v7 sits above the pointer, with no intent and no cleanup debt. The version is not served and is not tracked anywhere; it will be removed by the next successful write to this record (`destroy below`) or by deleting the record (`purge`).
`161-STORAGE-TIMEOUT` + `169-RACE-WRITE` + `267-DB-STORAGE-NOT-SYNCED` + `239-STORAGE-LATE-APPLY`
`350-STORAGE-LEFTOVER`

CC-864 Writer A passed tx0 and sent `put`, but the client gave up or the process crashed, while the request is still on its way. By this time the key of record R has been cleaned up: the create did not complete and its intent was healed after the lease (a create or a read of the same reference recorded and executed the `purge`), or the record was deleted (`purge`). After that Vault applies A's `put`, and the key exists again with A's version. There is no row with such a record_id, the intent is removed, there is no cleanup debt: nobody will come to the key, the record_id is not reused. The leftover remains forever.
`142-RACE-DELETE` + `267-DB-STORAGE-NOT-SYNCED` + `239-STORAGE-LATE-APPLY`
`350-STORAGE-LEFTOVER`

CC-914 The operator set the Vault plugin timeout comparable to the lease (the lease minimum of 60 s is validated, its relation to the timeout is not). The `put` lasts longer than the lease or is applied by Vault after the timeout, when the client has already gone; no in-process check enforces the relation between the two. Meanwhile someone else's successful write heals the expired intent and moves the pointer. The late `put` lands above the new pointer with no intent and no cleanup debt (503 to the client, the version is not served). It will be removed by the next successful write or by deleting the record, and for a dead key the leftover remains forever.
`239-STORAGE-LATE-APPLY` + `248-OPS-CONFIG`
`350-STORAGE-LEFTOVER`

CC-887 The record's pointer is at version v, and more than 10 versions have accumulated above it (Vault keeps `max_versions` = 10 by default, destroyed ones count too). The pointer did not move because at least 10 attempts to write this record did not reach tx1: the DB flaps on tx1 for longer than three retries, processes crash, the CAS is lost, and the operator did not raise `max_versions`. Each such attempt did a `put` and left a version above the pointer. Vault evicted the oldest one, that is, version v under the pointer. Secret read: `get` misses, the pointer has not moved, the answer is 500 Internal (logged). The record is unreadable until it is overwritten (a successful write sets the pointer to a new version) or deleted.
`178-DB-DOWN` + `267-DB-STORAGE-NOT-SYNCED` + `201-STORAGE-EVICT`
`382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR`

CC-966 Eleven or more writers update the same record R at the same time with `If-Match: <etag>` or create-only (with `If-Match: *`, roughly twenty or more, because each loser retries once). All of them read row version 7 and pass the precondition, and all of them `put` to Vault, which assigns v5…v15 in the order it applies the puts. The writer whose tx1 commits first wins the CAS (say the one holding v5) and its client gets 200; the others lose the CAS, record and execute `destroy exact` of their own versions, and answer 409. Because the winner is the first to commit, not the last to `put`, ten or more losing versions sit above its version, and Vault evicts it: the row still points at v5, which no longer exists, and reads answer 500 until the record is rewritten or deleted. No failure is involved, only concurrency on one record. A larger `max_versions` on the key raises the threshold; a single writer per record (a short claim taken in tx0, separate from the lease) or a conditional `put` would prevent it; neither is part of this version.
`169-RACE-WRITE` + `201-STORAGE-EVICT`
`382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR`

CC-897 The version under the record's pointer is gone from Vault bypassing the service: a Vault administrator deleted or destroyed it, `delete_version_after` on the mount expired it, or the store is not durable (the in-memory plugin) and lost all values on a process restart while the rows kept their pointers. The reader reads the row, the secret `get` misses, the reader re-reads the row (an extra query), and the pointer has not moved: the answer is 500 Internal, logged (retrying is pointless). The service does not know about the loss in advance; the record is unreadable until it is overwritten (replace or PATCH with a secret) or deleted. A non-durable store also starts its version numbers over after the restart, so a version written later under the same number (for example the orphan of a failed write) can be served under an old pointer, which is not detected; such a store is forbidden for production.
`267-DB-STORAGE-NOT-SYNCED` + `276-STORAGE-EXTERNAL-CHANGE`
`382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR` + `356-INTERNAL-DB-EXTRA-CALL`

CC-948 The DB was restored from a backup that is newer than the Vault state (Vault was rolled back or restored from an older snapshot). Rows point to versions that are not in Vault, because they were created after the Vault snapshot. Secret read: `get` misses, the pointer does not move, the answer is 500 Internal (logged) until overwritten or deleted. Other behavior (versions in Vault and the DB are out of sync) is undefined; the service does not detect the divergence.
`267-DB-STORAGE-NOT-SYNCED`
`382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR`

CC-902 The DB was restored from an old backup, while Vault is live and newer. The pointers in the rows are old: some of the versions under them were destroyed by `destroy below` after the snapshot, and a secret read of such records gives 500 until overwritten or deleted; the versions that remain serve the previous value. Records created after the backup have no rows, their keys with versions in Vault remain without a row, and the lost intents and cleanup debts are not tracked: the leftover remains forever, the behavior is undefined.
`267-DB-STORAGE-NOT-SYNCED`
`382-WRONG-BEHAVIOR` + `350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR`

CC-884 The operator configured the Vault mount (`max_versions`, `delete_version_after`, `cas_required`), and the service neither reads nor checks these settings. A `max_versions` below 10 brings the eviction of the version under the pointer closer (as in CC-887). `delete_version_after` deletes versions over time, including the version under the pointer (as in CC-897), and a read gives 500. With `cas_required`, every `put` without the `cas` parameter is rejected, writing secrets is impossible, and the client gets an error. This continues until the operator fixes the mount.
`267-DB-STORAGE-NOT-SYNCED` + `248-OPS-CONFIG`
`382-WRONG-BEHAVIOR` + `336-EXTERNAL-ERROR`

CC-967 Someone with direct access to Vault storage replaced the bytes of an existing version or wrote a new version bypassing the service. The service does not detect the tampering (the protocol has no byte fingerprint check): integrity rests only on the backend's contract. A tampered version under the pointer is served as an ordinary value. A version written bypassing the service above the pointer is not served and is not tracked in the DB. It will be removed by the next successful write to the record or by its deletion, while the tampering remains unnoticed forever.
`267-DB-STORAGE-NOT-SYNCED` + `276-STORAGE-EXTERNAL-CHANGE`
`382-WRONG-BEHAVIOR` + `350-STORAGE-LEFTOVER`

CC-998 Someone with direct access to PostgreSQL changed the gear's tables bypassing the service (manual SQL, a hand-written migration). A deleted record row: the record disappears (404), and its key with all versions stays in Vault with no `purge` debt, forever. An edited `value_version`: a secret read serves another version that still exists under the key (for example an orphan above the pointer) without noticing, or answers 500 when there is no such version. Deleted intent or cleanup debt rows: the versions they tracked stay in Vault untracked; for a live record they are removed by its next successful secret write (`destroy below`) or its delete (`purge`), for a key without a row never. The service detects none of this.
`267-DB-STORAGE-NOT-SYNCED` + `230-DB-EXTERNAL-CHANGE`
`382-WRONG-BEHAVIOR` + `350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR`

CC-961 Two creates of reference X with different types run at the same time: one in tenant T1, one in its descendant T2 (or T1 deletes its record and re-creates it with another type while T2's create is in flight). Each checks the other direction before the other's row exists: T2's upward check finds nothing or the old type, and T1's downward check does not see T2's row, which T2 inserts only in its tx1 after `put` (the window is the duration of a create, normally milliseconds, at most the store timeout). Both creates succeed, and the records of one chain carry different types. There are no leftovers in the DB or Vault and the client gets no error; listings stay correct (a winner outside the permitted types is dropped); the mismatch remains until one of the records is deleted and re-created.
`284-RACE-TYPE`
`347-TYPE-MISMATCH`

CC-893 A migration is in progress, and instances of the old and new service versions run at the same time on the same DB and Vault. They act under different protocols (old and new key, intent and cleanup debts, different plugin contracts) and do not know about each other's state. The migration is designed for stopping the old version; a mixed rollout is not supported. The consequences are undefined: leftovers (intents, cleanup debts, versions under a foreign key) that nobody tracks are possible in the DB and in Vault.
`250-OPS-ROLLOUT`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

CC-805 Intents and cleanup debt rows pile up in the DB (crashed writes, unexecuted debts), and the operator cannot see their number: counting rows (COUNT) is forbidden, and the metrics count only events (recorded, failed, healed), with no gauge of open intents and debts. The growth of leftovers is visible only indirectly, through failure metrics. The state stays invisible while the records are not touched; a leftover does not go away while there is no access to the record or reference.
`291-OPS-BLIND`
`372-DB-LEFTOVER`

CC-995 The writer executed tx0, but a slow DB or a suspension of the process delayed it so that most of the lease passed before `put`. There is no in-process check of the elapsed time: the writer calls `put` as usual and continues with tx1. The outcome depends on whether the intent was healed meanwhile: if not, the write completes normally; if yes, it ends as in CC-829 or CC-854 (tx1 finds no intent, rolls back, 503). The lease must comfortably exceed the time a store may still apply a received request (deployment requirement, see CC-914).
`218-VM-DELAY`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR`

CC-829 Record R exists. Writer A passed tx0 and `put`, received the answer (version vA), then froze (VM freeze) for longer than the lease. Meanwhile writer B successfully writes R: its tx1 removes A's expired intent, sets the pointer to vB > vA and records `destroy below vB`, which covers vA. A wakes up, its tx1 does not find its intent, rolls back and answers 503. Version vA is already removed by B's `destroy below vB`, so there are no leftovers.
`218-VM-DELAY`
`336-EXTERNAL-ERROR`

CC-854 Record R exists, the pointer is at v4. Writer A passed tx0, then froze (VM freeze) for longer than the lease before `put` was applied in Vault. Meanwhile writer B successfully writes R: v6, tx1 moves the pointer to v6 and removes A's expired intent. A wakes up, its `put` reaches Vault, gives v7 above the pointer, and the answer is received; the DB is available. A's tx1 does not find its intent, rolls back and answers 503. Version v7 stays above the pointer with no intent and no debt: it is not served and is removed by the next successful secret write to R (`destroy below`) or by deleting R. For a create the same leaves a key that has no row, and the version stays forever.
`218-VM-DELAY` + `267-DB-STORAGE-NOT-SYNCED`
`350-STORAGE-LEFTOVER` + `336-EXTERNAL-ERROR`

CC-925 A writer crashed or lost the answer after `put` (CC-661, CC-619, CC-691): version v is above the pointer, the intent is expired. The client did not retry the write, and nobody writes or deletes the record anymore. A read does not remove expired intents (the orphan is not served, readers see the previous value), and cleanup is done only by the next successful write (`destroy below` and removal of the intent) or by deleting the record (`purge`). So the orphan version v and the intent remain in Vault and the DB, tracked in the DB (R1), until the record is touched; if it is never touched, they remain forever.
`149-APP-CRASH` + `220-CLIENT-NO-RETRY`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

CC-919 A create did not complete (CC-661, CC-619, CC-525, CC-691): there is no row, an intent with the reference and record_id remained in the DB, and a version under this record_id's key in Vault. The client did not retry the create of the same reference, and nobody reads it. The failed-create heal is triggered only by a create or a read of this reference after the lease; without them the intent and the version remain. The leftover is tracked in the DB (R4a) and remains forever until someone creates or reads this reference.
`149-APP-CRASH` + `220-CLIENT-NO-RETRY`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

CC-938 Tenant T2 holds its own record of reference X with type A, and Account Management moves T2 under a new parent T1 that holds a `shared` record of X with type B. No create runs, so neither type check runs: T2's record now overrides T1's record of another type, and T2's descendants that inherit X get type A while T1's other descendants get type B. Inheritance itself follows the new hierarchy at once, as designed. There are no leftovers in the DB or Vault and nobody gets an error; the mismatch remains until one of the records is deleted and re-created.
`258-TENANT-CHANGE`
`347-TYPE-MISMATCH`

CC-913 Account Management deletes tenant T while T still holds credential records. The service is not notified and has no offboarding: T's rows, together with any write intents and cleanup debts, stay in the DB, and the keys with all their versions stay in Vault. No request can reach them any more (there is no subject in a deleted tenant), so nothing heals or deletes them; they remain forever unless an operator or a future external job removes them.
`258-TENANT-CHANGE`
`350-STORAGE-LEFTOVER` + `372-DB-LEFTOVER`

CC-881 Tenant T1 holds a `shared` record of reference X, and Account Management suspends or soft-deletes T1 while its descendants stay active. The service takes only the ids from the ancestor chain and never looks at tenant status, so T1's descendants keep resolving X to T1's value, and T1's records stay in the DB and Vault. Whether a suspended ancestor's credentials should stop being inherited is not decided; today they are served until T1's record is deleted or the tenant is removed from the chain.
`258-TENANT-CHANGE`
`382-WRONG-BEHAVIOR`

## Numbering

An ID is assigned once and never renumbered or reused; a new one is a random free number in its range: tolerated faults 100–199, out-of-model faults 200–299, effects 300–399, tolerated scenarios CC-500–CC-799, out-of-model scenarios CC-800–CC-999. Lists are ordered by meaning, not by number.
