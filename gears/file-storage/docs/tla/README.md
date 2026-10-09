# file-storage: TLA+ models

Three independent TLA+ models of one gear (`file-storage`), one per protocol:

| Model | Protocol | Step prefixes | Details |
|---|---|---|---|
| `FileStorageUpload.tla` | create → sidecar PUT → finalize → bind → delete → sweep → read (single-part upload) | `U`, `B`, `D`, `S`, `R` | `states-upload.md` |
| `FileStorageMultipart.tla` + `FileStorageMultipartTwoSessions.tla` | multipart initiate → part upload → report_part → complete → abort → sweep; two sessions racing to auto-bind one file | `M`, `MS` | `states-multipart.md` |
| `FileStorageMigration.tla` | `migrate_backend`: lease → transfer/verify → CAS → cleanup, racing a delete, a reader, lease expiry, timeout, cancellation | `G`, `G.D`, `G.R`, `G.X` | `states-migration.md` |

`states.md` is a one-paragraph-per-model index into the three write-ups above;
read those for the full step ↔ code correspondence. This file covers what each
model does and does not cover, how to run and reproduce everything, the
control-run results, the findings, the mutation-testing table, and known
model limitations.

## Fix status (2026-10-02)

Five of the ten findings below are now **fixed in code** (branch
`file-storage`, uncommitted working tree as of this writing). Each fix got
its own boolean `CONSTANT` in the model, `TRUE` = current (fixed) code:

| Finding | Constant | Code fix (one line) |
|---|---|---|
| G.12 / G.14 (migration) | `FixLeaseThroughCleanup` | `rebind_backend`'s CAS no longer clears the migration lease; `release_migration_lease` only runs after the post-commit source delete |
| F1 (upload, stale-PUT-outlives-delete) | `FixDownloadHashCheck` | GET claims carry the version's whole-object SHA-256 at issuance; the sidecar verifies the full download stream against it and aborts on mismatch |
| F3 (upload, `delete_file`'s missing recheck) | `FixDeleteIfMatchInTx` | the `If-Match` etag is re-verified a second time, inside the delete transaction, against the row it just locked |
| M7 (multipart, stuck `in_progress` session) | `FixCloseFromInProgress` | the embedded session-close CAS now also matches `state = 'in_progress'`, not just `'completing'` |
| M8, deep shape (multipart, assembled-object orphan) | `FixDeleteAssembledObject` | best-effort delete of the assembled backend object, both from the rejected finalize call and from the sweep's `delete_pending_version` success path |

Still open (not fixed, or not fixable by this gear): **M8's shallow shape**
(`backend.abort_multipart`'s own best-effort, no-retry discard — operationally
mitigated by a bucket lifecycle rule, not by this gear), **F2** (the P3
blob-without-row reconciliation gap, documented and accepted), **M1 / #5103**
(the `report_part` fencing gap — only reachable on the hypothetical,
currently-unreachable offset-object backend), and **#5013** (an external actor
acting outside the gear's own coordination). `#5106` (a plain failed
best-effort delete) was never a distinct bug in this model's terms — it is
the same residual class as F2/M8-shallow.

**No violation was found on the new code with every fix enabled** — see
Results below; `M8_DeepOrphan_NotReachable`'s closure is additionally backed
by a by-hand proof, not just the model-checked result (see its own finding
entry).

## Modelled / Not modelled

### Upload (`FileStorageUpload.tla`)
**Modelled**: create (fresh + idempotency replay), the sidecar's create-exclusive PUT, finalize (read-back verification, the `pending`/`available` CAS, idempotent PUT-retry convergence), manual bind as a genuine two-phase action (`ReadEtag` + `BindWithSaved`, so a stale cached etag can be told apart from a fresh one), auto-bind-on-finalize, both delete entry points (`delete_version_or_whole_file` — atomic — and `delete_file` — a genuine two-phase check-then-act, re-verified inside the transaction when `FixDeleteIfMatchInTx`), the two sweep passes (abandoned-pending reclaim, retention expiry), download-URL issuance and the sidecar read (whole-object hash re-verified against the DB-recorded value at issuance when `FixDownloadHashCheck`, otherwise no re-check of the DB at all), and a stale-but-unexpired PUT token being replayed against a version whose row may already be gone.
**Not modelled**: multipart upload entirely (own model below); metadata patch and ownership transfer (checked once, structurally can't touch content); backend migration (own model below); `Range` reads (so `FixDownloadHashCheck`'s own real-code carve-out — "Range responses are never checked against a whole-object hash" — is not separately exercised here, only asserted in code/doc comments); idempotency-key TTL/sweep; PDP/authorization/quota (any such gate only ever turns a would-succeed step into an upfront rejection, already covered by nondeterministic choice not to take the step). `Files` is a small, *reused* symbolic-name pool (unlike the real `file_id`, a `Uuid::now_v7()` never reused) — see **Model limitations** for the one place this needed a dedicated fix (`fileGen`/`dGen`). Full detail: states-upload.md's "Not modelled" section.

### Multipart (`FileStorageMultipart.tla`, `FileStorageMultipartTwoSessions.tla`)
**Modelled**: initiate (plan, pending version, backend-side native multipart handle), both part-write paths (native S3-style per-part mutable register, and the hypothetical non-native offset-object path), `report_part`'s authoritative upsert (and its known fencing gap, #5103), `complete`'s full lease/takeover/converge machinery including the detached finalize transaction's five sub-steps (version CAS, manifest insert, auto-bind CAS, the *separately*-fenced session-close CAS — now also closing from `in_progress` when `FixCloseFromInProgress` — and the standalone converge path), abort (CAS-first, part-row cleanup in the same transaction, best-effort backend/version cleanup, plus a best-effort assembled-object delete when `FixDeleteAssembledObject`), and the sweep's expired-session reclaim (same CAS as user abort, plus the same assembled-object delete on its own reclaim path). `FileStorageMultipartTwoSessions.tla` additionally models two independent sessions on the *same* file racing to auto-bind, as a separate, minimal model (see its own header for why a mechanical duplication of the single-session model would not have answered that question) — unaffected by either of this task's fixes (both are about the single-session finalize/sweep machinery this model doesn't include).
**Not modelled**: the offset-object backend's `complete_multipart` is *unreachable in the shipped code* today (Discrepancy #1 in states-multipart.md) — `NativeBackend = FALSE` models a hypothetical backend, not production; cross-backend orphan reconciliation (explicitly deferred to P3 in `cleanup.rs`, except where `FixDeleteAssembledObject` now specifically targets the one assembled-object case); real wall-clock lease/session timestamps (abstracted to an integer `clock` against `SessionExpiresAt`/`LeaseDuration`). Full detail: states-multipart.md's "Discrepancies" section and each invariant's own note.

### Migration (`FileStorageMigration.tla`)
**Modelled**: one `Available` version's one attempt end-to-end — lease acquire (CAS, database-clock timed), transfer+verify+publish (the destination-tail "retry once" rule), the pre-CAS `stat`, the rebind CAS and its three outcomes (committed / lost / ambiguous-under-timeout) — the lease held through the whole post-commit cleanup, not released by the CAS itself, when `FixLeaseThroughCleanup` — lost-CAS recovery, the post-commit source delete, lease release, the timeout and client-cancellation paths (each can cut the attempt short at a different, documented set of points), lease expiry enabling a genuine second concurrent attempt, a concurrent delete racing the CAS, a reader holding a pre-migration backend reference, and an external actor tampering with a backend object outside the gear's own coordination (`ExternalActor`, issue #5013).
**Not modelled**: PDP/authorization; the versioned-file/not-yet-`Available` rejections (out of this feature's scope); the same-backend no-op short-circuit (performs no write); real lease timestamps (abstracted to one nondeterministic `LeaseExpire` action); the retention/orphan sweep (confirmed never to touch `Available` versions, so it structurally cannot race a migration). Full detail: states-migration.md's "Not modelled" section.

## Run

```
java -Xmx4g -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -workers 6 -deadlock \
     -metadir /some/tmp/dir -config <Module>.cfg <Module>
```
from this directory. `-deadlock` because every model has idle/terminal actors
that are not themselves a deadlock. SANY parse check: `java -cp tla2tools.jar
tla2sany.SANY <Module>.tla`. TLC 2026.09.30 (`tla2tools.jar` pinned for this
task).

Each finding has its own committed `<Module>_<id>.cfg` that reproduces it in
isolation (minimal constants, only the violated invariant/property enabled,
every OTHER fix constant left at its current-code `TRUE` value so only the
one finding under test is reverted) — run it the same way; TLC reports the
violation and the shortest trace.

| Finding | Config | Reverts |
|---|---|---|
| F1 (`I5_ReadExactOrMiss`) | `FileStorageUpload_F1.cfg` | `FixDownloadHashCheck = FALSE` |
| F2 (`I4_NoPermanentOrphan`) | `FileStorageUpload_F2.cfg` | (no fix exists; both upload constants TRUE) |
| F3 (`I9_SavedDeleteRespectsCAS_SpecificEtag`) | `FileStorageUpload_F3.cfg` | `FixDeleteIfMatchInTx = FALSE` |
| G1/G.12 (`G1_NoDanglingPointer`, `ExternalActor=FALSE`) | `FileStorageMigration_G12.cfg` | `FixLeaseThroughCleanup = FALSE` |
| G.14 (`G4_TailDeleteSafe`, `ExternalActor=FALSE`) | `FileStorageMigration_G14.cfg` | `FixLeaseThroughCleanup = FALSE` |
| G1, #5013 (`G1_NoDanglingPointer`, `ExternalActor=TRUE`) | `FileStorageMigration_ExternalActor.cfg` | (not fixable here; `FixLeaseThroughCleanup = TRUE`) |
| M1, #5103 (`M1_ManifestMatchesBytes`, `NativeBackend=FALSE`) | `FileStorageMultipart_M1.cfg` | (no fix exists; both multipart constants TRUE) |
| M7 (`M7_AbortCompleteExclusive`) | `FileStorageMultipart_M7.cfg` | `FixCloseFromInProgress = FALSE` |
| M8, shallow (`M8_NoPermanentOrphan`) | `FileStorageMultipart_M8_shallow.cfg` | (no fix exists; both multipart constants TRUE) |
| M8, deep (`M8_DeepOrphan_NotReachable`) | `FileStorageMultipart_M8_deep.cfg` | `FixDeleteAssembledObject = FALSE` |

The main `.cfg`/`_medium.cfg` for each module run with **every** fix constant
`TRUE` (i.e. describe the model as currently shipped) and enable every
invariant that is now expected to hold given those fixes — `G1_NoDanglingPointer`/
`G4_TailDeleteSafe` (migration), `I5_ReadExactOrMiss`/
`I9_SavedDeleteRespectsCAS_SpecificEtag` (upload), `M7_AbortCompleteExclusive`/
`M8_DeepOrphan_NotReachable` (multipart) — in addition to the invariants that
already held before this task. They deliberately still **exclude** every
invariant known to remain violated (M8's shallow shape, F2, M1/#5103,
#5013) — see **Fix status** above and **Findings** below.

## Results

Control runs for this task (`-workers 6`, `-deadlock`, TLC 2026.09.30, this
machine, 2026-10-02, all fix constants `TRUE` on the main/medium rows).
"Exhaustive" = the full state graph was explored (TLC's own "0 states left
on queue" + no fingerprint-collision risk reported); "timeout 300/600" runs
that print no error timed out with states still queued (not exhaustive, no
violation found in the explored portion).

| Model | Config | Result | States gen / distinct | Depth | Time |
|---|---|---|---|---|---|
| Upload | `FileStorageUpload.cfg` (small) | exhaustive, no error | 33,674,911 / 6,608,634 | 22 | 1 min 02 s |
| Upload | `FileStorageUpload_medium.cfg` | no error, **not exhaustive** (timeout 600) | 185,530,874 / 53,017,195 (still queued) | 10 reached | 600 s |
| Multipart | `FileStorageMultipart.cfg` (small) | exhaustive, no error | 2,880,149 / 712,614 | 21 | 6 s |
| Multipart | `FileStorageMultipart_medium.cfg` | **exhaustive, no error** | 136,001,718 / 32,265,524 | 26 | 3 min 52 s |
| Multipart | `FileStorageMultipartTwoSessions.cfg` | exhaustive, no error (unaffected by either fix) | 13,570 / 5,020 | 16 | <1 s |
| Migration | `FileStorageMigration.cfg` (small) | exhaustive, no error | 25,192,349 / 5,071,252 | 40 | 44 s |
| Migration | `FileStorageMigration_medium.cfg` | exhaustive, no error | 36,044,269 / 3,949,530 | 24 | 1 min 06 s |

Findings reproduction runs (this task, small/minimal configs above, the one
named fix constant set `FALSE`, everything else `TRUE`):

| Finding | Config | Result | States gen / distinct | Depth |
|---|---|---|---|---|
| F1 | `FileStorageUpload_F1.cfg` | **violated** | 110,659 / 43,430 | 9 |
| F2 | `FileStorageUpload_F2.cfg` | **violated** | 1,391 / 659 | 6 |
| F3 | `FileStorageUpload_F3.cfg` | **violated** | 19,798 / 6,749 | 10 |
| G1/G.12 | `FileStorageMigration_G12.cfg` | **violated** | 111,110 / 35,655 | 13 |
| G.14 | `FileStorageMigration_G14.cfg` | **violated** | 522,915 / 141,573 | 17 |
| G1, #5013 | `FileStorageMigration_ExternalActor.cfg` | **violated** | 44 / 37 | 4 |
| M1, #5103 | `FileStorageMultipart_M1.cfg` | **violated** | 62,146 / 27,604 | 9 |
| M7 | `FileStorageMultipart_M7.cfg` | **violated** | 195,853 / 62,501 | 15 |
| M8, shallow | `FileStorageMultipart_M8_shallow.cfg` | **violated** | 2,025 / 1,279 | 6 |
| M8, deep | `FileStorageMultipart_M8_deep.cfg` | **violated** | 349,491 / 133,056 | 11 |

Depths/state counts differ slightly from the pre-fix report for some findings
(e.g. F1/F3/M1/M7/M8-deep) purely because the model gained new CONSTANTs and
a new ghost variable (`rExpect`, `deepCleanupAttempted`) since then, which
shifts TLC's fingerprint ordering and hence *which* shortest trace it reports
first — the scenario each finding config reproduces is unchanged (verified by
hand against each trace; see **Findings**). G1/G.12, G.14 and #5013's depths
are unchanged (those configs' constants/invariants didn't change shape).

Earlier agents' own, larger-scale runs (long runs, simulation, symmetry-reduced
runs at bigger constants, the full mutation sweeps) are reported in each
model's own `states-*.md` with their own numbers — not repeated here; this
table is the final control pass for this task, run against the fixed code.

## Findings

**No violation was found on the new (fixed) code** — every main/medium run
above, with every fix constant `TRUE`, completed with no error. This section
is unchanged in substance from the pre-fix report except where noted; each
entry now states its fix status up front.

Every finding below was traced by hand against the real code at the time it
was found (see each `states-*.md` entry cited); none is a TLA+ artifact
disconnected from a real interleaving the Rust code allows, **except** where
noted (F3's first, depth-6 trace — superseded below).

- **F1 — stale PUT token outlives a delete, serves new bytes instead of a miss.**
  **FIXED** (`FixDownloadHashCheck`). A PUT token for a version id is still
  cryptographically valid after that version's row *and* backend blob are
  both legitimately deleted (the sidecar never re-checks the control plane,
  `bin/sidecar.rs::upload`); a download ticket issued *before* the delete
  then observes the NEW bytes a late PUT publishes at the same (deterministic)
  path, never a `miss`, never the original content either. Invariant
  `I5_ReadExactOrMiss`, depth 9 (new trace numbering; same scenario as
  phase-3's original depth-9 trace — verified by hand against
  `FileStorageUpload_F1.cfg`'s trace, which still ends in `StaleRetryPut` onto
  a deleted version id, then a dangling `DoRead` observing it).
  **Fix** (now in code, matches the model-verified candidate from the
  original report): the download path verifies the backend bytes against the
  hash recorded in the DB at issuance time, aborting the stream on any
  mismatch (`Claims::content_sha256`, `verify_whole_object_download_stream`).
  Model-verified: `FileStorageUpload.cfg`/`_medium.cfg` with
  `FixDownloadHashCheck = TRUE` include `I5_ReadExactOrMiss` and pass
  (exhaustive / no-error-within-budget, see Results).
- **F2 — a best-effort blob delete can fail forever, leaving an orphan.**
  **NOT FIXED** (known, accepted residual).
  `D`/`S`'s blob-clearing calls are allowed to silently fail with no retry
  anywhere in the system. Invariant `I4_NoPermanentOrphan`, depth 6.
  **Classification**: known, documented P3 gap ("Backend blob-without-row
  reconciliation... deferred to P3", `concurrency-and-failure-model.md` §5),
  not a new bug. **Fix**: none proposed (accepted residual, pending P3 work).
- **F3 — `delete_file`'s missing recheck loses a concurrent bind, with a
  concrete etag.** **FIXED** (`FixDeleteIfMatchInTx`).
  `delete_file`'s If-Match check (D.2a) runs outside any transaction;
  `delete_file_inner` (D.2b) ran unconditionally, never re-reading
  `content_id`. A client's `DELETE` whose own precondition read a REAL,
  concrete etag (a genuinely bound version, not `If-Match: *`) and genuinely
  passed could still destroy a DIFFERENT version a concurrent bind
  retargeted the file to in the gap between D.2a and D.2b. Restricted
  invariant `I9_SavedDeleteRespectsCAS_SpecificEtag` (excludes the `*`
  wildcard, which is not a bug — see **Model limitations**), depth 10.
  **Fix** (now in code, matches the model-verified fix from the original
  report): the etag comparison moved inside D.2b, re-reading and
  re-comparing `content[f]` (`etag::content_etag` against the locked row's
  `content_id`) in the same step as the wipe. Model-verified:
  `FileStorageUpload.cfg`/`_medium.cfg` with `FixDeleteIfMatchInTx = TRUE`
  include `I9_SavedDeleteRespectsCAS_SpecificEtag` and pass.
- **G1/G.12 — a stale post-commit source-delete can race a later migration
  back onto the same backend.** **FIXED** (`FixLeaseThroughCleanup`).
  `rebind_version_backend`'s CAS cleared the migration lease in the *same
  statement* as the rebind, strictly before the post-commit source delete
  (`G.12`) even started; a second, independent `migrate_backend` attempt
  could acquire the now-free lease and commit its own (correct) write to
  that same backend before the first attempt's long-delayed source delete
  fired, which then wiped the second attempt's live content. Invariant
  `G1_NoDanglingPointer`, `ExternalActor=FALSE`, depth 13.
  **Classification**: explicitly not #5013 — no external actor — and not
  #5106 — not a failed delete. **Fix** (now in code, matches the
  model-verified `leasethrough` candidate from the original report): the
  lease is held through the post-commit cleanup instead of being released in
  the same statement as the CAS. Model-verified: `FileStorageMigration.cfg`/
  `_medium.cfg` with `FixLeaseThroughCleanup = TRUE` include
  `G1_NoDanglingPointer` and pass (exhaustive).
- **G.14 — the timeout's own "clean up my own write" branch has the same
  gap.** **FIXED** (same fix as G.12, `FixLeaseThroughCleanup`).
  A timeout's best-effort delete of its *own*, never-committed destination
  write did not re-check whether the row's pointer had, in the meantime,
  come to equal that exact backend (through an unrelated G.12-style chain).
  Depth 17 (`SYMMETRY` on `Migrators`).
  **Classification**: related to G1/G.12 (same root defect). **Fix**: the
  same `FixLeaseThroughCleanup` fix closes this too — holding the lease from
  acquire through release serializes every migrator attempting the same
  version, so nothing can change `row.backend` out from under a migrator
  that still holds the lease. Model-verified: same runs as G1/G.12 above
  (`G4_TailDeleteSafe` in the main/medium invariant list, passes).
- **G1, #5013 — an external actor can make the pointer dangle.** **NOT
  FIXED** (out of scope for this gear by definition).
  Direct backend-console surgery / another tool sharing the path namespace /
  shipped-but-misconfigured lifecycle rules can delete or overwrite an
  object outside the gear's own coordination, at any point. `ExternalActor=TRUE`,
  depth 4. **Classification**: known issue #5013. **Fix**: none in scope.
- **M1, #5103 — a stale `report_part` row can outlive the bytes it describes.**
  **NOT FIXED** (known issue, out of scope for this task's fixes).
  `report_part`'s authoritative upsert has no fencing against the physical
  per-part register's own value — **unless** the backend's own
  `complete_multipart` validates each part's etag itself (`NativeBackend =
  TRUE`, the shipped S3/in-memory backends), which is what actually saves
  production today. `NativeBackend=FALSE` (a hypothetical, currently-
  unreachable backend), depth 9. **Classification**: known issue #5103.
  **Fix**: none implemented this task; a report-time CAS against the
  physical register (`FenceSamePart=TRUE`) was previously shown to be only a
  **partial** fix (doesn't close the "report dropped entirely" sub-case).
- **M7 — a finalized-but-unclosed session reads as an ordinary abandoned
  upload.** **FIXED** (`FixCloseFromInProgress`).
  `finalize_multipart_version`'s session-closing CAS could lose on the very
  same transaction that just won the version CAS (a takeover's own failed
  attempt released the lease moments earlier); the session row then
  genuinely, truthfully read `in_progress` forever until some later
  `complete` call happened to land. Depth 15 (minimal trace needs a lease
  takeover, hence `NativeBackend=TRUE`).
  **Classification**: acknowledged in the code's own comments (the
  `f2_stale_completer_converges_instead_of_stranding_after_owner_fencing_
  fix` regression doc called this exact scenario "left to the same
  fallthrough, out of scope for this fix"). Severity was observability/
  audit-trail only, not data loss. **Fix** (now in code): the embedded
  session-close CAS (`MultipartRepo::finish_complete`, `expected_owner =
  None`) now matches `state IN ('completing', 'in_progress')`, not just
  `'completing'`. Model-verified: `FileStorageMultipart.cfg`/`_medium.cfg`
  with `FixCloseFromInProgress = TRUE` include `M7_AbortCompleteExclusive`
  and pass (exhaustive).
- **M8, shallow — a best-effort backend discard with no retry.** **NOT
  FIXED** (known, accepted residual, independent of this task's fixes).
  `backend.abort_multipart` is purely best-effort; if it fails once after a
  session is reclaimed before any completer assembled anything, the
  per-part physical registers linger forever (nothing ever retries).
  Depth 6. **Classification**: known, accepted residual — partially
  mitigated *operationally* (not by this gear) by a real S3 bucket's
  "abort incomplete multipart uploads after N days" lifecycle rule.
- **M8, deep — an already-assembled object has no cleanup path at all.**
  **FIXED** (`FixDeleteAssembledObject`).
  A completer's `backend.complete_multipart` (M.4.8.5) already physically
  succeeded — the final object genuinely exists — before the session is
  reclaimed (sweep or user abort) ahead of that completer's own finalize
  transaction committing. `NativeBackend=TRUE` (the shipped backends),
  depth 11. **Classification**: was a known P3 gap (Discrepancy #2 —
  cross-backend orphan reconciliation deferred to P3, `cleanup.rs`'s own
  module doc). **Fix** (now in code): (a) `MultipartService`'s complete path
  best-effort deletes the backend object when `finalize_multipart_version`
  rejects with the "session is no longer completing (aborted by cleanup)"
  conflict; (b) the sweep's `delete_pending_version` success path ALSO
  best-effort deletes the version's backend object. **Completeness proof**
  (beyond the model-checked result): the model's `dbPart` (DB part rows) is
  wiped in the SAME step that flips a session to `aborted`
  (`UserAbort`/`SweepAbortExpired`), and `DeliverReport` (the only action
  that repopulates `dbPart`) requires `sessState = "in_progress"` — so once a
  session is `aborted`, `dbPart` can never again satisfy `AllPartsReported`,
  which `Assemble`'s *first-time-success* branch (the only place
  `backendObjectExists` goes `FALSE → TRUE`) requires. Therefore
  `backendObjectExists`'s value is frozen at whatever it was at the exact
  instant the session became `aborted`, except for this fix's own two
  delete sites — so site (b) alone, whenever it runs, always observes the
  object's TRUE final status, regardless of ordering against a still-in-flight
  completer's `Assemble`/`Finalize` call. This rules out the ordering gap
  that would otherwise seem possible ("the sweep's delete runs before a
  slow completer's assembly finishes, and that completer then crashes before
  calling `Finalize`") — a dedicated exhaustive run with every fix `TRUE`
  and ONLY `M8_DeepOrphan_NotReachable` as the invariant found **no
  violation** (2,880,149 states, depth 21), consistent with this proof.
  Model-verified: `FileStorageMultipart.cfg`/`_medium.cfg` with
  `FixDeleteAssembledObject = TRUE` include `M8_DeepOrphan_NotReachable`
  (revised from a plain reachability witness to the same "at rest"
  antecedent `M8_NoPermanentOrphan` uses, scoped to the deep conjunct alone
  — see its own doc comment in `FileStorageMultipart.tla`) and pass
  (exhaustive).

## Mutations

Each mutation is a scratchpad copy of the real model (never applied to the
committed `.tla`) with exactly one real guard removed or weakened, run to
find the shortest violating trace. Full per-trace narrative in each
`states-*.md`; this table collects the headline numbers. Unaffected by this
task (no mutation touched the fixed code paths); reproduced from the
pre-fix report for reference.

| Model | # | Mutation (one guard removed) | Caught by | Depth |
|---|---|---|---|---|
| Upload | u1 | Finalize commits without read-back verification | `I2_AvailableHasBlob` | 7 |
| Upload | u2 | Single-step `Bind`, no If-Match CAS (original shape) | **not caught by any invariant** — proven identical reachable relation to the unmutated spec (818,435 distinct states both) | — |
| Upload | u2b | `BindWithSaved`'s CAS removed (after the 2-phase revision) | `I8_SavedBindRespectsCAS` (≥2 Clients) | 10 |
| Upload | u3 | Sweep reclaims with no age/status guard | `I1_NoDanglingContent` | 6 |
| Upload | u4 | Delete-version with no current-version/row-lock guard | `I1_NoDanglingContent` | 6 |
| Upload | u5 | Sidecar PUT overwrites in place (not create-exclusive) | `I2_AvailableHasBlob` | 6 |
| Upload | u6 | Idempotency replay with no "target still pending" guard | `I5_ReadExactOrMiss` | 9 |
| Migration | m1 | `G.8` tail rule drops the "still on source" check | `G1_NoDanglingPointer` | 9 |
| Migration | m2 | `Timeout`'s ambiguous-committed branch ignores `cas_started` | `G1_NoDanglingPointer` | 6 |
| Migration | m3 | `Release` never clears the lease on any exit path | `G1_NoDanglingPointer` on the unpatched base (pre-existing G.12 trace, depth 13); **no violation** isolated on the (now shipped) `FixLeaseThroughCleanup` fix (~49M states, depth 34) | 13 / — |
| Migration | m4 | `LeaseExpire` drops the instance-clock-skew gate | `G1_NoDanglingPointer` | 10 |
| Migration | m5 | `Commit`/`Timeout`/`Cancel` drop the `src_snap` check, keep only owner | `G1_NoDanglingPointer` on the unpatched base (pre-existing, depth 13); **no violation** isolated on the fix (~1.7-2M states) | 13 / — |
| Migration | m_nolease | `G.10`'s owner-held-lease conjunct dropped | `G1_NoDanglingPointer` | 13 |
| Multipart | m1 | `lock_session_state`'s `aborted` guard removed | `M13_NoFinalizeAfterAbort` | 10 |
| Multipart | m2 | Embedded session-close CAS made owner-fenced too | `M7_AbortCompleteExclusive` | 13 |
| Multipart | m3 | `AcquireLease` takeover drops the `clock>=leaseUntil` guard | `M14_NoLiveLeaseSteal` | 4 |
| Multipart | m4 | Sweep drops `clock>=leaseUntil` for a `completing` session | `M5_SweepSafe` (two-state fix) | 4 |
| Multipart | m5 | Auto-bind CAS drops the `contentPtr=boundTarget[c]` comparison | `M12_NoStaleRebind` | 9 |
| Multipart (2-session) | t1 | Auto-bind CAS deleted — binds unconditionally | `M12_NoStaleRebind` | 7 |
| Multipart (2-session) | t2 | *(verification, not a break)*: snapshot `boundTarget` before `AcquireLease` | no violation (confirms the CAS-at-finalize-time, not the snapshot's age, is what's safe) | — |
| Multipart (2-session) | t3 | `clear_current`/`set_current` split into a separate transaction from the bind CAS | `M16_CurrentFlagConsistent` (new) | 4 |
| Multipart (2-session) | t4 (baseline) | Added faithful `DeleteFile` + `M17_NoResurrectionAfterDelete` | no violation (matches the real `lock_session_state`/`reclaimed_by_cleanup` guard) | — |
| Multipart (2-session) | t4mut | `DeleteFile`'s guard drops the `fileDeleted` check (hypothetical) | `M17_NoResurrectionAfterDelete` (new) | 5 |

## Model limitations

- **Upload `u2` (bind as a single atomic step) is a model limitation, not a
  finding**: the original, single-step `Bind` action produces the IDENTICAL
  reachable `(state, state')` relation as the real two-phase `ReadEtag` +
  `BindWithSaved` — proven, not just observed (both report exactly 818,435
  distinct states on the canonical config) — so NO invariant over `vars` can
  ever tell them apart. This is exactly why the model was revised to the
  genuine two-phase shape (`B.1` in states-upload.md); `I8_SavedBindRespectsCAS`
  only exists, and is only non-vacuous, because of that revision.
- **F3's two ways to be "technically right but not the finding"** (see
  **Findings**, F3): an `If-Match: *` trace and a file-name-reincarnation
  trace both make `I9_SavedDeleteRespectsCAS` (the *general* property) fail
  first, for reasons that are not F3 — true both before and after the fix
  (`"*"`/`FixDeleteIfMatchInTx`'s own `dStar[d]` disjunct deliberately skips
  the recheck, by design, matching `delete_file_inner`'s `None` meaning "no
  check"). `dStar`/`I9_SavedDeleteRespectsCAS_SpecificEtag` and `fileGen`/`dGen`
  (ghost variables added in an earlier phase) rule both out; see their own
  comments in `FileStorageUpload.tla`. `Files` being a small, *reused*
  symbolic-name pool (the real `file_id` is a `Uuid::now_v7()`, never reused)
  remains a deliberate simplification everywhere else in the model.
- **Migration's `genCounter`/`committedGens`/`heldGen` ghosts are
  unbounded in principle**: a migrator may retry forever after any
  outcome (`Start` is always re-enabled from idle), so the raw reachable
  state space is infinite. `MaxGen` (a `CONSTANT`, with `CONSTRAINT
  GenConstraint == genCounter <= MaxGen`) bounds it for model-checking —
  the same role `MaxTick`/`MaxVersion`/`MaxWrites` play for the other
  unbounded clocks/counters in this family of models.
- **Multipart's `NativeBackend=FALSE` path is a hypothetical, currently
  unreachable backend** (Discrepancy #1): no shipped backend
  (`S3Backend`/`InMemoryBackend`: native; `LocalFsBackend`: no override)
  ever takes it. The committed main/medium configs use `NativeBackend=TRUE`
  to describe the model as actually shipped; `FileStorageMultipart_M1.cfg`
  uses `FALSE` specifically because that is the only way #5103 reproduces in
  this model.
- **Operator precedence in primed formulas**: `=` binds tighter than `\/`, so
  `y' = y \/ x` parses as `(y' = y) \/ x` and leaves `y'` undefined whenever `x`
  holds ("variable not defined"). Such formulas are written with explicit
  parentheses, `y' = (y \/ x)`.
- Everything else each model does not cover is listed under that model's own
  "Not modelled" section above and in `states-*.md` — those are scope
  boundaries, not limitations of the technique.
