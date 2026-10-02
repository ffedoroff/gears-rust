# file-storage: multipart-upload protocol (initiate / part / report / complete / abort / sweep)

Source of truth: `gears/file-storage/file-storage/src/domain/multipart_service.rs`,
`domain/multipart.rs`, `infra/storage/store/versions.rs::finalize_multipart_version`,
`infra/storage/repo/multipart_repo.rs`, `domain/cleanup.rs`, `src/bin/sidecar.rs`,
`infra/backend/{mod.rs,s3.rs,in_memory.rs,local_fs.rs}`. Where the feature docs
(`docs/features/multipart-coordinator.md`) and the code disagree, the model follows
the code; every disagreement found is listed under "Discrepancies" below.

Two TLA+ modules: `FileStorageMultipart.tla` (one session; M.1–M.6, MS, all
of M1–M14) and `FileStorageMultipartTwoSessions.tla` (phase 3(c): two
independent sessions racing to auto-bind the same file — a minimal,
separate model, see its own header and the "Phase 3" section below).

One multipart session = one PG row `multipart_uploads` (state machine
`in_progress → completing → completed` or `→ aborted`, both terminal) plus its
`multipart_upload_part` rows (one per reported part) plus one pending
`file_versions` row (`status = pending`, becomes `available` on a successful
`complete`) plus a backend-side upload handle (native: an S3-style multipart
upload id; offset-object: a set of per-part objects `{backend_path}.part.{n}`).
Step prefixes: **M** (initiate / part upload / report_part / complete / abort /
auto-bind) and **MS** (sweep steps touching multipart sessions). Numbering
`M.1`, `M.1.2`, … mirrors the credstore sample's `states.md` convention.

## Fix status (2026-10-02)

M7 and M8's deep shape are now **fixed in code**; M8's shallow shape, M1
(#5103) and the standalone converge path's own behaviour are unchanged/still
open. M7: `MultipartRepo::finish_complete`'s embedded, owner-blind CAS
(`expected_owner = None`) now matches `state IN ('completing', 'in_progress')`,
not just `'completing'` -- closing the session even when an intervening
takeover's own failed attempt already released the lease back to
`in_progress` moments before this call's version CAS won. M8, deep shape:
(a) `MultipartService`'s complete path now best-effort deletes the backend
object when `finalize_multipart_version` rejects with "session is no longer
completing (aborted by cleanup)"; (b) the sweep's `delete_pending_version`
success path now ALSO best-effort deletes the version's backend object, on
top of the pre-existing `abort_multipart` call. The model gained two boolean
`CONSTANT`s, `FixCloseFromInProgress` (M7) and `FixDeleteAssembledObject`
(M8 deep) (TRUE = current code); `M8_DeepOrphan_NotReachable` was also
revised from a plain reachability witness (which a normal successful
completion also -- correctly -- trips forever) to the same "at rest"
antecedent `M8_NoPermanentOrphan` uses, scoped to just the deep conjunct, so
it can be asserted as a general invariant once the fix is enabled. A
by-hand proof (not just the model-checked result) that this fix fully
closes the deep shape, with no residual ordering gap, is in the top-level
README's findings section. `FileStorageMultipart.cfg`/`_medium.cfg` run
with both fixes TRUE and now include `M7_AbortCompleteExclusive`/
`M8_DeepOrphan_NotReachable` (exhaustive/no-error -- see the README's
results table). `FileStorageMultipart_M7.cfg`/`_M8_deep.cfg` set their
respective constant FALSE to keep reproducing the original bugs for
regression purposes. `FileStorageMultipart_M8_shallow.cfg`/`_M1.cfg` are
unaffected by either fix (both left TRUE there) and remain open issues.

## M.1 — `initiate_multipart_upload` (`POST /files/{id}/multipart`)

- **M.1.1** Authorize (`actions::WRITE`) before any multipart-specific work;
  policy gate (allowed MIME, effective max size against `declared_size`);
  quota preflight against `declared_size` (fail-closed).
- **M.1.2** `compute_plan(declared_size, preferred_part_size, backend_min)` —
  pure function, enforces `MAX_PART_COUNT` (10 000) by widening `part_size`
  or rejecting outright before allocating the parts `Vec`.
- **M.1.3** `insert_pending_version`: one INSERT, `file_versions` row
  `status = pending`, `backend_id`/`backend_path` fixed from
  `storage_layout::backend_path(file_id, version_id)`.
- **M.1.4** `backend.initiate_multipart(backend_path)` — native only (the
  service **requires** `backend.capabilities().multipart_native` and errors
  out before this step otherwise, see "Discrepancies" #1). Returns an opaque
  `backend_upload_handle` (S3 `UploadId`, or an in-memory counter).
- **M.1.5** `create_multipart_upload`: INSERT the session row,
  `state = in_progress`, `lease_owner/lease_until = NULL`,
  `expires_at = now + session_ttl_secs`. On failure, best-effort
  compensation: `backend.abort_multipart` + `delete_version` (pending row) —
  both best-effort; a failure here leaves an orphan the sweep (MS) later
  reclaims (M.1.5 residual).
- **M.1.6** Mint one signed per-part URL per planned part
  (`op = multipart_part`, carries `upload_id`, `part_number`, `offset`,
  **exact** `size`, `backend_handle`); return the plan. No DB write.

## M.2 — part upload (sidecar, `PUT .../multipart/{upload_id}/parts/{n}`)

Two write models, chosen by `backend.capabilities().multipart_native`
(`write_multipart_part`, `sidecar.rs`):

- **M.2.1 native**: `backend.upload_part_stream(path, backend_handle,
  part_number, offset, stream, len = claims.size)` — S3 `UploadPart`. The
  backend mints a **fresh per-part `ETag`** on every call for the same
  `part_number` (S3 versions a part by its latest `UploadPart`; an earlier
  part body is no longer retrievable once a later one for the same number
  lands) — a physical **last-write-wins mutable register per part**, keyed
  only by `(upload_id, part_number)`, independent of DB state.
- **M.2.2 offset-object (non-native)**: `backend.put_stream("{backend_path}.
  part.{n}", stream, max_size = claims.size)` — plain overwrite-allowed
  object write, also last-write-wins per `(path, part_number)` (not even
  namespaced by `upload_id`, since `backend_path` is derived from
  `(file_id, version_id)` alone — safe only because one version has at
  most one live session at a time).

Both paths are **idempotent per `(upload_id, part_number)`** by design
(resumable uploads) — a re-`PUT` of the same part with different bytes is
accepted and simply overwrites the physical register. Neither path is aware
of the session's DB state (`write_multipart_part` never reads
`multipart_uploads`); a stray physical write can land after `abort`/`complete`
with no rejection at the backend layer.

## M.3 — `report_part` (sidecar → control plane callback, token-authenticated)

- **M.3.1** Load session by `upload_id`; reject if `(file_id, version_id)`
  don't match the token's claims (anti-cross-session poisoning).
- **M.3.2** Fast-path state check (`session.state == InProgress`) against the
  **snapshot** read in M.3.1 — non-authoritative, a cheap early reject only.
- **M.3.3** Reject if the caller-supplied `size` ≠ `claims.multipart.size`
  (the server-minted, authoritative per-part size) — defends `complete`'s
  summed `total_size` against a forged report.
- **M.3.4** `upsert_multipart_part` — **the authoritative step**, one
  transaction: a dummy self-CAS `UPDATE … SET state='in_progress' WHERE
  upload_id=? AND state='in_progress'` (takes Postgres's row lock, serializing
  against a concurrent `abort`/`acquire_complete_lease` CAS on the *same* row)
  — only if that matches does the part row get
  `INSERT … ON CONFLICT (upload_id, part_number) DO UPDATE` with
  `(backend_etag, part_hash, size, uploaded_at)`. **Known gap (#5103,
  `FenceSamePart = FALSE` in the model):** the upsert has **no fencing**
  against the physical register's own value — two concurrent `report_part`
  calls for the **same** `(upload_id, part_number)` (two client retries that
  raced a concurrent re-`PUT` of the same part with different bytes, M.2) are
  applied **last-commit-wins** on the DB row, regardless of which physical
  write actually landed last at the backend (M.2). The DB row can therefore
  end up recording a `(backend_etag, part_hash)` pair that does **not**
  describe the bytes the backend currently holds for that part number.

## M.4 — `complete_multipart_upload` (`POST .../multipart/{upload_id}/complete`)

- **M.4.1** Load session; authorize; bind to the authorized `file_id`
  (foreign `upload_id` → "not found").
- **M.4.2** Idempotent replay: `state == Completed` → replay the persisted
  `complete_result` snapshot (checked **before** the `If-Match` precondition
  — a replay is the recorded outcome of a past action, not a new one).
- **M.4.3** `state == Aborted` → error, terminal.
- **M.4.4** Optional `If-Match` precondition against the file's current
  content ETag (only reached for a genuinely new attempt).
- **M.4.5** Fast, non-authoritative `expires_at` check against the snapshot.
- **M.4.6** `acquire_multipart_complete_lease` — **one conditional UPDATE**,
  the only authoritative gate: `in_progress → completing` (fresh) **or**
  `completing → completing` with a **new** `(lease_owner, lease_until)`
  (takeover) **iff** `lease_until < now`, both additionally fenced by
  `expires_at > now` evaluated against the live row (not the M.4.5 snapshot).
- **M.4.7** Lost the CAS → re-read fresh row: `Completed` → replay (even past
  `expires_at` — an idempotent replay never expires); `InProgress`/
  `Completing` with `expires_at ≤ now` → "expired" error; `Completing` (live
  lease held by someone else) → `202 Completing` (client polls); anything
  else (`Aborted`) → error.
- **M.4.8** Winner runs **detached** (`tokio::spawn`, survives a dropped
  client connection) — `assemble_and_finish`:
  - **M.4.8.1** Fast path: `get_version` already `Available` (a crashed
    completer's finalize transaction (M.4.8.8) committed but the session
    close lost the race, **or** an even-later takeover already finished) →
    skip straight to **converge** (replay + close session, M.4.8.10).
  - **M.4.8.2** `list_multipart_parts`; **missing-parts check** — any planned
    part number with no DB row → error (`409`, lists the missing numbers).
    This check only sees `multipart_upload_parts` **rows**, never the
    backend's physical registers — a physically-written-but-never-reported
    part (M.3's callback never arrived) is "missing" here regardless of what
    the backend holds.
  - **M.4.8.3** `Σ part.size == declared_size` (defence in depth; M.3.3
    already pins each part's size).
  - **M.4.8.4** Policy size check against the real assembled size.
  - **M.4.8.5** `backend.complete_multipart(path, handle, parts)` — the
    **physical assembly step**, a plain backend call with **no surrounding
    DB transaction**; `parts` carries `(part_number, offset, digest,
    backend_etag)` **from the DB rows** (M.3.4's possibly-stale snapshot),
    never a fresh read of the physical register.
    - **native (S3)**: `CompleteMultipartUpload` with the DB-recorded
      `ETag`s. S3 itself **validates** each given `ETag` against what it
      currently has stored for that `part_number`; a mismatch (the DB row is
      stale relative to a later physical overwrite, M.2/M.3's gap) makes the
      **whole call fail** (`InvalidPart`) — nothing is assembled, the version
      stays `pending`. Only on a match does the call succeed, and succeeding
      is only possible when the DB-recorded bytes and the physically-stored
      bytes for every part agree — S3's own per-part `ETag` is effectively a
      **fencing token** the control plane does not mint but gets for free.
    - **offset-object**: no concrete backend implements this today (see
      Discrepancy #1); if one did, per the trait's own contract it would
      have to build the manifest from the **DB-recorded** digests (never
      re-read the object) while physically concatenating **whatever the
      `.part.{n}` objects currently hold** — exactly the gap M.3.4 leaves
      open, with no S3-side check to catch it.
    - **Takeover recovery**: on a backend error, **only if** this completer
      took over a `completing` session, check `backend.stat(path)` — if the
      final object already exists (an earlier completer's own M.4.8.5 already
      consumed the handle), derive `(manifest, root)` **locally**,
      deterministically, from the same DB-recorded parts, without a second
      backend call (byte-identical to what the first completer would have
      computed). A non-takeover completer never performs this check and
      simply propagates the error.
  - **M.4.8.6** A one-part plan degenerates to `whole-sha256` (no manifest
    row); ≥ 2 parts keep `multipart-composite-sha256`.
  - **M.4.8.7** MIME-sniff the assembled bytes (`read_prefix`) and validate
    against `declared_mime` — **after** M.4.8.5, **before** M.4.8.8. A
    mismatch here leaves the already-physically-assembled backend object as
    an orphan with no finalize to follow (residual, picked up only by the
    generic sweep of the still-`pending` version once the session itself
    later expires — see MS.1/MS.2; the object's own backend bytes are not
    separately tracked, see Discrepancy #2 / M8).
  - **M.4.8.8** `finalize_multipart_version` — **one PG transaction**:
    1. `lock_session_state` (`SELECT … FOR UPDATE`) — **first statement**,
       deliberately before touching `file_versions`/`files`, so this
       transaction serializes against a concurrent sweep/abort CAS on the
       same session row instead of racing it. Reject (`conflict`, whole
       transaction rolls back) **only** if the locked state is `aborted`
       (or the row is missing) — `in_progress`/`completing`/`completed` all
       fall through unchanged (see the method's own extensive doc comment
       for why each of those is still correct to let through).
    2. `versions.finalize`: CAS `file_versions` `status = pending →
       available` (+ hash/mode/part_count/mime). **Not `updated`** (lost CAS:
       status was already `available`) → return early
       (`updated=false, session_completed=false`), no manifest, no bind, no
       session-close attempted in this transaction — the caller's own
       `!updated` branch handles it (M.4.8.9).
    3. Insert the manifest row (composite mode only) + the finalize audit row.
    4. **Auto-bind** (`auto_bind` sessions only): `files.bind_content_cas`
       (CAS `content_id: expected → version_id`, `expected` computed by the
       caller **before** this transaction — the file's content pointer
       observed at `If-Match` time if the caller supplied one, else `NULL`
       unconditionally, never a stale unconditional snapshot). On a win:
       `clear_current` + `set_current` (abort the whole transaction, "target
       version no longer exists", if a concurrent `delete_version` removed
       this exact version in between — can't happen for a version this same
       transaction just finalized, kept as defence in depth) +
       `mark_bound_on_finalize` + bind audit + file-event enqueue. A lost CAS
       is **not** an error: `bind_state = Conflict`, the upload itself still
       succeeds, a manual rebind needs no re-upload.
    5. `finish_complete(expected_owner = None)` — the **session-closing** CAS,
       `state = 'completing' → 'completed'`, **deliberately owner-blind**
       (fenced only by `state = 'completing'`, not by `lease_owner`): this
       call is made immediately after this **same** transaction's own
       just-won, owner-blind version CAS (step 2), which already proves
       unique, legitimate authorship of *this* completion regardless of
       which `lease_owner` the row currently shows — requiring a match here
       would re-strand a stale-but-correct completer whose lease a takeover
       already (harmlessly) overwrote. If the locked state at step 1 was
       `in_progress` (a later takeover's own failed attempt already released
       the lease back) this CAS's `state='completing'` condition can no
       longer match → `session_completed = false` even though the version
       **did** just become `Available` in this very transaction — the
       session row is left `in_progress` forever until a fresh `complete`
       call reaches M.4.8.1's fast path and closes it (M.4.8.10) — a
       transient, self-healing inconsistency, not data loss (see
       Discrepancy #3).
    6. If `session_completed`: insert the `MultipartComplete` audit row.
  - **M.4.8.9** `!updated` (lost the version CAS) →
    `converge_or_error_after_lost_finalize_cas`: re-read the version; if
    `Available` (someone else's finalize already won — expected, not an
    error) → converge (M.4.8.10); otherwise (the `pending` row is genuinely
    gone — a concurrent abort/sweep reclaimed it, or a stranger scenario) →
    hard error, "version row was removed before completion".
  - **M.4.8.10** **Converge**: rebuild the response from already-committed
    state (`replay_completed`) and close the session via the **standalone**
    `finish_session` → `Store::complete_multipart_upload` →
    `finish_complete(expected_owner = Some(lease_owner))` — **this** path
    **is** owner-fenced (`state='completing' AND lease_owner=lease_owner`,
    "DBS-05 hardening"). A lost CAS here is checked against the fresh state:
    `Completed` → converge silently (someone else's own finish already won);
    anything else → error.

## M.5 — `abort_multipart_upload` (`DELETE .../multipart/{upload_id}`, user-driven)

- Reject up front (service-layer snapshot check) unless `state ==
  InProgress`.
- **CAS-first**, `Store::abort_multipart_upload`, **one transaction**:
  `state: in_progress → aborted` (or, the same store method's second CAS
  branch, `completing → aborted` **iff** `lease_until < now` — reachable even
  from this "user" entry point if the snapshot read raced a lease expiry,
  harmless); on a win, **in the same transaction**,
  `delete_parts_for_upload` (removes every `multipart_upload_part` row —
  prevents the permanent-orphan-row hazard documented on `upsert_part`) +
  audit row. A **lost** CAS (concurrent `complete` or another `abort` already
  won) stops immediately — critically, **never** falls through to the
  backend/version cleanup below, because a concurrent `complete` may already
  be assembling from (or have already finished with) this exact handle/version.
- On a win: best-effort `backend.abort_multipart(path, handle)` (logged,
  ignored on failure — the backend-side handle/parts are then left for the
  backend's own GC, see Discrepancy #2); best-effort `delete_version`
  (unconditional variant — safe here since this version is never `is_current`
  while its session was still `in_progress`).

## M.6 — auto-bind at complete

Not a separate step — folded into M.4.8.8.4/5 above; listed separately only
because the task names it as its own named concern. Guarantee: `files.
content_id` is only ever set to this session's `version_id` in the **same**
transaction that just proved `file_versions.status` flipped to `available`
(step 2 → step 4 of M.4.8.8) — so a bound pointer never outlives (points
past) the version becoming available, by construction (see invariant **M6**).

## MS — sweep steps touching multipart sessions (`CleanupEngine::run_sweep`, step 2)

- **MS.1** `list_expired_multipart_uploads`: selects sessions with
  `expires_at < now` **and** (`state = in_progress` **or** (`state =
  completing AND lease_until < now`)) — a **live** `completing` lease (even
  past the session's own `expires_at`) is never selected; a completer
  mid-assembly is never reaped out from under itself by the expiry check
  alone.
- **MS.2** `abort_expired_multipart_session`: wins the **same** CAS
  `Store::abort_multipart_upload` uses for M.5 (`in_progress → aborted`, with
  the `completing + lapsed-lease → aborted` fallback — this is in practice
  the **only** way a `completing` session with a dead completer ever gets
  reclaimed) — **before** touching anything else, for the same
  race-avoidance reason M.5 documents. A **lost** CAS (a concurrent
  `complete` won first) skips all cleanup below — the version may already be
  `Available`/bound, must not be touched. On a win: best-effort
  `backend.abort_multipart` (three-way fallback for `(backend_id,
  backend_path)`: the version row if still present → the session's own
  recorded `backend_id`/`backend_path` → the default backend + a recomputed
  path, legacy-session-only) + `delete_pending_version` (**status-guarded**:
  only removes the row if it is **still** `pending` — a version a racing
  `complete` already flipped to `available` is left untouched even if this
  sweep pass reached it a moment too late) + the zero-version orphan-file
  reclaim check (out of this model's scope).
- **MS.3** Part-row cleanup is **folded into MS.2's own CAS transaction**
  (`delete_parts_for_upload`, same call `Store::abort_multipart_upload`
  makes for M.5) — so **DB-row** orphans ("сироты частей") cannot survive a
  won abort CAS. **Not covered**, in either the user-driven or the sweep
  path: the backend-side physical registers (M.2's per-part writes, for an
  offset-object backend; or an already-**assembled final object** for a
  native backend whose `complete_multipart` physically succeeded — M.4.8.5 —
  before the session was concurrently reaped by MS.2, see Discrepancy #2 /
  invariant **M8**). Cross-backend orphan-blob reconciliation (`list_paths`)
  is explicitly deferred to P3 (`cleanup.rs` module doc) and provides no
  backstop here.

## Discrepancies found while modelling (code vs. apparent design intent)

1. **Offset-object multipart is unreachable in the current branch.**
   `initiate_multipart_upload` hard-rejects any backend with
   `capabilities().multipart_native == false`
   (`DomainError::multipart_not_supported`) **before** a session is ever
   created. The sidecar nonetheless carries a full parallel write path for
   it (`write_multipart_part_offset_object`, `sidecar.rs`), and the
   `StorageBackend` trait's `upload_part_stream`/`complete_multipart`/
   `abort_multipart` default implementations all return
   `multipart_not_supported` — no shipped backend (`S3Backend`,
   `InMemoryBackend`: `multipart_native = true`; `LocalFsBackend`: no
   override, defaults apply) ever exercises it. `NativeBackend = FALSE` in
   the model therefore represents a **hypothetical future backend**, not a
   reachable production configuration today — flagged here rather than
   silently assumed.
2. **No backend-side orphan reconciliation for an already-assembled
   object.** M.4.8.5 physically assembles the final object on the backend
   with **no surrounding DB transaction**. If the session is concurrently
   reaped (MS.2) or the completer's own later steps fail
   (M.4.8.7/M.4.8.8 rejecting), the **already-physically-assembled object**
   is never referenced by any `file_versions`/`multipart_uploads` row again
   and is not cleaned by anything in P2 scope (`cleanup.rs`'s own doc:
   cross-backend blob reconciliation is deferred to P3). This is a known,
   accepted residual (not unique to multipart — the single-part finalize
   path has the same class of gap), but multipart's **detached**, lease-
   timed completion widens the race window materially. See invariant **M8**
   and its counterexample below.
3. **A finalized-but-not-closed session can linger as `in_progress`
   indefinitely.** `finalize_multipart_version`'s session-closing CAS
   (M.4.8.8 step 5) can lose even on the **very same** transaction that just
   won the version CAS, if the locked `state` read back as `in_progress`
   (a concurrent takeover's own failed attempt released the lease a moment
   earlier). The caller's `assemble_and_finish_inner` then reports
   `session_completed = false` and calls the **owner-fenced** standalone
   `finish_session`, which **also** fails to close it (state isn't
   `completing`) — leaving `file_versions.status = available` (and possibly
   already bound) while `multipart_uploads.state` still reads `in_progress`,
   until some **later** `complete` call happens to land, hits the
   already-`Available` fast path (M.4.8.1), and finally closes the session.
   Not a correctness bug (no data is lost or duplicated — `completedCount`
   stays 1, see invariant **M2**) but worth a code comment cross-reference:
   this is exactly the scenario `versions.rs`'s own doc comment calls out as
   "left to the same fallthrough, out of scope for this fix" for the
   `f2_stale_completer_converges_instead_of_stranding_after_owner_fencing_fix`
   regression.

   **Found by the model, not anticipated above:** this stranded session is
   indistinguishable from a genuinely abandoned (or simply still-running)
   `in_progress` upload to **anyone** who reads `multipart_uploads.state` —
   its DB column really does read `in_progress`, and stays that way. That
   includes: (a) `list_expired_multipart_uploads` (MS.1), once `expires_at`
   passes, **and** — the shorter, model-confirmed path, needing no expiry at
   all — (b) **the user's own `DELETE .../multipart/{upload_id}` (M.5)**:
   its service-layer snapshot check (`if session.state != InProgress {
   return Err(..) }`) reads the true, current `in_progress` and passes, so
   the request reaches `Store::abort_multipart_upload` and the CAS
   `in_progress → aborted` wins (nothing about this session distinguishes it
   from a real candidate) — a client that simply got impatient and issued an
   explicit abort can reclaim a session whose content has *already* been
   assembled, finalized, and even **bound as the file's live content**.
   Either way, once the CAS wins: `backend.abort_multipart` is attempted
   best-effort against a handle that a successful `complete_multipart`
   (M.4.8.5) already consumed (a harmless no-op/error, swallowed), and
   `delete_pending_version` correctly matches zero rows (status-guarded, the
   version is already `available`) — so **no bytes, version or binding are
   destroyed**. But `multipart_uploads.state` is now permanently `aborted`
   while `file_versions.status = available` for the **same** `version_id`,
   possibly still the file's live bound content (`files.content_id`) — a
   session now terminally `aborted` whose own version is the file's current,
   served content. Nothing in the system ever reconciles this (M.4.8.1's
   "already Available" fast path is the only place that would have closed it
   correctly, and nothing reaches it once the row reads `aborted`). Purely an
   observability/audit-trail inconsistency (`GET .../multipart/{upload_id}`
   reports `aborted` for an upload whose content is actually live), never a
   data-integrity one — model trace: `PhysicalWrite`×3, `DeliverReport`×2
   (one **stale**, #5103), `AcquireLease(c2)`, `Tick` (lease expires),
   `AcquireLease(c1)` (**takeover**), `Assemble(c1)` (native etag check
   correctly **rejects** the still-stale part, lease released back to
   `in_progress`), `DeliverReport` (the missing fresh report finally lands),
   `Assemble(c2)` — note **`c2` no longer holds any lease at all**, yet
   nothing stops it from finishing its own, now-stale-but-still-in-flight
   attempt — `Finalize(c2)` (wins the version CAS; session stays
   `in_progress` since `state` wasn't `completing` at that instant; binds),
   `UserAbort` (wins, "in_progress" was true), `SweepCleanupBackend`
   (no-op, handle already consumed) — see
   invariant **M7**, whose counterexample is exactly this interleaving, not
   the (also real, see **M8**) "assembled-object-outlives-its-session" one.

## Model constants

- `Parts` — fixed 2-part plan (`p1, p2`).
- `Values` — the distinct byte contents a part can physically hold (`a, b`)
  — enough to detect a manifest/bytes mismatch (M1).
- `Completers` — 2 actors, modelling "several parallel/repeated `complete`
  calls, each with its own `lease_owner`" (fresh attempts, retries after a
  lost CAS, and a takeover of a crashed completer are all just a second
  `Completers` element reaching `AcquireLease` while the first is stuck).
- `FenceSamePart` (BOOLEAN) — `FALSE` reproduces the shipped code exactly
  (M.3.4's gap, #5103); `TRUE` is a hypothetical **partial** fix:
  `DeliverReport` additionally requires the report's `etag` still match the
  part's **current** physical register at the instant of delivery (a
  compare-and-swap on the physical write instead of last-commit-wins). The
  model runs below show this closes only the "two concurrent reports race
  for the same part" sub-case — it does **not** close the general gap, because
  a physical re-write whose own report is simply **dropped** (never
  delivered at all, e.g. the sidecar's callback retry budget is exhausted and
  the client does not retry) leaves the **earlier**, still-accepted report's
  value in `dbPart` with no later report ever arriving to supersede it. See
  the **M1** analysis below.
- `NativeBackend` (BOOLEAN) — `TRUE` models the shipped S3/in-memory
  backends (per-part `ETag` fencing at `complete_multipart` time, M.4.8.5);
  `FALSE` models the hypothetical, currently-unreachable offset-object path
  (Discrepancy #1): no cross-check between the DB-recorded digest and the
  physical register at assembly time.
- `SessionExpiresAt`, `LeaseDuration`, `MaxTick` — abstract clock bounds
  (`Tick` advances a shared integer clock; a session/lease is "expired" once
  the clock has reached its deadline).
- `MaxWrites` — bounds the total number of physical per-part writes across
  the whole run (keeps `pendingReports`/the physical-etag counter finite for
  TLC).

## Invariants (see `FileStorageMultipart.tla` for the exact TLA+)

- **M1_ManifestMatchesBytes** — once the version is `available`, the
  persisted manifest/root (recorded from the DB part rows at the moment
  M.4.8.5 ran) equals the bytes the backend physically assembled at that
  same moment. Violated whenever `NativeBackend = FALSE`, **regardless of
  `FenceSamePart`** (matrix below) — `FenceSamePart` only prevents a stale
  report from clobbering a fresher one when **both** reports are actually
  delivered; it does nothing for a part that is physically re-written
  (M.2, a legitimate resumable re-`PUT`) whose **own** report is then
  dropped (the sidecar's callback retry budget is exhausted, or the client
  simply never retries after a `502`) while an **earlier** write's report
  was already accepted — `dbPart` keeps the earlier, now-stale value
  forever, `missing_part_numbers` (M.4.8.2) is satisfied (a row exists for
  every part number — it just is not the *latest* one), and nothing at
  M.4.8.5 cross-checks it against the physical register. Only
  `NativeBackend = TRUE` saves it, and not through any report-side fencing:
  S3's own `CompleteMultipartUpload` validates **every** given `ETag`
  against what it currently holds for that `PartNumber` at assembly time
  (M.4.8.5) — the one place in the whole flow where a stale `dbPart` row is
  actually caught, and it is a property of the **backend**, not of
  `report_part`.
- **M2_SingleFinalize** — the version-row CAS (M.4.8.8 step 2) commits at
  most once across the whole run.
- **M3_LeaseSafety** — the **standalone**, owner-fenced session-close CAS
  (M.4.8.10 / `finish_complete(expected_owner = Some(...))`) only ever
  closes the session while that same completer still held the live lease at
  that instant. (Structural/regression invariant — see the mutation that
  falsifies it by making this CAS owner-blind too, mirroring the embedded
  one.)
- **M4_TerminalAbsorbing** — `completed`/`aborted` never change once reached.
- **M5_SweepSafe** — a session that is `completed`, or `completing` with a
  still-live lease, is never the target of a part-row wipe, a physical-
  register wipe, or a pending-version delete.
- **M6_NoDanglingAfterAutoBind** — whenever the file's content pointer names
  this session's version, that version is `available` **and** its backend
  object exists.
- **M7_AbortCompleteExclusive** — the backend-side best-effort discard
  (`backend.abort_multipart`, M.5/MS.2) and a `file_versions` row this
  session finalized being `available` never both happen. **Violated** — not
  by the "stale completer assembles, sweep reclaims" interleaving (there the
  version correctly stays `pending` forever, M8's concern, not M7's), but by
  the **Discrepancy #3** follow-on above: a session whose embedded finalize
  CAS won (`versionAvailable` becomes, and stays, `TRUE`) but whose own
  session-close CAS lost (left `multipart_uploads.state = in_progress`) is
  later picked up by MS.1/MS.2 **as if it were an ordinary abandoned
  upload** — its `state` column genuinely still reads `in_progress`, so the
  sweep's CAS matches, wins, and runs its best-effort backend discard,
  **while the version it is nominally discarding is already `available`**
  (data is not harmed — see the discrepancy note above for why — but the
  bookkeeping invariant this property states is still false at that point).
  **Repo-config note**: the phase-1 "Small, safe subset only" row below found
  NO violation for M7 at 2-completer scale — but that run used
  `NativeBackend = FALSE`. The committed `FileStorageMultipart.cfg` was
  later changed to `NativeBackend = TRUE` (to match the SHIPPED backends,
  Discrepancy #1 — `FALSE` models a hypothetical, currently-unreachable
  backend) to let `M1_ManifestMatchesBytes` hold; under `NativeBackend =
  TRUE`, M7 reproduces already at this SAME 2-completer small scale (the
  takeover-then-native-etag-fail-then-resume mechanism needs the native etag
  check — see "Shortest M7 trace" below, which already used `NativeBackend =
  TRUE`). So M7 is excluded from both the main and `_medium` repo configs
  regardless of scale; `FileStorageMultipart_M7.cfg` reproduces it
  (depth 15).
- **M8_NoPermanentOrphan** (at rest) — once a session has reached `aborted`
  **and** both of its own best-effort cleanup steps have run
  (`backendCleaned`, the M.5/MS.2 `backend.abort_multipart` attempt, and
  `pendingVersionDeleted`), no physical per-part register and no assembled
  backend object may still exist. **Violated**, two distinct ways:
  - **shallow** (any config): `backend.abort_multipart` is purely
    best-effort with **no retry** anywhere in the system — the model lets it
    simply fail (as the real code's `log + ignore` does), after which
    nothing ever attempts it again; the physical per-part register(s) stay
    forever. Partially mitigated **operationally** (not by this gear's own
    code) for a real S3-style backend by the bucket's own "abort incomplete
    multipart uploads after N days" lifecycle rule — not modelled here, and
    not available at all for a hypothetical offset-object backend with no
    such native lifecycle concept.
  - **deep** (Discrepancy #2): a completer that physically finished M.4.8.5
    (the final object now exists on the backend) is then overtaken by
    MS.1/MS.2 (lease expired, swept to `aborted`) **before** it reaches
    M.4.8.8 — the assembled object is left behind forever;
    `backend.abort_multipart`'s best-effort discard is a guaranteed no-op
    here (not just a possible failure) once the upload handle has already
    been **consumed** by a successful assembly, so this case has **no**
    operational mitigation at all (it is a real, finished object, not an
    "incomplete" multipart upload a lifecycle rule would ever match).

### Phase 2 additions (M9–M14)

Four new angles the coordinator asked for ((a)–(d)), plus two invariants
added *while* building the five mutations below, when the originally-planned
checks turned out not to be the right shape to catch them.

- **M9_ReplayMatchesStored** ((a) "a client that got 200/201 on `complete`
  sees the version `available` with the same hash/manifest it was given"):
  for every completer, if it ever reported success
  (`returnedAvailable[c]`), the manifest it reported equals the persisted
  `completedManifest` at every later instant (the ghost is never
  overwritten with a second, different value — `completedManifest` is
  itself set-once, by **M2**). Holds in the unmutated model (the only
  sources of a "success" report — the embedded finalize win M.4.8.8,
  the standalone converge M.4.8.10, and the direct replay M.4.2 — all copy
  the *same* `completedManifest`/`assembledManifest` value, never a second,
  independently-derived one).
- **M10_RepeatCompleteReplays** ((b) "a repeat `complete` after success
  replays, never `409`"): once `state = completed`, `ReplayCompleted(c)`
  (M.4.2's direct replay, no lease needed) is always `ENABLED`, for any
  completer not already mid-attempt. Holds structurally — M.4.2's replay is
  unconditional in the real code too (checked *before* the `If-Match`
  precondition, see M.4.2's own note).
- **M11_NoChangeAfterCompleted** ((c) "abort after complete does not change
  the available version/pointer"): once `state` first reaches `completed`,
  `completedManifest` and `versionAvailable` are frozen at that instant
  forever (a snapshot ghost, set once). Holds structurally in the unmutated
  model: `M4_TerminalAbsorbing` already keeps `completed` from ever
  transitioning again, and no action mutates `completedManifest` outside the
  single M2-guarded write.
- **M12_NoStaleRebind** ((d) "the file pointer never regresses to an older
  version because of a late completer"): our own auto-bind CAS
  (`contentPtr = boundTarget[c]`, M.4.8.8 step 4) never overwrites the
  pointer when that comparison does **not** hold. A ghost records whether a
  bind ever fired despite the mismatch; holds in the unmutated model by
  construction (the overwrite is gated by exactly that comparison) —
  **violated** by mutation **m5** (below), which deletes the comparison.
- **M13_NoFinalizeAfterAbort** (the complementary, *harder* direction of
  (c), found while designing the mutations, not originally planned): once
  `state = aborted`, **no later transition** may flip `versionAvailable`
  from `FALSE` to `TRUE` — a finalize must never succeed "underneath" a
  session the sweep (or the user) has already reclaimed. A two-state
  property, like **M4**. Holds in the unmutated model (Finalize's own
  `sessState = "aborted"` guard, M.4.8.8's `lock_session_state` check,
  rejects exactly this) — **violated** by mutation **m1** (below), which
  deletes that guard.
- **M14_NoLiveLeaseSteal** (found while designing mutation **m3**, not
  originally planned): `AcquireLease` never succeeds against a *different*
  owner's still-live lease — a completer that is actively, legitimately
  working can never be stolen from. Holds in the unmutated model (the
  takeover disjunct's own `clock >= leaseUntil` guard) — **violated** by
  mutation **m3** (below), which deletes that guard.

### A real gap found in M5 itself, while mutation-testing

The *original* `M5_SweepSafe` (phase 1) was a plain state invariant:
`(state = completed \/ (completing /\ clock < leaseUntil)) => (~partsWiped
/\ ~physWiped /\ ~pendingVersionDeleted)`. Mutation **m4** (sweep ignores
`lease_until` for a `completing` session) was expected to violate it
directly — it did not. **Root cause:** `SweepAbortExpired` flips
`sessState` to `"aborted"` in the *same* step that wipes `partsWiped`; by
the time TLC evaluates the invariant on the **post**-state, the antecedent
(`state = completing /\ clock < leaseUntil`) is already `FALSE` (state is
now `aborted`), so the very transition the invariant exists to forbid is
invisible to it — a plain state invariant cannot see a condition that only
held in the **pre**-state of the violating step. m4 was still caught, but
only *indirectly* and *downstream*, by **M7** at depth 13 — a much less
direct diagnosis than the bug deserves. **Fixed** by restating M5 as a
two-state property over the pre-state condition (mirroring M4/M13):
```
M5_SweepSafe ==
    [][ (sessState = "completed" \/ (sessState = "completing" /\ clock < leaseUntil))
          => /\ partsWiped' = partsWiped
             /\ physWiped' = physWiped
             /\ pendingVersionDeleted' = pendingVersionDeleted
      ]_vars
```
Re-verified: the unmutated model still satisfies the fixed M5 exhaustively
(small cfg, see the results table), and mutation m4 now violates it directly
at depth 4 instead of depth 13/15 via M7. **Lesson for future models in this
style:** any invariant whose antecedent names `sessState` (or another
variable a *single* action can also change) needs to be a two-state
property, not a plain state invariant, whenever the action that would
violate it is also the action that moves `sessState` out of the antecedent.
M7 and M3 happen to be safe as plain invariants only because, by
construction, nothing in this model ever changes `backendCleaned`/
`versionAvailable` (M7) or `standaloneClosedBy`/`standaloneClosedLeaseOwner`
(M3) *back out* of the condition that would flag them — M5 was the one
case where the antecedent itself was also the thing being overwritten.

## Witnesses (sanity checks the model must still be able to reach)

- `W1_NeverCompleting202` — a completer observing `state = completing` with
  a still-live lease (would answer `202`) is reachable.
- `W2_NeverTakeover` — a lease takeover (`AcquireLease` firing while
  `state = completing`) is reachable.
- `W3_NeverSweepReclaims` — `MS.1`/`MS.2`'s expired-session CAS actually
  firing is reachable.

## M — Model checking

TLC 2026.09.30 (the `tla2tools.jar` pinned for this task), `-workers 2`,
`-deadlock`, every run capped at `timeout 180` (none needed it except the one
noted). `FileStorageMultipart.cfg` (small): `Parts={p1,p2}`, `Values={a,b}`,
`Completers={c1,c2}`, `SessionExpiresAt=2`, `LeaseDuration=1`, `MaxTick=3`,
`MaxWrites=3`. `FileStorageMultipart_medium.cfg`: `Completers={c1,c2,c3}`,
`MaxTick=4`, `MaxWrites=4`, `NativeBackend=TRUE`. Witness/matrix runs use
scratch `.cfg` copies (same module) varying only `FenceSamePart`/
`NativeBackend`/the invariant list, per the task's rule against committing
throwaway configs.

| Run | Config | States gen. | Distinct | Depth | Time | Result |
|---|---|---|---|---|---|---|
| SANY | — | — | — | — | <1s | clean parse, no errors |
| Small, as shipped (`FenceSamePart=FALSE, NativeBackend=FALSE`) | `FileStorageMultipart.cfg` | 1 279 | 795 | 5 | <1s | **M8 violated** (shallow — best-effort backend-abort failure) |
| Small, safe subset only (`TypeOK, M2, M3, M5, M6, M7` + `M4`) | small, same constants | 1 985 235 | 537 708 | 19 | 14s | **exhaustive, no error** |
| M1 matrix, `FS=F, NB=F` | small, `INVARIANTS={M1}` | 74 938 | 33 534 | 9 | <1s | **M1 violated** (#5103, reported trace) |
| M1 matrix, `FS=F, NB=T` | small, `INVARIANTS={M1}` | 2 146 636 | 601 390 | 21 | 5s | **exhaustive, no error** |
| M1 matrix, `FS=T, NB=F` | small, `INVARIANTS={M1}` | 77 464 | 34 210 | 9 | <1s | **M1 violated** (dropped-report trace, see analysis) |
| M1 matrix, `FS=T, NB=T` | small, `INVARIANTS={M1}` | 2 007 900 | 559 518 | 21 | 4s | **exhaustive, no error** |
| M8 deep-orphan witness (`NativeBackend=TRUE`) | small variant, `INVARIANTS={M8_DeepOrphan_NotReachable}` | 302 875 | 117 116 | 11 | 1s | **violated** (assembled-object-outlives-session) |
| `W1_NeverCompleting202` | small, `NativeBackend=TRUE` | 12 | 12 | 3 | <1s | **violated** (reachable, as intended) |
| `W2_NeverTakeover` | small, `NativeBackend=TRUE` | 825 | 563 | 5 | <1s | **violated** (reachable, as intended) |
| `W3_NeverSweepReclaims` | small, `NativeBackend=TRUE` | 547 | 384 | 5 | <1s | **violated** (reachable, as intended) |
| Medium, as shipped (3 completers, `NativeBackend=TRUE`) | `FileStorageMultipart_medium.cfg` | 1 580 | 1 007 | 5 | <1s | **M8 violated** (same shallow case, confirms it is not a small-scale artifact) |
| Medium, safe subset only | medium, same constants minus `M1`/`M8` | 12 165 299 | 4 207 408 | 15 | 1min 26s | **M7 violated** — new finding, see Discrepancy #3 follow-on above; not exhaustive (stopped at first violation, ~1.69M states still queued) |

Every violation above was traced by hand against the code (Discrepancies
1–3 and the M1/M7/M8 analyses above); none is a TLA+ artifact disconnected
from a real interleaving the Rust code actually allows — each trace cites
the exact guard (CAS condition, status check, `expected_owner`) in the real
source that lets the step fire.

### Phase 2 — new invariants, a minimal M7 trace, and mutations

Same rules/files, `-workers 3` (shared machine, two other agents running in
parallel), every run capped at `timeout 1800`, actual times well under that
in every case below. M9–M14 added (see above); `M5_SweepSafe` fixed from a
plain invariant to a two-state property (see the dedicated note above).

| Run | Config | States gen. | Distinct | Depth | Time | Result |
|---|---|---|---|---|---|---|
| Small, safe subset incl. M9–M14 (`TypeOK,M2,M3,M6,M7,M9,M10,M11,M12,M14`+`M4,M5,M13`) | small, `FS=F,NB=F`, 2 completers | 2 017 987 | 555 740 | 19 | 7s | **exhaustive, no error** |
| M13 alone, small | small, `FS=F,NB=F` | 2 017 987 | 555 740 | 19 | 3s | **exhaustive, no error** |
| M7 minimal-trace search | `Values={a}` (singleton!), 2 completers, `SessionExpiresAt=3,MaxTick=2,MaxWrites=3`, `INVARIANTS={M7}` | 181 156 | 61 030 | 15 | 1s | **violated**, same depth as the phase-1 medium find — see step-by-step trace below |
| Mutation **m1** (remove `aborted` check in `lock_session_state`/Finalize) | small, 2 completers, `NativeBackend=TRUE` | 150 966 | 63 614 | **10** | <1s | caught by **M13_NoFinalizeAfterAbort** |
| Mutation **m2** (embedded session-close CAS gets an owner check) | same | 817 301 | 277 212 | **13** | <1s | caught by **M7_AbortCompleteExclusive** |
| Mutation **m3** (`AcquireLease` takeover drops the `clock>=leaseUntil` guard) | same | 100 | 91 | **4** | <1s | caught by **M14_NoLiveLeaseSteal** (added for exactly this) |
| Mutation **m4** (sweep drops `clock>=leaseUntil` for `completing`) | same | 182 | 159 | **4** | <1s | caught by the **fixed M5_SweepSafe** directly (was depth 13/15 via M7 before the fix — see the note above) |
| Mutation **m5** (auto-bind CAS drops `contentPtr = boundTarget[c]`) | same | 82 413 | 37 026 | **9** | <1s | caught by **M12_NoStaleRebind** (added for exactly this) |

| **Long run**: 4 completers, `MaxTick=5`, `SYMMETRY Symm` (`Permutations(Completers)`), safe subset minus M7 (`TypeOK,M2,M3,M6,M9,M10,M11,M12,M14`) | `Parts={p1,p2}`, `Values={a,b}`, `MaxWrites=4`, `NativeBackend=TRUE` | 199 979 373 | 45 490 146 | 32 | 19min 37s | **exhaustive, no error** (coordinator's suggested scale-up, run to completion) |

All five mutations are caught — none revealed a permanently-uncaught hole,
but **m4** exposed a real weakness in the *original* M5 (a plain invariant
blind to same-step antecedent changes), fixed above and re-verified; **m3**
and **m5** needed two invariants (M14, M12) that phase 1 did not have,
added specifically for the two "(d)"-style angles the coordinator asked
for. See each mutation's own comment in the `.tla` (`MUTATION m1` … `m5`
tags) for the exact one-line (or few-line) diff from the real code's guard.

(A first attempt at the long run above *included* `M7` in the invariant
list by oversight — it immediately found the already-known, real M7 bug
again at depth 15, 1min 19s, confirming it is reachable at 4-completer
scale too and is not a 2-completer artifact, but it meant the other eight
invariants were never actually pushed to exhaustion. Re-run excluding M7,
as reported above, to get the real scale-up signal.)

#### Shortest M7 trace (coordinator request #2)

Minimal config found: `Parts={p1,p2}`, **`Values={a}`** (a single byte value
suffices — the race is about *which etag/version* of a part's bytes the DB
row names, not about distinguishing byte content), `Completers={c1,c2}`,
`FenceSamePart=FALSE`, `NativeBackend=TRUE`, `SessionExpiresAt=3`,
`LeaseDuration=1`, `MaxTick=2`, `MaxWrites=3`. TLC (breadth-first, so this
*is* the shortest) finds depth 15 — shrinking `Values` to a singleton did
not shorten it further than the phase-1 medium find; `LeaseDuration` cannot
go below 1, and the two-completer "steal, fail, let the original resume"
shape genuinely needs both actors (a single completer that fails and
retries closes the session normally — see the step-by-step reasoning
below). Full trace, who/what/which predicate:

1. **`PhysicalWrite(p1,a)`** → the sidecar's first `PUT` of part 1 lands;
   backend physical register `physPart[p1] = (a, etag=1)` (M.2).
2. **`PhysicalWrite(p1,a)`** → a **resumable re-`PUT`** of the *same* part 1
   (same bytes, a legitimate retry/resume) lands a second time:
   `physPart[p1] = (a, etag=2)` — the backend register is overwritten
   (M.2's own "last-write-wins mutable register" note).
3. **`PhysicalWrite(p2,a)`** → part 2's one and only `PUT`:
   `physPart[p2] = (a, etag=3)`.
4. **`DeliverReport(p1, a, etag=1)`** → `report_part` for part 1's **first**
   write is delivered (and accepted — `session.state = in_progress`, M.3.4's
   self-CAS): `dbPart[p1] = (a, etag=1)`. **This is now stale**: the
   physical register already moved on to `etag=2` in step 2, but nothing
   fences this report against that (#5103 — though here it matters only as
   set-up, not as the M7 bug itself).
5. **`DeliverReport(p2, a, etag=3)`** → part 2's report lands:
   `dbPart[p2] = (a, etag=3)`. Both parts now have *a* row
   (`missing_part_numbers`, M.4.8.2, is satisfied) — but part 1's is stale.
6. **`AcquireLease(c1)`** → `c1` calls `complete`; `acquire_multipart_complete_lease`
   wins the fresh-acquire branch (`WHERE state='in_progress' AND
   expires_at>now`): `state: in_progress → completing`, `lease_owner=c1`,
   `lease_until = now+1`.
7. **`Tick`** → the abstract clock advances; `now >= lease_until` for `c1`'s
   lease (it has "expired" — the model does not need `c1` to crash, only
   for enough wall-clock time to pass, e.g. a slow assembly elsewhere).
8. **`AcquireLease(c2)`** → `c2` calls `complete` too; the CAS's **takeover**
   branch wins this time (`WHERE state='completing' AND lease_until<now`):
   `lease_owner: c1 → c2`, a fresh `lease_until`. `c1`'s own in-process
   state (`pc[c1] = "assemble"`, i.e. its request handler is still sitting
   inside `assemble_and_finish_inner`, not crashed, just slow) is
   **untouched** — the DB row's lease fields are the only thing that moved.
9. **`Assemble(c2)`** → `c2`'s own `backend.complete_multipart` call:
   `missing_part_numbers` is empty (both parts have a row), so it proceeds
   to the native-backend etag check — **and loses**: `dbPart[p1].etag=1 ≠
   physPart[p1].etag=2` (S3's own `CompleteMultipartUpload` would reject
   this exact mismatch, "InvalidPart"). `c2`'s own code path (mirroring
   `assemble_and_finish_inner`'s real error-exit) releases the lease it just
   won, **scoped to its own ownership**: `state: completing → in_progress`,
   `lease_owner/lease_until` cleared. `pc[c2] → idle` (this attempt is done;
   a real client would see an error and could retry).
10. **`DeliverReport(p1, a, etag=2)`** → the **second**, correct report for
    part 1 finally arrives (a delayed/retried callback): `dbPart[p1] = (a,
    etag=2)` — now matches the physical register.
11. **`Assemble(c1)`** → `c1`'s *original*, still-in-flight request handler
    (parked at `pc[c1]="assemble"` since step 6, never crashed) finally
    reaches its own `backend.complete_multipart` call. It does **not**
    re-check who currently holds the lease (the real code doesn't either —
    see `assemble_and_finish_inner`'s own flow, M.4.8.5). The etag check now
    **passes** (`dbPart[p1].etag=2 = physPart[p1].etag=2`,
    `dbPart[p2].etag=3 = physPart[p2].etag=3`): the backend physically
    assembles the object. `backendObjectExists' = TRUE`,
    `assembledManifest' = (a, a)`.
12. **`Finalize(c1)`** → `finalize_multipart_version`'s one transaction:
    `lock_session_state` reads `state = "in_progress"` (not `"aborted"`, so
    the transaction is **not** rejected — see M.4.8.8 step 1's own doc: this
    exact state is "reachable in principle… left to the same fallthrough").
    `versions.finalize`'s CAS (`WHERE status='pending'`) **wins**:
    `versionAvailable' = TRUE`, `completedManifest' = (a,a)`. The auto-bind
    CAS (`contentPtr = boundTarget[c1]`, both still `"none"`) **also wins**:
    `contentPtr' = "this"`. The session-closing sub-CAS
    (`WHERE state='completing'`) **loses** — the predicate reads `state =
    "in_progress"`, not `"completing"` — so `sessState` is **left
    untouched**: still `"in_progress"`, even though the version is now
    genuinely `available` and bound. (This is exactly Discrepancy #3.)
13. **`UserAbort`** → a client (possibly the very same one that originally
    started this upload, now impatient) calls
    `DELETE /files/{id}/multipart/{upload_id}`. The service's own snapshot
    check (`if session.state != InProgress { reject }`) **passes** — the row
    genuinely, truthfully reads `in_progress`. `Store::abort_multipart_upload`'s
    CAS (`WHERE state='in_progress'`) **wins**: `state: in_progress →
    aborted`, `multipart_upload_part` rows deleted (MS.3).
14. **`SweepCleanupBackend`** → the best-effort `backend.abort_multipart`
    call runs against `session.backend_upload_handle` — but that handle was
    already **consumed** by step 11's successful `CompleteMultipartUpload`;
    the call is a guaranteed no-op/error on the real backend, logged and
    ignored. `backendCleaned' = TRUE`.

At this point `backendCleaned = TRUE` and `versionAvailable = TRUE`
simultaneously: **M7_AbortCompleteExclusive is violated.** The session row
reads `aborted`; `GET /files/{id}` would show this exact version as the
file's live, bound content. No bytes are lost (the real violation is purely
the session row's own bookkeeping disagreeing with reality) — see the
Discrepancy #3 follow-on above for the full consequence analysis.

### Phase 2 (long runs) — done, and what is left for phase 3

Done in phase 2 (see the table above): the `MaxWrites=4, Completers=
{c1..c4}, MaxTick=5` scale-up, `SYMMETRY Symm`, safe subset minus M7 —
**exhaustive, no error**, 45 490 146 distinct states, depth 32, 19min 37s,
`-workers 3`. This supersedes the phase-1 "suggested" version of this
config below (now historical: it had asked for `MaxWrites=5`, both
`NativeBackend` values, and `M5`/`M7` folded into the plain invariant list —
superseded by M5's two-state fix and by running M7 separately, since a
plain-invariant M7 in the mix stops the search at the first, already-known
violation instead of pushing the *other* eight invariants to exhaustion).
`NativeBackend=FALSE` was not re-run at this scale: `NativeBackend` only
gates one guard inside `Assemble` (the native etag check) and does not
change the logic of M2/M3/M6/M9–M12/M14 at all, so a FALSE-side long run at
this scale is low-value; it remains a cheap option for phase 3 if ever
wanted.

Still open for phase 3:

- **3-part plan (`Parts={p1,p2,p3}`), `Completers={c1,c2}`, `MaxWrites=4`**,
  safe-subset invariants (minus M1/M7/M8, the three with an already-known
  violation): checks the missing-parts logic (M.4.8.2) and the
  takeover/converge machinery scale past 2 parts without a new failure mode;
  expect a notably larger state space (one more part roughly squares the
  `dbPart`/`physPart` product) — budget `timeout 1800`, `-workers 3`+.
- **`Values={a,b,c}`** (3 distinct byte contents instead of 2): widens the
  #5103 manifest-mismatch search (more distinguishable stale/fresh
  combinations) without changing the qualitative result already established
  by the small-cfg matrix; mainly useful as an exhaustiveness sanity check
  at larger `MaxWrites` (≥4) — budget `timeout 900` (15 min).
- **M7 and M8 at the 4-completer/`MaxTick=5` scale, each run alone** (not
  mixed with the other eight invariants): confirm the *shortest* trace for
  each stays the same depth found at small/medium scale (15 for M7, 5/11 for
  M8's shallow/deep cases) rather than only ever being reached via some
  longer, scale-dependent path — a quick sanity check, `timeout 300`.
- **`SYMMETRY` extended to `Parts` too** (a combined permutation group over
  `Completers × Parts`) for the 3-part run above, if it does not finish
  within budget without it — `Symm` in the current model only covers
  `Completers`.

## Phase 3 — wider coverage, deeper scale, two sessions, orphan classification

Same rules/files, `-workers 3`, every run capped at `timeout 1800`. New file:
`FileStorageMultipartTwoSessions.tla` + `.cfg` (task 1c; see its own module
header for why it is a **separate, minimal** model rather than a mechanical
duplication of the full per-part machinery).

### 1(a)/(b) — 3-part plan, 3 completers, exhaustive

`Parts={p1,p2,p3}` (up from 2), `Completers={c1,c2,c3}`, `Values={a,b}`,
`MaxWrites=4`, `SessionExpiresAt=2`, `LeaseDuration=1`, `MaxTick=3`,
`SYMMETRY Symm`.

| Run | Invariants | States gen. | Distinct | Depth | Time | Result |
|---|---|---|---|---|---|---|
| (a) `NativeBackend=TRUE` | `TypeOK,M1,M2,M3,M6,M9,M10,M11,M12,M14`+`M4,M5,M13` | 30 412 217 | 8 228 462 | 25 | 1min 54s | **exhaustive, no error** (M1 included and holds — native etag check still saves it at 3-part scale) |
| (b) `NativeBackend=FALSE, FenceSamePart=FALSE` | same minus `M1` | 28 044 165 | 7 411 818 | 21 | 1min 46s | **exhaustive, no error** (M1 excluded — still expected to violate, as at 2-part scale; not re-run here, no new information in doing so) |

No new failure mode past 2 parts: the missing-parts diff (M.4.8.2), the
takeover/converge machinery, and the lease/abort/sweep races all scale
cleanly to a 3-part plan.

### 1(c) — two independent sessions on one file, racing to auto-bind

`FileStorageMultipartTwoSessions.tla`/`.cfg`: `Sessions={s1,s2}`,
`Completers={c1,c2}`, `SessionExpiresAt=2`, `LeaseDuration=1`, `MaxTick=3`
(plus a scaled re-run with `Completers={c1,c2,c3}`, `SessionExpiresAt=3`,
`MaxTick=4`). Checked: `M6_NoDanglingAfterAutoBind` (generalized: the shared
pointer, whenever it names a session, names one that is genuinely
`available` with an existing object), `M15_PointerAlwaysValidWinner` (the
coordinator's exact phrasing, existentially — logically the same fact as
M6, kept as its own name for direct traceability), `M12_NoStaleRebind`
(generalized: no session's auto-bind CAS ever overwrites the shared pointer
despite a mismatch — "the winner matches the CAS"), `M2`, `M4`, `TypeOK`.

| Run | States gen. | Distinct | Depth | Time | Result |
|---|---|---|---|---|---|
| Small (`Completers={c1,c2}`) | 13 570 | 5 020 | 16 | <1s | **exhaustive, no error** |
| Scaled (`Completers={c1,c2,c3}`, `MaxTick=4`) | 367 217 | 111 599 | 23 | 1s | **exhaustive, no error** |

**No dangling/stale pointer across two competing sessions, in either run.**
The auto-bind CAS (`contentPtr = boundTarget[sess][c]`, read and written
against the ONE shared `contentPtr`) is exactly what keeps this safe: a
completer from session `s1` that reaches `Finalize` with a stale
`boundTarget` (observed before `s2`'s own bind already won) simply loses its
bind attempt (`Conflict` — `contentPtr` is left alone) while still
correctly finalizing its OWN version (`versionAvailable[s1]` still flips
`TRUE` — the upload itself never fails just because the bind lost, exactly
matching `BindState::Conflict`'s real contract). Both sessions can reach
`available` independently; only one can ever hold `contentPtr` at a time,
and it is always the one whose CAS actually matched. This is a genuine,
if structurally expected, confirmation: the *single*-session model already
established that this same CAS is airtight against a *stale same-session*
completer (M12); this run adds the confirmation that it is equally airtight
against a *second, independent, concurrent upload* targeting the same file
— nothing about the single shared `contentPtr` resource lets two sessions
corrupt each other's view of it.

### 2 — statistical simulation at a scale too large to finish exhaustively

`-simulate -depth 150`, `Parts={p1,p2,p3}`, `Completers={c1,c2,c3,c4}`,
`Values={a,b}`, `NativeBackend=TRUE`, `FenceSamePart=FALSE`,
`SessionExpiresAt=5`, `LeaseDuration=1`, `MaxTick=8`, `MaxWrites=6`,
invariants `TypeOK,M1,M2,M3,M6,M9,M10,M11,M12,M14`+`M4,M5,M13` (M7/M8
excluded — known violations, not useful noise for a random walk), budget
`timeout 1700` (~28 min), `-workers 3`.

Ran the full `timeout 1700` budget (the `-simulate` mode has no natural end
of its own; `timeout` is what stops it). **No violation found**: 28 465 725
random traces generated, 613 457 058 states checked in total (mean trace
length 16, truncated at the `-depth 150` cap only by the time budget, never
by actually reaching depth 150 — the model's own terminal/idle states end a
trace long before that). This is a strong (though, unlike the exhaustive
runs above, not a *proof* of) confirmation that `M1/M2/M3/M6/M9/M10/M11/
M12/M14` (+`M4/M5/M13`) hold at a scale (4 completers, 3 parts, `MaxTick=8`)
too large to finish exhaustively within this budget — consistent with every
exhaustive result at smaller scale finding no violation of these same
invariants either.

### 3 — M8 orphan classification: all mechanisms, proven exhaustive

**Repo-config note**: the finding configs promote the scratch helper
invariant this classification used (`M8_DeepOrphan_NotReachable ==
~backendObjectExists`) into the committed `FileStorageMultipart.tla`, right
after `M8_NoPermanentOrphan` — a plain search for `M8_NoPermanentOrphan`
always finds the shallower shape first (it's shallower), so isolating the
deep one needs this separate invariant; `FileStorageMultipart_M8_shallow.cfg`
/ `FileStorageMultipart_M8_deep.cfg` reproduce the two shapes independently.

Attempted `-continue` (keep searching past the first violation instead of
halting) on a small cfg with `INVARIANTS={M8_NoPermanentOrphan}` alone,
`-workers 1`. It printed exactly one counterexample in the time available
and did not finish exploring the (still fully exhaustive-BFS, just
non-halting) state graph within a short budget — `-continue` does not
append a short "here are N distinct shapes" summary, it just never stops on
the first one, so getting *several* printed traces this way would need
either a much longer run or a custom trace-diffing step outside TLC itself.
Rather than spend budget on that, the classification below is a **proof**,
not just an empirical sample — read directly off the model's own action
definitions, so it is exhaustive by construction rather than "exhaustive
within however long `-continue` happened to run."

**Claim: exactly two mechanisms are possible, and no third exists in this
model.** `M8_NoPermanentOrphan`'s violation condition is
`(sessState="aborted" ∧ backendCleaned ∧ pendingVersionDeleted) ∧
¬(¬backendObjectExists ∧ ∀p: physPart[p]=NoPart)`, i.e. (de Morgan) the
right conjunct reduces to `backendObjectExists ∨ (∃p: physPart[p]≠NoPart)`.
**`backendObjectExists ⟹ ∀p: physPart[p]≠NoPart` always holds** in this
model: `Assemble`'s only success branch requires `AllPartsReported` (every
`dbPart[p].val≠NoVal`); every `dbPart[p]` entry was itself written by
`DeliverReport` from a `pendingReports` element that `PhysicalWrite` created
*together with* setting that same `physPart[p]` to a non-`NoPart` value;
and nothing clears `physPart` before `Assemble` can run (`UserAbort`/
`SweepAbortExpired` only ever clear `dbPart`, and `SweepCleanupBackend` --
the only action that touches `physPart` -- cannot fire before `sessState`
reaches `aborted`, which itself cannot happen before `Assemble` has already
either succeeded or not been attempted). So the violation condition
collapses to a **plain case split on one boolean**, `backendObjectExists`,
and that split is exhaustive by definition — there is no state satisfying
neither branch and no state satisfying some third thing:

- **Shape 1 — "shallow" (`backendObjectExists=FALSE`, some `physPart[p]≠NoPart`).**
  The session was reclaimed (user abort or sweep) before any completer ever
  successfully assembled anything; `dbPart` is wiped (MS.3, part-row
  cleanup), but the sidecar's own physical per-part write(s) (M.2) are left
  for `SweepCleanupBackend`'s best-effort `backend.abort_multipart`
  (M.5/MS.2) — which, in the model, **may or may not** succeed, exactly
  mirroring the real code's `log + ignore` on a failed backend call with
  **no retry anywhere in the system**. Witness: small cfg, depth 5-6 (see
  the Phase 1 results table, "M8 violated (shallow)"). **Can the sweep ever
  reclaim it?** *Sometimes* — if the best-effort `backend.abort_multipart`
  call happens to succeed, this specific case self-heals; if it fails even
  once, nothing ever retries, so it becomes permanent. Partially mitigated
  *operationally* (not by this gear) by a real S3 bucket's own "abort
  incomplete multipart uploads after N days" lifecycle rule.
- **Shape 2 — "deep" (`backendObjectExists=TRUE`, hence `physPart`
  non-empty too, structurally, as shown above).** A completer's own
  `backend.complete_multipart` call (M.4.8.5) already physically succeeded
  — the final object genuinely, completely exists on the backend — but
  the session is reclaimed (sweep *or* a user's own `DELETE`, see
  Discrepancy #3) before that completer's `finalize_multipart_version`
  transaction (M.4.8.8) ever commits, whether because that transaction
  actually runs and is rejected by the (correct!) `sessState = "aborted"`
  guard, or because the completer's process simply never reaches it at all
  (crashed, or just very slow — the model's `CrashCompleter`/an
  indefinitely-delayed `Finalize` are indistinguishable in their effect on
  this invariant, since the reject branch is a no-op either way). Witness:
  small cfg, depth 11 (Phase 1, `M8_DeepOrphan_NotReachable`). **Can the
  sweep ever reclaim it?** **Never** — `SweepCleanupBackend`'s own logic
  takes the `backendObjectExists=TRUE ⟹ no-op` branch *unconditionally*;
  there is no nondeterministic "maybe it succeeds" here, because the
  backend-side multipart *handle* really has been consumed by the
  successful assembly (calling `AbortMultipartUpload`/discarding it again
  is meaningless on a real backend once `CompleteMultipartUpload` already
  ran) — there is no code path anywhere that would ever target the
  *finished object itself* for cleanup. This is the more serious of the two:
  not probabilistic, not mitigated by any provider-side lifecycle rule (it
  is a real, complete object, not an "incomplete" multipart upload such a
  rule would ever match) — see Discrepancy #2.

**What is explicitly out of `M8`'s scope, and why that is the right scope:**
a lingering `pendingReports` entry (an HTTP callback that was never
delivered) is not counted as an "orphan" by `M8` — it names no backend
resource and no storage cost; it is a dropped network call, already covered
separately by the #5103 analysis (M1), not a leak this invariant is about.
`dbPart` itself is always wiped by the same transaction that wipes
`partsWiped` (MS.3's part-row delete), so it can never be the *cause* of an
M8 violation on its own.

## Phase 4 — mutations on the two-session model; a wider-parameter simulation

Same rules/files, `-workers 3` (small mutation runs used `-workers 1`,
state spaces are tiny), `timeout 1800` cap. All four mutations are
**copies of `FileStorageMultipartTwoSessions.tla` in scratchpad**
(`TwoSessions_t1..t4.tla`, plus `TwoSessions_t4mut.tla`), never touching the
committed model.

### Code verification for t2 (before modelling it)

Confirmed (dedicated read of `multipart_service.rs`): `complete_multipart_
upload` reads `let file = self.store.require_file(...)` as its **first**
statement — strictly before authorization, the session load, the `If-Match`
precondition check, the expiry check, and the lease CAS. The detached task
later computes `auto_bind_target` from **this same, already-old** `file.
content_id` snapshot, never a fresh read. So the real staleness window
between "expected pointer observed" and "lease won" is at least as wide as
the whole rest of the request pipeline — wider than phase 3's model, which
captured `boundTarget` at the SAME instant as the lease CAS.

### Mutations/refinements → invariant, depth

| # | What changed | Caught by | Depth | Notes |
|---|---|---|---|---|
| t1 | Auto-bind CAS (`contentPtr = boundTarget[sess][c]`) deleted — binds unconditionally | **M12_NoStaleRebind** | 7 | direct analogue of single-session m5 |
| t2 | *Not a "break it" mutation* — added a `ReadExpected(sess,c)` action that captures `boundTarget` BEFORE `AcquireLease` (matching the real code's actual timing above), instead of at the lease CAS | — | exhaustive, depth 20, **no violation** | confirms the CAS-at-finalize-time is what provides safety, not the snapshot's age — a wider staleness window changes how often a bind reports `Conflict`, never whether the protocol stays safe |
| t3 | `clear_current`+`set_current` (`isCurrent`) split into a separate action/transaction from `bind_content_cas` (`contentPtr`) — a NEW ghost `isCurrent[sess]` and invariant `M16_CurrentFlagConsistent` added for this | **M16_CurrentFlagConsistent** (new) | **4** | even the single-session, no-second-session trace already shows the window: `contentPtr=s1` committed, `isCurrent[s1]` still `FALSE` (pending) one step later |
| t4 (baseline) | Added `DeleteFile` (faithful: `~fileDeleted` guard on `AcquireLease`, `\/ fileDeleted` in `Finalize`'s reject branch) + `M17_NoResurrectionAfterDelete` | — | exhaustive, depth 17, **no violation** | the real code's `lock_session_state`/`reclaimed_by_cleanup` (`None ⟹ true`, from my code-research agent) already treats "row gone" exactly like "aborted" — modelled faithfully, holds |
| t4mut | From the t4 baseline, delete `\/ fileDeleted` from `Finalize`'s reject guard (reproducing a HYPOTHETICAL missing check) | **M17_NoResurrectionAfterDelete** (new) | **5** | see trace below — genuine resurrection, not just dangling |

All four are caught (t1/t3/t4mut directly; t2 is a verification, not a
break-it test, and correctly found nothing to break). t3 needed a **new**
invariant (`M16`); t4 needed a new action (`DeleteFile`) **and** a new
invariant (`M17`) built specifically for it, exactly as instructed
("иначе усиль").

#### t3 trace (depth 4) — why splitting the transaction is unsafe

1. `AcquireLease(s1,c1)` — `s1` acquires the lease.
2. `Finalize(s1,c1)` — wins the version CAS, wins the auto-bind CAS
   (`contentPtr' = s1`), sets `flagPending[s1]' = TRUE` — but (mutation t3)
   does **not** touch `isCurrent` in this same step; session `s1` closes to
   `completed`.

At this point `contentPtr = s1` but `isCurrent = [s1 ↦ FALSE, s2 ↦ FALSE]` —
**`M16_CurrentFlagConsistent` is already false**, one step after the bind,
before `UpdateCurrentFlag` ever gets a chance to run. This is the direct
TLA+ confirmation that `bind_content_cas` and `clear_current`/`set_current`
being two separate transactions creates a real, observable window where
`files.content_id` and `file_versions.is_current` disagree — exactly the
"dangling current" the task asked about. (The real code never has this
window: both run in `finalize_multipart_version`'s one transaction — see
`versions.rs`'s own doc comment on why the auto-bind CAS and its
`clear_current`/`set_current` must stay together.) A "double current" (two
sessions' flags both `TRUE`, or a STALE `flagPending` from an earlier bind
overwriting a later one's correct flag) is also reachable in principle —
e.g. `s1` binds (`flagPending[s1]=TRUE`), then `s2` legitimately re-binds
over it (`contentPtr: s1→s2`, `flagPending[s2]=TRUE`), and if `s1`'s
now-stale `UpdateCurrentFlag` finally fires *after* `s2`'s own — not run
separately here, since the simpler depth-4 trace above already answers the
question asked ("will it catch a dangling/double current") with a direct
yes.

#### t4mut trace (depth 5) — resurrecting a deleted file

1. `AcquireLease(s1,c1)` — `s1` acquires the lease; `boundTarget[s1][c1]`
   snapshots `contentPtr = "none"` (nothing bound yet).
2. `BecomeReady(s1)` (or already ready — order doesn't matter here).
3. `DeleteFile` — the file (and, `ON DELETE CASCADE`, `s1`'s own
   `multipart_uploads`/`file_versions` rows) is deleted:
   `fileDeleted' = TRUE`, `contentPtr' = "none"`, `versionAvailable[s1]' =
   FALSE`.
4. `Finalize(s1,c1)` — **mutation t4mut**: the reject guard only checks
   `sessState[s1] = "aborted"` (`FALSE` — `s1` was still `"completing"`),
   never `fileDeleted`. It proceeds: wins the version CAS
   (`versionAvailable[s1]' = TRUE` — **the deleted file's version is
   "available" again**), and wins the auto-bind CAS too — `contentPtr =
   "none" = boundTarget[s1][c1]` (both still `"none"`, the snapshot taken
   *before* the delete) — **`contentPtr' = s1`: the deleted file's content
   pointer is resurrected**, pointing at a version whose row no longer
   exists in the real schema.

`M17_NoResurrectionAfterDelete` is violated: `fileDeleted = TRUE` yet
`contentPtr = s1` and `versionAvailable[s1] = TRUE`. In the **real** code
this cannot happen — `lock_session_state` (first statement of
`finalize_multipart_version`) returns `None` once the row is gone (cascaded
away with the `files` row), and `reclaimed_by_cleanup = (None ⟹ true)`
rejects the whole transaction before the version CAS or the bind CAS ever
run — confirmed by direct code reading before building this mutation. The
mutation exists only to show the invariant is not vacuous; it is not a
reachable path in the shipped code.

### Phase 4, task 2 — simulation at wider parameters

`-simulate -depth 200`, base single-session model `FileStorageMultipart.tla`:
`Parts={p1,p2}`, **`Values={a,b,c}`**, `Completers={c1,c2,c3}`,
`FenceSamePart=FALSE`, `NativeBackend=FALSE`, `SessionExpiresAt=6`,
`LeaseDuration=1`, **`MaxTick=10`**, **`MaxWrites=6`** (≈3 retries/writes per
part — the coordinator's "3 Uploaders-retries per part" modelled as the
write budget, since `PhysicalWrite` already has no per-uploader identity,
see the module header), invariants `TypeOK,M2,M3,M6,M9,M10,M11,M12,M14`+
`M4,M5,M13` (M1/M7/M8 excluded — expected violations at `NativeBackend=
FALSE`, not useful simulation noise). Budget `timeout 1200` (~20 min),
`-workers 3`.

Ran the full 1200s budget. **No violation found**: 17 967 024 random traces
generated, 434 950 726 states checked (mean trace length 19). Consistent
with every exhaustive result at smaller scale and with phase 3's
`MaxTick=8` simulation — widening `Values` to 3 (more distinguishable
stale/fresh combinations for the #5103 angle, not exercised here since M1
is excluded), `MaxTick` to 10, and the write budget to ~3 retries/part finds
nothing new for `M2/M3/M6/M9/M10/M11/M12/M14`/`M4/M5/M13` at
`NativeBackend=FALSE`.

