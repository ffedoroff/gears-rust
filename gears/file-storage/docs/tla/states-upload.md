# FileStorageUpload: create → PUT → finalize → bind → delete → sweep → read protocol

Model of **one gear instance**, an unbounded-in-principle but TLC-bounded set of **files** (`Files`,
names reused across lifetimes — see note at the end) and a shared, never-reused pool of **version ids**
(`VerIds`). PostgreSQL's `files` row is `[ex, content]` (`content_id`, `NoVer` = `NULL`); `file_versions`
is `[owner, status]` per version id (`owner` = the owning file, or `NoFile` once the row is gone —
`status ∈ {pending, available}`); the backend is a map `blob: VerIds → bytes` keyed by a path that is
**deterministic in `(file_id, version_id)`** (`domain/storage_layout::backend_path`) — since a version id,
once minted, is never reused (mirrors `Uuid::now_v7()` never repeating and the backend path formula), the
model collapses the path key to the version id alone. `file_versions` also carries its own recorded
`verVal` (`hash_value`/`size`, written by `U.3.2`'s read-back and compared against by `U.3.3`'s
convergence check) — kept as a SEPARATE variable from `everVal`, a ghost, sticky record of "the one true
content of this version id, forever" (ADR-0003's "bytes never mutate in place"), used only for checking;
`verVal` only ever equals `blob`/`everVal` because `U.3.2`'s read-back verification enforces it (mutation
`u1` breaks exactly that link). Step ids below (`U.x`, `B.x`, `D.x`, `S.x`, `R.x`) refer to
`FileStorageUpload.tla`'s action comments.

## Fix status (2026-10-02)

Both F1 and F3 are now **fixed in code**. F1: the GET-claims gained
`content_sha256` (`infra/signed_url/mod.rs::Claims`), populated at
download-URL issuance from the version's own recorded hash whenever
`hash_mode` is whole-object SHA-256 (`domain/service/read_ops.rs`); the
sidecar's full (non-`Range`) download handler
(`bin/sidecar.rs::download_whole`) now verifies the live stream against it
end-to-end and aborts the response on a mismatch
(`infra/content/stream_verify::verify_whole_object_download_stream`). Range
reads and multipart-composite-hash versions are NOT covered (a partial
range, or a Merkle-style composite root, cannot be checked against a
whole-object digest) -- this model has no Range reads at all, so that carve-out
is not separately exercised here. F3: `delete_file`'s `If-Match` is now
re-checked a second time, inside `delete_file_inner`'s transaction, against
the row `lock_for_update` just locked (`Store::
delete_file_collecting_versions`) -- not just the earlier, pre-transaction
read. The model gained two boolean `CONSTANT`s, `FixDownloadHashCheck` (F1)
and `FixDeleteIfMatchInTx` (F3) (TRUE = current code);
`FileStorageUpload.cfg`/`_medium.cfg` run with both TRUE and now include
`I5_ReadExactOrMiss` and `I9_SavedDeleteRespectsCAS_SpecificEtag` (both
exhaustive/no-error at the small scale, no-error-within-budget at medium --
see the top-level README's results table). `FileStorageUpload_F1.cfg`/
`_F3.cfg` set their respective constant FALSE to keep reproducing the
original bugs for regression purposes. F2 (`I4_NoPermanentOrphan`, the P3
blob-reconciliation gap) is unaffected and remains open.

## U — Upload (create, idempotency, sidecar PUT, finalize)

- **U.1 Create a new file** (`FileService::create_file`, `domain/service/create.rs`; `Store::create_file_with_pending_version_and_event`,
  `infra/storage/store/files.rs`). **One transaction**: insert the `files` row (`content_id NULL`) +
  insert the first `file_versions` row (`status = pending`) + (if an `idempotency_key` was given) the
  idempotency ticket — all three or nothing. The signed `PUT` URL is minted **before** the transaction
  (pure CPU) and is not itself modelled (a terminal "done" the way `states.md`'s credstore sibling treats
  HTTP replies) — only the DB rows it is built from matter here.
  - **U.1.1** Fresh create: picks a file name not currently live (`ex[f] = FALSE`) and a version id never
    minted before (`v ∉ minted`), `auto_bind` chosen once at mint time and stuck to `v` (`verAutoBind[v]`,
    mirrors the token's `bind_on_finalize` claim, `claims.bind_on_finalize` — DESIGN §3.6 amendment); on
    `PresignAddVersion`/`U.4` auto-bind is always `FALSE` — `presign_version` never mints that claim.
  - **U.1.2** Idempotency replay (`FileService::replay_idempotency_key`): a second `create_file` with the
    **same key** that already has a live ticket (`idemFile[k] ≠ NoFile`) does **not** mint a new file or
    version — it re-targets the stored `(file, version)` pair and re-mints a URL for it (not modelled: the
    re-signing itself, only that it targets the SAME pending/available version, which a client can then
    `U.2`/`U.3` against again — this is how the model reaches "PUT retried via a fresh create_file replay"
    without a separate action). The real code additionally 409s a replay whose target version is no longer
    `pending` (`"idempotency key's target version is no longer pending"`) and a replay whose `auto_bind`
    doesn't match the stored one — **not modelled** (both are rejections with no state change; letting the
    model's replay re-target an `available` version too is a safe superset, matching the credstore sibling's
    "any writer may restart after any terminal step").
  - A key is bound to at most one file for its whole lifetime once set (`idemFile[k]` is write-once — I7).

- **U.2 Sidecar PUT** (`bin/sidecar.rs::upload` → `StorageBackend::publish_exclusive`,
  `infra/backend/{local_fs,in_memory,s3}.rs`). **Create-exclusive, backend-only** — the sidecar never
  touches the DB before writing bytes, so this action's only precondition is "a version id has been
  minted" (`U.2` therefore fires even for a version whose `files`/`file_versions` row was *already deleted*
  concurrently — the signed token is still valid and the backend doesn't know the row is gone; this is a
  genuine, documented residual, see `I4` below). `blob[v] = NoVal` → write succeeds, `blob[v] := val`,
  `everVal[v] := val` (first and only write, ever). `blob[v] ≠ NoVal` → **no-op**: the existing bytes are
  never overwritten (`PublishOutcome.created = false`); the attempting client still remembers its own `val`
  (`cval[w]`) to present to `U.3`, exactly like a losing racer's digest in `bin/sidecar.rs::upload`'s
  `!created` branch.

- **U.3 Finalize** (`FileService::finalize_upload` / `finalize_upload_by_token`, `domain/service/write.rs`;
  `Store::finalize_version`, `infra/storage/store/versions.rs`). One transaction: the version
  `pending → available` CAS, optionally followed — same transaction — by the auto-bind CAS
  (`Files::bind_content_cas` then `set_current`, `B.2` below).
  - **U.3.1 Row already gone** (`verOwner[v] = NoFile`): `require_file`/`get_version` return "not found" —
    rejection, no state change (`FinalizeNotFound` in the model).
  - **U.3.2 Still `pending`**: the control plane **trusts the sidecar's measured size/hash** (the callback
    is authenticated by the mandatory internal credential; the sidecar computed both while streaming the
    PUT) and does **not** read the object back. It only checks the object's stored length via the backend's
    metadata (`size`/`stat`) against the reported `size` and reads the bounded MIME-sniff prefix
    (`check_uploaded_object`). No object at all (`blob[v] = NoVal`, PUT never landed) → validation error,
    no-op; a stored length that disagrees with the reported size → validation error, no state change — the
    version stays `pending`. **The model is deliberately stricter than the implementation here**: it
    compares the caller's claim (`cval[w]`) with the stored bytes (`blob[v] ≠ cval[w]` — only reachable when
    this caller lost `U.2`'s race against a different writer → hash-mismatch, no state change; `blob[v] =
    cval[w]` → commit), i.e. it models a verifying finalize, whereas the implementation accepts any
    reported hash whose size matches. Commit: `verStatus[v] := available`, and the DB row's OWN recorded
    hash `verVal[v] := cval[w]` is persisted — a SEPARATE variable from the ghost `everVal[v]` (also set,
    earlier, at the original `U.2` write): `verVal` is what `file_versions.hash_value`/`size` actually
    holds, provably equal to `blob[v]` in the model only because the modelled check enforces it (mutation `u1`
    drops exactly this guard — see the report). If `verAutoBind[v]` and `content[f] = NoVer` at this
    instant → bind too (`B.2`); if something already bound `f` first (`content[f] ≠ NoVer`), the finalize
    still succeeds, the auto-bind CAS simply loses (`bind_state: conflict`, F9 in the concurrency doc) —
    never a finalize failure.
  - **U.3.3 Already `available`** (`finalize_upload_by_token`'s "idempotent PUT-retry convergence", F4 in
    `concurrency-and-failure-model.md`): no read-back — compare the caller's claim against the DB row's
    own recorded `verVal[v]` (`version.size`/`version.hash_value`, never a fresh read of the backend).
    Equal → converge (success reply, no further state change — in particular, auto-bind is **replayed
    from the persisted decision**, never re-derived, so this step does nothing to `content`). Different →
    hash mismatch, no-op.
  - There is no "ambiguous, might-or-might-not-have-committed" branch distinguishable from an ordinary CAS
    outcome here, unlike the credstore sibling: nothing in this protocol *reacts* to "I don't know if my
    write landed" by deleting anything (no `destroy`-on-loss). A response the client never saw is modelled
    simply as `U.5 Crash` after the transaction already ran — the next thing anyone does is `U.2`/`U.3`
    again (PUT replay converges per `U.3.3`), never a compensating delete. This is a structural difference
    from `CredStoreValueVersions.tla`'s model, not an oversight.

- **U.4 Presign an additional version on an existing file** (`FileService::presign_version`): same shape as
  `U.1.1` but requires `ex[f] = TRUE` and never sets `verAutoBind[v]`.

- **U.4' Stale token retry** (`StaleRetryPut` in the model; `bin/sidecar.rs::upload`, no code-side
  counterpart by that name — this is what the sidecar's complete lack of a DB check *allows*, not a
  function it calls). Any client may, from idle, re-present a PUT token for **any** version id ever
  minted — whether or not its `files`/`file_versions` row (or even its whole file) still exists — and
  proceed through `U.2`/`U.3` exactly as if it had just received that token from `U.1`/`U.4`. This is not
  a modelling shortcut: `bin/sidecar.rs::upload` authenticates purely from the token's own signature +
  `exp`, never re-checking the control plane's DB, so this is *exactly* what the real sidecar allows. See
  the report's finding F1 for the consequence (combined with `R.1`/`R.2`, this is what makes `I5` provably
  violable).

- **U.5 Crash**: any client mid-flow (`pc ≠ idle`) may abandon at any point — the version it was working on
  simply stays `pending` (possibly with real bytes already published by `U.2`) until a later retry
  (`U.4'`/a replay through the same idempotency key) or `S.1` sweeps it.

## B — Bind

- **B.1 Manual bind** (`FileService::bind` → `Store::bind_atomic_with_event` → `FileRepo::bind_content_cas` +
  `VersionRepo::{clear_current,set_current}`, `infra/storage/store/versions.rs`). One transaction, gated on
  the **content ETag** (`domain/etag.rs::content_etag` is a pure function of `(file_id, content_id)`, so the
  model uses `content[f]` itself as the token — no separate ETag variable is needed). `is_current` is **not**
  a separate model variable — the code's own invariant ("`files.content_id` and `file_versions.is_current`
  can never diverge", DESIGN §3.7) is enforced *structurally* by deriving "is `v` current" as `content[f] = v`
  everywhere.
  - **Phase-3 correction**: re-reading `write.rs::bind` + `FileRepo::bind_content_cas` shows
    `bind_atomic_with_event` is **always** called with `expected_content_id = file.content_id`, i.e. THIS
    SAME call's own fresh read, for **all three** If-Match modes — the precondition check (None/`*`/a
    specific etag) only gates whether the attempt is even made, never what the CAS itself compares
    against. So `None` (legal only when that fresh read is already `NULL`) and `*` (skips the match check)
    can never observe a value other than "right now" — **`BindFresh`** covers both in one action. Only a
    **specific, client-cached etag** can genuinely be stale across a real gap in time: **`ReadEtag`**
    (B.1a) snapshots `content[f]` into the client's held state; **`BindWithSaved`** (B.1b), arbitrarily
    later, presents it — any other action, including a competing bind or a delete, may run in between.
    `I8_SavedBindRespectsCAS` is the lost-update guarantee this closes: a `BindWithSaved` that actually
    changes `content[f]` must have found its saved value still live at that instant.
- **B.2 Auto-bind on finalize** (embedded in `U.3.2`, `Store::finalize_version`'s `auto_bind` branch): the
  same CAS, with `expected = NoVer` always (`content_id IS NULL`), run in the SAME transaction as the
  finalize. Modelled inline, not as a separate action, because the code runs it inline.
- **X-FS-Bound** (the sidecar's echoed response header: `true` / `conflict` / absent) is a reply value, not
  state — not modelled, same treatment as every other HTTP status in this family of models.

## D — Delete

- **D.1 Delete one version, or the whole file if it's the last one**
  (`FileService::delete_version` → `Store::delete_version_or_whole_file`,
  `infra/storage/store/versions.rs`). One transaction, decided **inside** the transaction against a fresh
  snapshot (the real code locks the `files` row first — race #10 in `concurrency-and-failure-model.md` —
  so a concurrent `U.1`/`U.4` version-insert can never be cascade-dropped unaccounted; the model gets the
  same effect for free since this and every other action are already atomic steps with no in-between state
  to race into). `v ∉ live(f)` (not a version of `f`, or `f` doesn't exist) → not-found, no-op. `live(f) =
  {v}` (only version) → **whole-file delete**: every version of `f` is dropped (`verOwner[u] := NoFile`
  for all `u` with `verOwner[u] = f`) with a best-effort, independently-nondeterministic blob delete per
  version (`FileService::best_effort_blob_delete` — logged, never failing the request), `ex[f] := FALSE`,
  `content[f] := NoVer`. `v` is `content[f]` (current) and not the last version → `IsCurrent` conflict,
  no-op ("bind another version first"). Otherwise → remove just `v`'s row + best-effort blob delete.
- **D.2 Delete the whole file, If-Match required** (`FileService::delete_file`, `domain/service/read_ops.rs`;
  `Store::delete_file_collecting_versions`). **Phase-3b correction** (the phase-3 revision of this entry was
  itself wrong — it modelled the comparison as atomic with the delete; it is not): `require_file` (D.2a,
  `CheckDelete`) runs **outside any transaction** and compares `etag_for(&file)` from that one read against
  the caller's header (`*` always passes; `None` never reaches the service). If it passes,
  `delete_file_inner` (D.2b, `DoDelete`) runs as a **separate, later** transaction: it locks the `files` row
  and deletes it **unconditionally** — it never re-reads or re-compares `content_id`/the etag. So **every**
  `delete_file` call, `*` included, has a genuine check-then-act gap between D.2a and D.2b in which anything
  — in particular a concurrent bind — may run; there is **no CAS** here, for any If-Match mode, to make any
  of it atomic. `dExpect` records what D.2a saw, read only by `I9_SavedDeleteRespectsCAS` to detect the lost
  update this gap allows — `DoDelete` itself never looks at it. **Confirmed violated as modelled — finding
  F3**, see below; `I9` holds once `DoDelete` re-reads and re-compares `content[f]` in the same step as the
  wipe (the fix — one extra conjunct, verified separately, see F3's entry).
- A version that is `pending` (never finalized) can be deleted exactly like an `available` one by both of
  the above — the code's `delete_version_or_whole_file`/`delete_file_collecting_versions` count **every**
  row in `file_versions` regardless of status, not just `available` ones.

## S — Cleanup sweep (`domain/cleanup.rs::CleanupEngine::run_sweep`)

Modelled as two always-enabled, parameterless-per-tick global actions — "any order, any time" per the
module's own doc comment ("one step's failure does not abort the rest", "cross-instance coordination is
deliberately absent... concurrent sweeps... produce at most one successful deletion per row"). Both are
gated on the abstract clock `tick` crossing a small bound, standing in for `orphan_grace_secs` / a
retention rule's `max_age_days` — real wall-clock durations, collapsed to `Tick` per the task's own
instruction.

- **S.1 Reclaim an abandoned pending version** (`sweep_abandoned_pending_page` →
  `delete_abandoned_pending_version` [status-guarded: only while still `pending`, race-safe against a
  concurrent `U.3`] → best-effort blob delete → `maybe_delete_orphaned_file` if that was the file's last
  version and `content[f] = NoVer`). Requires `verOwner[v] ≠ NoFile`, `verStatus[v] = pending`,
  `tick - verCreated[v] > PendingGrace`. Effect: `verOwner[v] := NoFile` + nondeterministic blob delete;
  if that leaves `f` with zero live versions and `content[f] = NoVer`, also `ex[f] := FALSE` (the orphan-file
  reclaim, same transaction-pair shape as `delete_orphan_file_with_event`'s re-verified guard).
- **S.2 Retention expiry** (`sweep_retention_expiry_page` → `expire_file` →
  `delete_file_with_event_collecting_versions`). Requires `ex[f] ∧ tick - createdTick[f] > RetentionGrace`.
  Unconditional (no `If-Match`, no CAS) whole-file wipe — same effect as `D.1`'s whole-file branch. The real
  rule bodies (age / inactivity / metadata-equals) are collapsed to one abstract age bound, since only the
  *mechanism* (an unconditional background whole-file delete, racing concurrent writers/readers the same way
  `D.2` does) matters for the invariants in scope; the policy-matching logic itself (`domain/policy.rs`) is
  out of scope.
- **Not modelled**: `sweep_versionless_files` (second phase of sweep step 1 — reclaims a `files` row that
  never got ANY version row at all; its only real trigger is the merged multipart create+plan path,
  `create_file_bare` + a failed/crashed `initiate_multipart_upload`, which this model does not have —
  `U.1` always inserts the file row and its first pending version in the SAME transaction, so this state is
  structurally unreachable here); the expired-multipart-session sweep phase (multipart is out of scope
  entirely); the idempotency-key-row sweep (`sweep_idempotency_page` — ages out `idemFile`/`idemAutoBind`
  tickets; omitted because nothing in the modelled invariants depends on a stale idempotency row ever being
  reclaimed — a key simply stays replayable forever in the model, a superset of the real TTL'd behaviour).

## R — Read (download URL + sidecar read; no `Range`, per the task)

- **R.1 Issue a download URL** (`FileService::download_url`, `domain/service/read_ops.rs`). Requires
  `ex[f]`; target is either `content[f]` (default, requires `content[f] ≠ NoVer`) or an explicitly named
  live version — either way the target must be `available` (`version.status != Available` →
  `conflict`/`version_not_found`, no ticket issued). Effect: the reader now holds `(f, v)`. Not modelled:
  the URL's own `exp` (§2.3's clock inventory) — an expired-but-otherwise-valid ticket cannot do anything a
  live one can't, in this model, since nothing downstream re-checks a wall-clock deadline; only a safety
  property is in scope, not the liveness of "the ticket is still usable".
- **R.2 Read via the sidecar** (`bin/sidecar.rs::download`). **The sidecar never calls back into the control
  plane or the DB at all** — it verifies the signed token's own fields and then does exactly
  `backend.stat(path)` / `get_stream(path)` (`infra/backend/*.rs`). So `R.2`'s only precondition is holding a
  ticket; it does **not** re-check that the version's row is still live. Effect: `ans[r] := blob[v]` if
  `blob[v] ≠ NoVal`, else `ans[r] := Miss` (`404`). This is exactly how a signed download URL can outlive
  the DB row it was issued for (the version/file was deleted, or swept, after `R.1` but before `R.2`) and
  still correctly serve the **same bytes it always would have** — never wrong ones, and a `Miss` only once
  the backend blob is actually gone (which, per `D`/`S`'s best-effort, nondeterministic blob deletes, may
  never actually happen — a documented, bounded residual, not a new finding; see `I4` below and
  `concurrency-and-failure-model.md`, "Backend blob-without-row reconciliation... is deferred to P3").

## Clock

- **Tick**: `tick < MaxTick ⟹ tick' = tick + 1`, otherwise unchanged. Stands in for wall-clock time against
  which `PendingGrace` (⇒ `orphan_grace_secs`) and `RetentionGrace` (⇒ a retention rule's age bound) are
  compared. No other clock (token `exp`, finalize grace, lease TTLs) is modelled — multipart and its leases
  are entirely out of scope, and the upload-token `exp` only ever turns a *would-have-succeeded* step into a
  rejected one with no state change, which the model already covers via plain nondeterministic choice not to
  take that step.

## I — Invariants

- **I1_NoDanglingContent** (`files.content_id` always resolves, to a version whose recorded hash matches
  its real bytes). `ex[f] ∧ content[f] ≠ NoVer ⟹ verOwner[content[f]] = f ∧ verStatus[content[f]] =
  available ∧ blob[content[f]] = verVal[content[f]] ≠ NoVal`.
- **I2_AvailableHasBlob**. `∀v: verOwner[v] ≠ NoFile ∧ verStatus[v] = available ⟹ blob[v] = verVal[v] ≠
  NoVal` (every `available` version's recorded hash really matches its bytes, right now, not just
  historically — exactly the guarantee `U.3.2`'s read-back exists to provide; mutation `u1` breaks it).
- **I3_BoundNotLost** (action property): whenever `content[f]` changes, it either clears (a delete ran) or
  moves to a version that is, in the **next** state, live and `available` under `f` — i.e. no step ever
  corrupts the pointer to something other than a legitimate `CAS`-approved target. Combined with `I1` this
  also shows a successfully-bound pointer is never silently reverted by anything other than another
  CAS-guarded bind or a delete.
- **I4_NoPermanentOrphan** (`Quiescent` state predicate: every client/reader idle, `tick = MaxTick`, so every
  grace window has elapsed and no sweep step can still be pending). **Expected to be violated** — see the
  report; it is the model-checked confirmation of the documented P2 gap ("Backend blob-without-row
  reconciliation... deferred to P3", `concurrency-and-failure-model.md` §5) rather than a new finding: a
  best-effort blob delete (`D`/`S`) is free to "fail" in the model, in which case nothing ever revisits that
  path, so `blob[v] ≠ NoVal ∧ verOwner[v] = NoFile` persists forever once reached.
- **I5_ReadExactOrMiss**. `∀r: ans[r] ∈ Values ⟹ ans[r] = everVal[rver[r]]` — a finished read never
  returns any value other than the one-true, ever-published content of the version id its ticket names
  (immutability of `blob`, `I6`, is what makes this provable at all). **Confirmed violated** — see the
  report: a stale-but-unexpired PUT token (`U.2`/`StaleRetryPut`, which exists precisely because
  `bin/sidecar.rs::upload` never re-checks the DB) can publish NEW bytes at a version id's path after
  that version's row **and** backend blob were both legitimately deleted, and a download ticket issued
  for that version **before** the delete (`R.1`) then observes those new bytes on its `R.2` read — never
  a `miss`, and not the original content either. Kept out of the main invariant list for the same reason
  as `I4` (a confirmed hit would otherwise stop TLC before it exhaustively checks `I1`/`I2`/`I3`/`I6`/`I7`)
  and checked instead via the witness config.
- **I6_AvailableImmutable** (action property, "bytes never mutate in place"). `∀v: blob[v] ≠ NoVal ∧
  blob'[v] ≠ NoVal ⟹ blob'[v] = blob[v]` — a blob transitions `NoVal → val` (first `U.2` write) or
  `val → NoVal` (a delete/sweep's best-effort removal) but never `val1 → val2`.
- **I7_IdempotencyNoDuplicate** (action property). `∀k: idemFile[k] ≠ NoFile ⟹ idemFile'[k] = idemFile[k]`
  — an idempotency key, once bound to a file, is bound to that same file forever (write-once), so it can
  never be replayed into minting a second file.
- **I8_SavedBindRespectsCAS** (phase 3, action property): a `BindWithSaved` that changes `content[cf[w]]`
  must find its saved `cv[w]` still equal to the live pointer at that instant — the lost-update guarantee
  that only exists to check once bind is modelled as genuinely two-phase (see `B.1`). Vacuous under the
  OLD single-step `Bind` (same reachable `(state, state')` relation with or without the CAS — see the
  report's analysis of mutation u2), which is exactly why this needed the phase-3 model revision.
- **I9_SavedDeleteRespectsCAS** — the analogous question for `DoDelete` (`D.2b`): did the live pointer still
  equal what `CheckDelete` (`D.2a`) saw, at the instant the wipe actually commits? **Confirmed violated as
  the model stands — finding F3** (below): `delete_file_inner` really never rechecks, so this is not a
  vacuous or hypothetical property. Kept out of the main invariant list for the same reason as `I4`/`I5`;
  holds once `DoDelete` re-reads and re-compares `content[f]` in the same step as the wipe (verified
  separately, small config, exhaustive, 2,482,706 states, no error).

### Witnesses (meant to fail — show the model isn't vacuous; see the report for the run table)

All three violated on the canonical small config (`Files={f1}`, `VerIds={v1,v2}`, `MaxTick=1`), confirming
the corresponding code path is actually reachable, not vacuously excluded by some other guard:

- **NeverBound** (`∀f: content[f] = NoVer`): violated at depth 5 — a bind (here, auto-bind on finalize)
  is reachable.
- **NeverMiss** (`∀r: ans[r] ≠ Miss`): violated at depth 7 — `R.2` returning `404` for a dangling ticket
  is reachable.
- **NeverIdemUsed** (`∀k: idemFile[k] = NoFile`): violated at depth 2 — `U.1` with an idempotency key is
  reachable (trivially, but confirms `useKey` branches are live).

### Mutations (each a standalone copy of the module, one guard removed; see the report for the full trace
of every catch and the one that provably cannot be caught)

Run on the canonical small config (`Files={f1}`, `VerIds={v1,v2}`, `MaxTick=1`), `TypeOK` + `I1` + `I2` as
`INVARIANTS`, `I3`/`I6`/`I7` as `PROPERTIES` (deliberately excluding `I5`, itself already known-violated in
the *unmutated* model via `U.4'`/`R`, which would otherwise make every mutation look "caught" by a
pre-existing, unrelated finding):

- **u1** finalize commits without read-back verification → caught by **I2_AvailableHasBlob** (depth 7).
- **u2** (original, single-step `Bind`) bind without the If-Match CAS → **not caught by any invariant over
  `vars`** — proven (not just observed) to produce the IDENTICAL reachable `(state, state')` relation as the
  unmutated spec: both runs report exactly 818,435 distinct states. This is exactly why the model was
  revised to a genuine two-phase `ReadEtag` + `BindWithSaved` (see `B.1`) — **u2b**, the same CAS removed
  from `BindWithSaved` specifically, **is** caught, by the new **I8_SavedBindRespectsCAS**, but only once
  the config has ≥ 2 `Clients` (depth 10; 1 client can never race its own held read). (The equivalent
  "remove the recheck from `DoDelete`" mutation for delete is no longer a mutation at all — that recheck
  does not exist in the real code, so it is what the BASE model already does; see finding **F3** below.)
- **u3** sweep reclaims a pending/available version with no age or status guard → caught by
  **I1_NoDanglingContent** (depth 6).
- **u4** delete-version with no current-version / row-lock guard → caught by **I1_NoDanglingContent**
  (depth 6).
- **u5** sidecar PUT overwrites in place instead of create-exclusive → caught by **I2_AvailableHasBlob**
  (depth 6).
- **u6** idempotency replay with no "target still pending" guard → **not caught by I1/I2/I3/I6/I7**; caught
  only by **I5_ReadExactOrMiss** (depth 9), and confirmed, in an isolated copy with `U.4'` additionally
  disabled, that `u6` ALONE (no `StaleRetryPut` available at all) still reaches the same `I5` violation —
  so this is a second, independent way to reach the same class of bug `U.4'`/finding F1 already documents,
  not a re-discovery artifact of leaving `StaleRetryPut` enabled.

### F3 — `delete_file`'s missing recheck loses a concurrent bind (confirmed, not an artifact)

**Mechanism.** `FileService::delete_file` reads the file and validates `If-Match` (`*`, or a specific etag
against `etag_for(&file)`) in step D.2a, **outside any transaction**. If it passes, `delete_file_inner` →
`Store::delete_file_collecting_versions` runs, **later**, as its own transaction (D.2b): it locks the
`files` row and deletes it **unconditionally** — `content_id` is never re-read or re-compared. So the
window between D.2a's read and D.2b's commit is a genuine check-then-act gap, for **every** `If-Match`
value including `*`, in which any other write — in particular a concurrent `bind` (manual or auto-bind on
finalize) — may land. The delete then destroys that bind's content too, even though the precondition the
deleting caller presented was checked against a file state that no longer existed by the time the delete
actually ran, and the deleting caller never saw (and never approved) what it ended up destroying. Neither
side gets an error: the delete's own precondition was genuinely satisfied at D.2a, and the bind genuinely
committed before D.2b — this is a silent lost update, not a conflict either party is told about.

**A first, depth-6 trace found is AMBIGUOUS, not the finding.** The shortest counterexample to the
general `I9_SavedDeleteRespectsCAS` starts from an empty, content-less file (`CheckDelete` records
`dExpect[d1] = NoVer`, a bind then lands, the wipe fires): this is indistinguishable from `If-Match: *`
("delete whatever is there right now"), which is correct client-requested behaviour, not a bug — a client
that asks to delete unconditionally gets exactly that. `dStar` (ghost, `TRUE` iff `CheckDelete` actually
took the `expected = Star` disjunct) and the restricted property `I9_SavedDeleteRespectsCAS_SpecificEtag`
(`FileStorageUpload_F3.cfg`) exist specifically to rule this reading out: the violation only counts when the
deleter's precondition named a **concrete, non-`*` etag** (`~dStar[d] ∧ dExpect[d] ≠ NoVer`) — i.e. the
client read a REAL bound version and the server told it "yes, that's still current" before the gap opened.

A second subtlety the depth-6 trace also hid: `Files` is a small, reused pool of symbolic names (unlike the
real `file_id`, a `Uuid::now_v7()` never reused). Without tracking incarnations, TLC's shortest path to
*any* `I9` violation exploits that simplification instead of the real race: delete file `f1` outright via
the unrelated, atomic `D.1`/`DeleteVersion` action (not `D.2`'s check-then-act pair) while `d1`'s `D.2a`
check is still parked `"ready"`, let `f1` be **recreated** under the same symbolic name, then let the stale
`DoDelete` fire against the new incarnation. The real `delete_file_inner`'s `DELETE ... WHERE file_id = :id`
can never do this (a recreated file gets a fresh, different id; the stale delete would match zero rows and
no-op) — so this path is a modelling artifact, not F3. `fileGen` (ghost, incremented every fresh
`CreateNewFile` for a given symbolic name) and `dGen` (the `fileGen` `CheckDelete` observed) close it:
`DoDelete` now wipes only `IF ex[f] /\ fileGen[f] = dGen[d]`, mirroring the real `file_id`-keyed DELETE's
"same row, or zero rows" dichotomy.

**Shortest genuine trace** (`I9_SavedDeleteRespectsCAS_SpecificEtag`, depth 10, `FileStorageUpload_F3.cfg`,
exhaustive witness run, 23,576 states generated / 7,830 distinct):
1. `CreateNewFile(c1)`: new file `f1`, auto-bind version `v1` minted `pending`.
2. `Put(c1)` + `Finalize(c1)`: `v1` → `available`; the embedded auto-bind (`B.2`) wins its CAS —
   `content[f1] := v1`. The file now has real, live content bound to a concrete version, `v1` (etag `E1`).
3. `PresignAddVersion(c1)` + `Put(c1)` + `Finalize(c1)`: a second version `v2` is minted on the SAME file,
   uploaded, and finalized to `available` (no auto-bind — `content[f1]` stays `v1`).
4. `CheckDelete(d1)`: a deleter's `DELETE /files/f1` with a concrete `If-Match: E1` passes D.2a — `content[f1]
   = v1` matches — `dPc[d1] := "ready"`, `dExpect[d1] := v1`, `dStar[d1] := FALSE` (not a wildcard),
   `dGen[d1] := fileGen[f1]` (same incarnation, recorded for the no-op-on-reincarnation guard).
5. `BindFresh(c1)`: a concurrent, perfectly legitimate manual bind (`If-Match: *` or a fresh read) retargets
   the file to the now-`available` `v2` — `content[f1] := v2`. Nothing about this bind is stale; it is a
   fresh CAS against the live pointer, and it succeeds.
6. `DoDelete(d1)`: the deleter's **already-authorized** delete fires, unconditionally — `fileGen[f1] =
   dGen[d1]` still (no reincarnation happened), so the guard does not save it: `ex[f1] := FALSE`, wiping `f1`,
   `v1` AND `v2` together. `I9_SavedDeleteRespectsCAS_SpecificEtag` fails: `dExpect[d1] = v1 ≠ content[f1] =
   v2` (the pre-wipe value) — a client holding a download link for `v1` (never touched) is unaffected, but
   the file's current, just-rebound content (`v2`) is destroyed by a DELETE whose own precondition was
   checked against `v1` and genuinely passed at the time, against a REAL etag, not a wildcard.

**Window and consequences.** The real-world window is `require_file`'s read-plus-etag-check in
`delete_file` up to `delete_file_inner`'s transaction actually opening — not bounded by any lock (nothing is
held between the two), so it widens under DB latency/contention rather than being a fixed handful of
instructions. Consequence: **data loss with no error surfaced to anyone** — a file that was just created and
had its first content successfully uploaded and bound can be destroyed by a concurrent `DELETE` whose own
precondition check legitimately ran against the pre-upload state. This generalizes beyond auto-bind: any
manual `bind` landing in this same window is equally destroyed. Severity is bounded by needing a genuine
race (a delete and a bind on the very same, very new file within a short real-world window) — more a data
integrity gap under concurrent client usage than an attacker-controlled exploit (contrast `F1`, which needs
a stale/replayed token).

**Fix verified**: move the etag comparison inside D.2b — re-read and re-compare `content[f]` in the SAME
step as the wipe (equivalent to `DELETE ... WHERE content_id = :expected` instead of an unconditional
`DELETE`, or re-checking right after `lock_for_update`). With that one-line change, `I9` holds — small
config, exhaustive, 2,482,706 states, 24 s, no error (scratchpad copy, not applied to the canonical model,
which must stay a faithful mirror of the CURRENT code).

### F1 candidate fixes (evaluated in scratchpad copies, not applied here)

F1 (see the report): a stale-but-unexpired PUT token (`U.4'`) can publish new bytes at a version's path
after its row **and** blob are deleted, and a download ticket issued before the delete (`R.1`) then serves
those new bytes instead of a `miss`. Three candidate fixes, each checked against `I5_ReadExactOrMiss` on the
canonical small config:

- **(a) sidecar asks the control plane "is this version still pending?" before `publish_exclusive`.**
  Modelled as a genuine two-step `PutCheck` (can abort if the row is already gone) → `PutWrite` (the actual
  write, run as a separate later step, so anything — including a delete — may run in between). **Does
  NOT close the window**: `I5` is still violated (depth ≈ same order as the base finding). An extra
  round-trip narrows the TOCTOU gap, it cannot collapse it to zero, because the write still isn't
  re-verified at the instant it actually happens.
- **(b) download verifies a hash carried in the claims.** Modelled by having `R.1` additionally snapshot
  `rExpect[r] := verVal[v]` (the DB's recorded hash at issuance) and `R.2` compare the live `blob` against
  it, answering `Miss` on any mismatch instead of serving it. **Holds I5** on the canonical small config
  (no violation found, same scale as the clean base runs) — this directly neutralizes F1's actual
  mechanism: a reused path's new bytes never match the ORIGINAL version's recorded hash, so the reader gets
  `Miss`, never wrong bytes.
- **(c) defer the blob delete until the max upload-token TTL has elapsed.** Modelled by gating every
  blob-clearing step (`WipeFile`, `D.1`'s single-version delete, `S.1`) on `tick - verCreated[v] >
  TokenTtl`, and bounding `U.4'` itself by the same `TokenTtl` (a real token has its own `exp`). **Does NOT
  close the window either, for a different reason than (a)**: a token verified (`pc[w] := "put"`) WHILE
  still inside `TokenTtl` can have its actual write land arbitrarily later — this model has no bound on how
  long a client may dwell in `"put"` before calling `Put`, and neither does the real sidecar (`exp` is
  checked "at request start... not re-checked mid-stream", `concurrency-and-failure-model.md` §2.1 S2 —
  a slow-but-live upload can legitimately finish after its own token's nominal `exp`, which is exactly why
  the real system has a SEPARATE `finalize_token_grace_secs` on top of `exp`). A correct version of fix (c)
  would need to defer clearing until `TokenTtl` **plus** that grace period, not `TokenTtl` alone — deferring
  by `TokenTtl` only moves the race, it doesn't remove it.
- **Net recommendation**: (b) is the only one of the three that is a complete fix on its own (it attacks
  F1's actual observable symptom — wrong bytes served — directly, independent of timing assumptions). (a)
  and (c) each narrow the real window but remain races in principle; combining (c) with the correct grace
  period, or combining (a)+(c), narrows it further but (b) is the only one proven closed here.

## Not modelled (whole features, not individual branches — branch-level omissions are called out inline above)

- **Multipart upload** entirely (`domain/multipart.rs`, `multipart_service.rs`, sessions, leases, parts,
  `complete`/`abort`) — a separate state machine the task scopes out; `create_file_bare` +
  `compensate_failed_multipart_initiate` and the `sweep_versionless_files` phase that is its backstop are
  therefore also out (see `S`'s "not modelled" note).
- **Metadata patch** (`update_metadata`, `PATCH /files/{id}`) — structurally never touches `content`/`blob`
  (same "no store call" argument as the credstore sibling's `I5`), so it cannot affect any invariant here.
  Checked for F3's class of bug anyway (phase-3b): `update_metadata` → `Store::patch_metadata_atomic` →
  `FileRepo::touch_meta` does `UPDATE files SET meta_version = meta_version + 1, ... WHERE file_id = :id
  [AND meta_version = :expected]` as ONE statement inside ONE transaction — a genuine in-transaction CAS on
  `If-Match-Metadata`, not `delete_file`'s read-outside-transaction-then-unconditional-act shape. `bind`
  (`FileRepo::bind_content_cas`) is the same: a single `UPDATE ... WHERE content_id = :expected` inside the
  bind transaction (confirmed phase-3). So `delete_file` is the ONLY If-Match-bearing write in this gear
  with F3's shape; `bind` and `update_metadata` are real, atomic CASes and do not need (and do not get) the
  two-phase treatment `delete_file` needs.
- **Ownership transfer** (`transfer_ownership`) — touches `owner_id`/`owner_kind` only, neither of which
  this model tracks (no policy/quota/authorization is modelled at all: `PDP`, `PolicyResolver`, quota
  checks are all orthogonal gates that only ever turn a would-be action into an upfront rejection with no
  state change — the model already covers that by simply not always taking the action).
- **Backend migration** (`migrate_backend`, migration leases) — a different backend id/path for the same
  version id; out of scope (the model has one implicit backend).
- **Range reads** — explicitly out of scope per the task; `R.2` always reads the whole blob.
- **Idempotency-key TTL / sweep** (`sweep_idempotency_page`) — see `S`'s note.
- **File-name reuse** (model simplification, not a code fact): `Files` is a small, reusable pool of
  symbolic names (`ex[f]` cycles `TRUE`/`FALSE` as files are created and deleted), unlike the real
  `file_id` (a `Uuid::now_v7()`, never reused). This is sound here because nothing in the model keys
  anything off a *file* identity across a delete — every durable fact (`blob`, `verVal`, `everVal`, `verOwner`,
  `idemFile`) is keyed by **version id**, which the model (like the real code) never reuses. A reincarnated
  `f` starts with `content[f] = NoVer` and no live versions, so it cannot alias a reader's or a binder's
  reference to the previous incarnation's version ids.
