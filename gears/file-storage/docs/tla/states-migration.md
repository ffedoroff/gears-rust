# file-storage: `migrate_backend` protocol (backend-relocation, one version)

Source: `file-storage/src/domain/service/backend.rs` (`migrate_backend`,
`migrate_backend_transfer_and_commit`, `stream_verify_and_publish_to_dest`),
`infra/storage/repo/version_repo.rs` (`acquire_migration_lease`,
`release_migration_lease`, `rebind_backend`), `infra/storage/store/versions.rs`
(`rebind_version_backend`, `delete_version`/`delete_version_or_whole_file`),
`config.rs` (`migrate_timeout_secs`, `migrate_lease_margin_secs`),
`infra/backend/mod.rs` (`StorageBackend::publish_exclusive`/`stat`/`delete`/
`get_stream`), `docs/features/backend-migration.md`. Step ids below (`G.x`)
are the ones `FileStorageMigration.tla` references in its action comments.
Doc and code agree closely here (`backend-migration.md` is unusually precise
and already names issue #5013 and the lease/timeout interaction); no
doc/code divergence was found worth flagging beyond what is noted under
"Known gap" below.

## Fix status (2026-10-02)

The G.12/G.14 root cause below ("a stale post-commit source-delete can race
a later migration back onto the same backend") is now **fixed in code**:
`VersionRepo::rebind_backend`'s CAS no longer clears
`migration_lease_owner`/`migration_lease_until` on a won CAS; the lease is
released only by the pre-existing `release_migration_lease` call in
`FileService::migrate_backend`, which now runs AFTER the post-commit source
delete on every exit path (success, error, timeout) -- holding the lease
through the whole cleanup closes the window by construction (a second
migrator cannot even acquire the lease until this one's own cleanup has
finished). The model gained a boolean `CONSTANT FixLeaseThroughCleanup`
(TRUE = current code); `FileStorageMigration.cfg`/`_medium.cfg` run with it
TRUE and now include `G1_NoDanglingPointer`/`G4_TailDeleteSafe` in the
invariant list (both exhaustive, no error -- see the top-level README's
results table). `FileStorageMigration_G12.cfg`/`_G14.cfg` set it FALSE to
keep reproducing the original bug for regression purposes. `#5013`
(`ExternalActor = TRUE`) is unaffected by this fix (out of the gear's own
coordination by definition) and remains open.

One `file_versions` row is modelled (`row`): a non-versioned file's single
`Available` version, with fields `backend_id` (current location),
`migration_lease_owner`/`migration_lease_until` (abstracted as a single
`lease_owner` -- the model does not carry real timestamps; a separate
`LeaseExpire` action represents "the database's own clock says the held
lease is past `migration_lease_until`", which is the only thing that matters
for takeover). The destination path (`storage_layout::backend_path(file_id,
version_id)`) is deterministic and therefore **the same literal path on
every backend** -- the model needs no `path` dimension at all, only "does
backend `b` currently hold an object at that one path" (`store[b]`).

`store[b] \in {"absent", "present", "foreign"}`: `"absent"` -- nothing at the
path; `"present"` -- an object with this version's correct bytes (written by
some `migrate_backend` attempt, or never touched); `"foreign"` -- an object
exists but its bytes do **not** match this version's hash (only reachable
through the `ExternalActor` action, see `G.X`; the gear itself never writes
anything but verified bytes, so a legitimate writer can only ever produce
`"absent"` or `"present"`).

## G -- `migrate_backend` (one attempt, actor `Migrators`)

- **G.1** Load the file, authorize `WRITE` (`domain/service/backend.rs`). **Not modelled**: PDP, tenancy.
- **G.2** List versions; require exactly one, status `Available`. **Not modelled**: the versioned-file / not-yet-`Available` rejections -- the model only ever has the one `Available` version this feature is scoped to.
- **G.3** No-op short-circuit: `target_backend_id == version.backend_id` returns `Ok(())` immediately, no lease, no audit. **Not modelled as a separate action**: a `Migrator` always starts with `target # row.backend` (picking the trivial case teaches nothing about the race protocol); the real no-op path cannot corrupt anything since it performs no write.
- **G.4** If the destination is non-durable, require `ADMIN_POLICY` in addition to `WRITE`. **Not modelled**: PDP; irrelevant to the concurrency protocol.
- **G.5** `acquire_migration_lease`: one conditional `UPDATE`, `migration_lease_owner`/`_until` CAS'd from free-or-expired to this attempt's own `owner`, timed by the **database's own clock** (`version_repo.rs`). Loses -> `409 Conflict`, before any backend is touched (`backend.rs`). This is the step that makes two concurrent attempts *at the same version* mostly impossible to interleave past this point -- but "mostly": see `G.Lx` (lease expiry) below, which is how the model reaches the genuinely-concurrent case the rest of `G` has to resolve (`rebind_backend`'s own doc, `version_repo.rs`, names this as the CAS's "third way to lose").
- **G.6** Everything from here through `G.12` (inclusive) runs inside **one** `tokio::time::timeout(migrate_timeout_secs, ..)` (`backend.rs`); a client disconnect (the whole request future dropped by the HTTP layer) can additionally cut this short at any `await` point from `G.5` through `G.13` -- see "`G.Cancel`" below, which is **not** the same thing as the timeout.
- **G.7** `stream_verify_and_publish_to_dest`: open `source.get_stream`, verify the hash mode-awarely as bytes stream past, `dest.publish_exclusive(dest_path, ..)` (create-exclusive -- never overwrite). Two outcomes:
  - `created: true` -- fresh bytes landed; `created_by_us := true`; go to `G.9`.
  - `created: false` -- something already sat at the deterministic path; resolved at `G.8` **without ever reading it back**.
  (Verification failure / source-stream break: delete the object `created_by_us` wrote, if any, and fail -- a terminal path the model folds into "verify never corrupts the version row": not separately modelled, since it can only ever choose between "delete what we just wrote" and "touch nothing", both already covered by other branches' cleanup logic.)
- **G.8** Destination-tail rule (see `backend-migration.md` "Migration Lease and Destination-Tail Resolution"): compare the version's **own pointer** (not the object) against the pre-migration snapshot this attempt started from (`src_snap`):
  - pointer still `= src_snap` (nothing else has legitimately claimed this path while *this* lease is held) -> it is a tail an earlier interrupted attempt left behind: best-effort delete it, retry the publish **exactly once** (`cleared_tail`). A second `created: false` after that retry is `Conflict`, no further retry.
  - pointer has moved -> a concurrent migration already claimed this path as live content: leave the object untouched (**never delete it**), fail `Conflict`.
- **G.9** Pre-CAS `stat`: re-confirm the object this call is about to make live is still there, at the expected length. Missing or wrong size -> `503` (retryable), **CAS never attempted**, pointer never touched. This narrows, but — see `G.X` — does **not** close the race with something outside the gear's own coordination.
- **G.10** `cas_started := true` (stamped *immediately before* the call), then `rebind_version_backend`: one transaction, `UPDATE .. SET backend_id = dest, backend_path = dest_path, migration_lease_owner = NULL, migration_lease_until = NULL WHERE backend_id = src_snap AND backend_path = src_snap_path AND migration_lease_owner = owner` (`version_repo.rs`). Three outcomes, nondeterministic in the model exactly as they are from the caller's point of view:
  - **committed** (1 row) -> `G.12`.
  - **lost** (0 rows) -- for any of three reasons the predicate can fail: the row is gone (a concurrent `delete_version`, `G.D`), the pointer already moved (a concurrent migration's `G.10` already won), or the lease moved on from `owner` (`G.Lx` fired and someone else re-acquired it) -> `G.11`.
  - **ambiguous** (the DB call's own `await` is cancelled by `G.Timeout` or `G.Cancel` while in flight) -- the transaction may or may not have committed; the model resolves this nondeterministically (`Apply` or not) at the same step, matching the code's documented position: *"once the CAS is in flight, this call can no longer tell whether it silently committed before the timeout raced it ... not attempting a cleanup in that ambiguous case is the safe choice"* (`backend.rs`).
- **G.11** Lost-CAS recovery (see `backend-migration.md`'s `cpt-cf-file-storage-algo-backend-migration-race-resolve`): re-fetch the row.
  - gone -> this attempt's destination write is a genuine orphan: best-effort delete it, fail `VersionNotFound`.
  - `backend_id = target` (a **different** migrator's commit to the **same** target already landed, since the path is deterministic) -> treat as a successful no-op, **do not delete** (it is the winner's live content).
  - `backend_id # target` (a different migration won, to a different target) -> best-effort delete this attempt's own write (it cannot be live), fail `Conflict`.
- **G.12** CAS won: best-effort delete the **source** blob -- by this point `row.backend_id` is already the destination (set in the same `G.10` transaction), so this can never target the live pointer.
- **G.13** Release the lease, best effort, **outside** the `timeout` wrapper, unconditionally on every exit path from `G.6`-`G.12` (success, every failure, and the elapsed-timeout branch) -- scoped to `owner`, so a lease already taken over by someone else is correctly left alone (`backend.rs`, `version_repo.rs`). A release that itself fails (or never runs -- `G.Cancel`) is not fatal: the lease is bounded and expires on the database's own clock regardless (`G.Lx`).
- **G.14** Timeout elapses: best-effort delete the destination **iff** `created_by_us /\ ~cas_started`; otherwise touch nothing. Return `503` either way; the pointer is "never observed to change" from the caller's perspective, but (ambiguous branch of `G.10`) it may already have.
- **G.Lx** Lease expiry (database clock): a live `lease_owner` can become "expired" at any time after `G.5` without the holder doing anything (a slow attempt, a crash, a lost connection) -- modelled as a standalone action that clears `lease_owner`, after which a **different** `Migrator` may `G.5`-acquire the very same lease and race ahead while the first attempt (unaware) is still anywhere between `G.6` and `G.13`. This is the only way the model reaches two attempts genuinely both live on one version at once; `G.10`'s owner predicate is what makes that safe.
- **G.Cancel** Client cancellation (HTTP request future dropped -- not represented anywhere in `backend.rs` as code, because there is nothing *to* write: Rust drops a `Future` by just not polling it again). Can hit **any** `await` point from `G.5` through `G.13`, including ones `G.Timeout` cannot reach (lease acquire itself, and the lease-release call). Unlike `G.Timeout`, nothing downstream of the drop point ever runs: no best-effort delete, no `release_migration_lease` call, no outcome returned to anyone. See "Timeout vs. cancellation" below for why this is still safe.

## G.D -- concurrent `delete_version` / `delete_file` (actor `Deleters`)

`store/versions.rs::delete_version` / `delete_version_or_whole_file`:
one transaction re-reads the row (`versions.get`,
*inside* the transaction, immediately before the `DELETE`) and removes it,
guarded by `is_current = false` at the DB level. The **row's current**
`backend_id` at that instant is what the service layer later best-effort
deletes (`read_ops.rs` passes `removed.backend_id`/`removed.backend_path`
straight from the transactional delete's return value, never a
pre-transaction snapshot) -- so the row-delete and the "which backend do I
blob-delete" decision are atomic with each other. Modelled as two steps:
`G.D1` (the transaction: `row.exists := FALSE`, snapshot `victim :=
row.backend_id`) then `G.D2` (best-effort `store[victim] := "absent"`,
nondeterministic like every other best-effort delete in this model). A
migrator whose `G.10` is still in flight when `G.D1` lands simply loses its
CAS (row gone) and takes the orphan branch of `G.11` -- no special case
needed, `G.10`'s predicate already requires `row.exists`.

Not modelled: the retention/orphan-reconciliation sweep (`domain/cleanup.rs`)
never touches `Available` versions (confirmed by reading `run_sweep`'s
candidate queries -- only `pending` rows older than `orphan_grace_secs` are
ever candidates, explicitly excluding anything an in-progress upload or
multipart session still needs); a migration only ever runs against an
`Available` version, so no sweep step can race it. `Sweeper` is intentionally
absent from the model.

## G.R -- a reader holding a pre-migration download reference (actor `Readers`)

A reader that resolved `(backend_id, backend_path)` once (e.g. a signed
download URL, or simply "read the version row") before a migration moved
the pointer, and fetches the bytes later. Downloads do **not** re-verify the
content hash (only `migrate_backend`'s own transfer, and upload finalize, do
that) -- modelled as `RSnapshot` (capture `rid := row.backend_id`) then
`RGet` (`ans := store[rid]`, mapped to `hit` / `miss` / `hit_bad`). A `miss`
(the source blob was best-effort deleted after a successful migration, or
the whole version/file was deleted) is availability, not a correctness
violation (`G5`'s own exception, by design -- the alternative, keeping the
old blob around "just in case" forever, is not what the code does: `G.12`
and `G.D2` both delete unconditionally once their own transaction committed).
A `hit_bad` is only reachable through `ExternalActor` (`G.X`) and is the same
root cause as the `G1` witness, not a second, independent problem.

## G.X -- `ExternalActor` (constant `ExternalActor: BOOLEAN`, issue #5013)

Something outside this gear's own coordination -- direct backend-console
surgery, another tool sharing the bucket/path namespace, a misconfigured
lifecycle rule -- deletes or overwrites the object at a backend's copy of the
deterministic path. Modelled as one always-enabled action (gated on the
constant) that picks any backend `b` with `store[b] \in {"present",
"foreign"}` and sets it to `"absent"` or `"foreign"`, at **any** point in the
global state, not just the documented "between `stat` and the CAS" window:
`rebind_version_backend`'s CAS (`G.10`) never inspects the blob at all, only
DB-row fields, so there is nothing structurally different about the window
before `G.9`'s `stat` versus the one between `G.9` and `G.10` -- the `stat`
call is what narrows the *first* half of that race (an external delete
before `G.9` is caught there, `503`, CAS never attempted), while nothing in
the code narrows the second half at all. Generalizing the action this way is
strictly more thorough than restricting it to the documented window, and
costs nothing extra to model.

## Known gap: timeout racing the CAS (the "ambiguous" outcome) -- verdict

**Yes, `rebind_version_backend`'s own `.await` is inside the
`tokio::time::timeout`** (`backend.rs`: the whole
`migrate_backend_transfer_and_commit` call, which performs the CAS, is the timed future). `cas_started` is stamped `true`
*immediately before* that `.await`, specifically so the code can
tell "the CAS never ran" apart from "cancelled after it may have already
landed" when the timeout's own cleanup decision runs afterward.

So: yes, the timeout **can** fire at the exact moment the CAS transaction has
already committed on the database side but the `tokio` task racing it gives
up before the result comes back over the wire. The code's answer in that
case is: **do nothing** -- no delete of the destination object (
gated on `!cas_started`, which is now `true`), and the lease is still
released afterward (the release call is outside the timed block, so it
always runs on this path). This is deliberate and is exactly the right
answer: deleting in that window could destroy the pointer the (possibly
already-committed) CAS just made live, which is a strictly worse outcome
than "a destination object nobody's pointer loses track of" (the committed
case) or "an unreachable destination object that the *next* migration
attempt's own `G.8` tail rule reclaims" (the not-committed case) -- both of
which are states the protocol already has to tolerate for other reasons.
**Verdict: not a bug.** The model's `G.10`/`G.Timeout` interaction encodes
precisely this and `G1`/`G4` hold across it (see Results).

Client cancellation (`G.Cancel`) is the same ambiguity one level up, with one
real difference: **nothing downstream runs at all**, not even the lease
release. The only consequence is the lease staying held until `G.Lx` (its
own database-clock expiry) fires -- bounded, and already the documented
fallback for "a release that itself fails is not fatal" (`backend.rs`'s own
doc for `release_migration_lease`). No invariant among `G1`-`G7` is affected by this, because `G.Cancel`
can only ever do a strict subset of what `G.Timeout` already does (resolve
the in-flight CAS nondeterministically, then stop -- `G.Timeout` additionally
runs a best-effort cleanup and the lease release, both of which only ever
*remove* an object or free a lease, never create a dangling pointer). This
is a genuine (if minor) finding worth recording even though it is not a
safety violation: **a migration can succeed (CAS committed) and still return
a `503` to the caller** if the best-effort source-delete at `G.12` alone
overruns `migrate_timeout_secs` -- the caller sees an error for an operation
that actually finished; retrying is still safe (the retry's own `G.3` no-op
check resolves it immediately).

## Finding: a stale `G.12` source-delete can race a *later* migration back onto the same backend

Not #5013 (no external actor involved) and not #5106 (not a *failed* delete) --
found by TLC on the small config (`FileStorageMigration.cfg`, exhaustive,
`ExternalActor = FALSE`), reachable in the minimum possible configuration (2
backends, depth 13), so this is not an edge case the model manufactured by
being overly permissive -- see "Verdict" below for why it is realistic.

**The race.** `migrate_backend`'s destination path is deterministic
(`/{file_id}/{version_id}`, fixed for the version's entire lifetime, the
same on every backend it ever visits). The migration lease protects attempts
*up to the CAS*, but `rebind_version_backend`'s `UPDATE` clears
`migration_lease_owner` in the **same statement** as the CAS (`version_repo.rs`)
-- i.e. the lease is gone the instant the commit lands, strictly *before*
`G.12`'s best-effort source delete even starts (`backend.rs`). Sized
against *this* attempt's own `migrate_timeout_secs` (up to
`MAX_MIGRATE_TIMEOUT_SECS` = 24h), `G.12`'s delete call can be slow for
reasons that have nothing to do with the version it is cleaning up after (a
contended connection pool, a backend already being drained because it is
being decommissioned -- the headline use case for this whole feature). A
**second**, fully independent `migrate_backend` call is free to acquire the
now-released lease and run an entire attempt of its own while the first
call's `G.12` is still in flight. In a 2-backend deployment the second
attempt's only possible target is the backend the first attempt just
vacated -- so "migrate back to where it just came from" is not a contrived
scenario, it is the *only* other option. If the second attempt writes its
own (correct, verified) content to that backend and commits its own CAS
*before* the first attempt's long-delayed `G.12` delete finally fires,
`G.12`'s unconditional, un-guarded `backend.delete(path)` wipes the object
the second attempt's pointer now names: `row.exists /\ row.backend = the
backend G.12 is deleting`, with nothing left there -- `G1_NoDanglingPointer`
violated, with `ExternalActor = FALSE`. (The order can also go the other
way -- the second attempt commits first, then the stale delete fires -- same
outcome, arguably more obviously wrong since the object being deleted is
unambiguously the current live pointer's content at the moment of deletion.)

**Why this is not the same gap as #5013.** #5013 is "something outside the
gear's own coordination changes the destination object in the narrow window
between this attempt's own `stat` and its own `CAS`". This is "a **different,
later, fully legitimate** `migrate_backend` attempt of the **same version**
writes to a backend this attempt is *also* about to touch, outside any
window the lease covers, because the lease was already released." The loser
cleanup path (`G.11`) already has exactly the guard this would need --
`backend.rs`: *"guarded by a belt-and-suspenders re-check that it
doesn't coincidentally equal the live pointer for some other reason"* -- but
`G.12`'s winner-side source cleanup has no equivalent check at all.

**A natural guard is not sufficient.** I tried the obvious mirror of `G.11`'s
guard -- re-check `row.backend # (the backend about to be deleted)`
immediately before `G.12`'s delete, skip if it now matches (`g12fix` in
`.../scratchpad/tla/work/g12fix/`) -- and TLC still finds the same violation
at the same depth: the danger is not "the pointer already moved back by the
time of the delete" (which the re-check would catch), it is "a **write** is
already in flight / about to commit to that path" at delete time, which is
not visible from the row at all; the re-check only ever sees the row
*before* the second attempt's CAS has landed. Closing it this way would
need a real compare-and-delete (delete only if the object is still the one
this attempt itself wrote -- a generation/ETag check the `StorageBackend`
trait does not expose today, `infra/backend/mod.rs`).

**A fix that does work.** Holding the lease through `G.12` instead of
releasing it in the same statement as the CAS (clear it only at `G.13`) does
close this by construction: a second attempt cannot even acquire the lease
until the first one's own cleanup has finished (or been timed out and
force-released) -- verified in `.../scratchpad/tla/work/g12fix2/`
(`FileStorageMigrationLeaseThroughCleanup.tla`), exhaustive at both the small
and medium configs, no violation. The tradeoff is holding the lease for
longer than today (through one best-effort backend call instead of none),
which only delays a *different* version's... no -- a **second attempt on the
very same version**, which is already waiting out the lease today in the
overlapping case anyway; the window this closes is specifically "the second
attempt would otherwise have been allowed to start before the first one's
cleanup is done." This is reported as a finding for the file-storage team to
triage, not applied anywhere -- no code in `file-storage/src` was changed.

## Invariants (`G1`-`G7`)

- **G1_NoDanglingPointer**: `row.exists => store[row.backend] = "present"`
  (existence *and* correct bytes in one predicate, matching the task's
  phrasing). Must hold when `ExternalActor = FALSE`. Expected to be
  reachable as a witness when `ExternalActor = TRUE` (#5013) -- see Results.
- **G2_LeaseExclusive** / **G3_NoCommitWithoutLease**: in a one-row model
  these collapse into the same thing -- `lease_owner` is a single-valued
  field, so "two migrators both hold it" cannot be represented at all, and
  `G.10`'s `committed_ok` guard structurally requires `row.lease_owner =
  Some(w)`. Checked as a mutation target rather than as a standing
  invariant: a copy with the owner conjunct dropped from the guard
  (`.../scratchpad/tla/work/m_nolease/`) is caught by `G1_NoDanglingPointer`
  at the same small config, confirming the guard is load-bearing and the
  model does not pass vacuously.
- **G4_TailDeleteSafe**: no delete action (`G.8`'s tail delete, `G.11`'s
  orphan/loser cleanup, `G.14`'s timeout cleanup) ever targets a backend `b`
  with `row.exists /\ row.backend = b` at the moment it fires. Checked
  directly as a state invariant (see TLA module).
- **G5_ReadExactOrMiss**: a finished reader's answer is never `hit_bad`
  when `ExternalActor = FALSE`; `hit_bad` is an expected #5013 witness under
  `ExternalActor = TRUE` (same root cause as `G1`, not independently
  interesting). `miss` is never a violation (availability, not correctness).
- **G6_NoPermanentOrphan**: **not** encoded as a standing TLC invariant --
  every best-effort delete in the model (`G.8`, `G.11`, `G.12`, `G.13`
  n/a-doesn't-delete, `G.14`, `G.D2`) is allowed to nondeterministically
  fail, exactly as the real `best_effort_blob_delete` logs-and-continues on
  error (`write.rs`). A failed source-delete at `G.12` is the known,
  accepted residual #5106 (nothing ever retries it -- no sweep candidate
  covers an `Available` version, `G.D`'s note above). Documented, not
  asserted.
- **G7_DeleteVsMigrate**: likewise descriptive, not a standing invariant --
  `~row.exists` does not imply every backend is clear of a `"present"`
  object at every subsequent state, because `G.D2`'s own delete is
  best-effort and can fail (same #5106 shape, this time for the *deleted*
  version rather than a migrated-away one). What *is* true, and checked, is
  narrower and covered by `G4`: nothing a migrator or deleter does can ever
  turn this residual into a *dangling pointer*, because there is no pointer
  left to dangle once `row.exists = FALSE`.

## Phase 2: long runs, a second finding, mutations, and a validated fix

`G2_LeaseExclusive`/`G3_NoCommitWithoutLease` (`~doubleCommit`) and
`G4_TailDeleteSafe` (`~deletedLiveTarget`) are now real, independently
checked invariants backed by their own ghost bookkeeping (`genCounter`/
`heldGen`/`committedGens` for G2/G3; a per-delete-site live-pointer check for
G4, deliberately excluding `PostCommit` and `Timeout`/`Cancel`'s
`"post_commit"` branch -- the already-reported `G.12` family -- so this
check can be run *instead of* `G1` without immediately re-tripping on that
known cause). `G7_DeleteVsMigrate_AtRest` (`Quiescent /\ ~row.exists =>
no backend holds "present"`) is now declared too, run only as a witness.

### Second finding: `G.14`'s "clean up my own write" branch has the same gap as `G.12`

Running **all invariants except `G1`** (small config, `SYMMETRY Symm` on
`Migrators`) -- specifically to see past the known `G.12` cause and look for
anything else -- surfaced a **second, independent violation of `G4`** at
depth 17. Full trace, reconstructed field-by-field from the TLC counterexample:

1. `w1` migrates `b1 -> b2`, commits (gen 1), lease cleared in the same
   statement; `w1` is still sitting at `post_commit` (its own `G.12` source
   delete of `b1` has not run yet).
2. `w2` starts a second, unrelated migration `b2 -> b1` (the only other
   backend), acquires the now-free lease (gen 2). Its own `G.8` tail-check
   finds `b1` occupied (by `w1`'s not-yet-cleaned-up original content),
   concludes -- correctly, by the pointer rule -- that nothing legitimately
   claims it, deletes it and retries; its own fresh write lands at `b1` and
   it reaches `cas` (`cas_started` set).
3. **`w1` is `Cancel`'d** (client disconnect) while still at `post_commit`
   from its *already-successful* gen-1 attempt. The pending source-delete
   this leaves resolves (nondeterministically, same ambiguity as `G.12`
   always allows) as **"deleted"** -- and the backend it deletes, `b1`, is
   at this exact moment `w2`'s fresh, already-verified, about-to-be-committed
   write. This step alone is already a restatement of the `G.12` finding
   (reached via `Cancel` racing the delete instead of plain slowness) --
   `deletedLiveTarget` is correctly NOT tripped here (`PostCommit`/`Cancel`'s
   `"post_commit"` branch is deliberately excluded from `G4`), but it
   silently creates a **`G1` dangling pointer the instant `w2` later
   commits** (not checked in this run, by design).
4. `w1` restarts fresh (gen 3), and -- since there are only 2 backends --
   is forced to pick `target = b1`, `src_snap = b2` (both backends are
   occupied otherwise). **`AcquireLease` never re-validates `src_snap`
   against the row's current state**, so this snapshot goes stale the
   moment `w2` commits next.
5. `w2` commits (gen 2): `row.backend := b1`, even though `store[b1]` is
   currently `"absent"` (wiped at step 3) -- a direct `G1` violation, simply
   not being checked here.
6. `w1` acquires the lease (gen 3) and its own `Transfer` finds `store[b1] =
   "absent"` (from step 3/5) -- takes the **fresh-write** branch,
   `created_by_us[w1] := TRUE`, and (coincidentally, for the wrong reason)
   **"repairs"** the dangling pointer from step 5 by writing correct bytes
   there.
7. **`w1`'s own `Timeout` fires while it is still at `"stat"`** (before its
   own CAS). Per `G.14`, `created_by_us[w1] = TRUE` unconditionally triggers
   a best-effort delete of `target[w1] = b1` -- **without re-checking
   whether the row's pointer has, in the meantime, come to equal that exact
   backend**. It has (step 5/6's chain made `b1` live). The delete fires:
   `deletedLiveTarget := TRUE`. `G4` violated.

**Verdict.** This is the same root defect as the `G.12` finding --
*none* of `migrate_backend`'s best-effort cleanup call sites (`G.8`'s tail
delete, `G.11`'s loser/orphan cleanup, `G.12`'s own source delete, and now
confirmed also `G.14`'s "delete what I just wrote, the attempt timed out"
branch) re-verify the row's *current* pointer immediately before deleting --
`G.11` is the only one that already does this (`backend.rs`'s own
"belt-and-suspenders" comment). Here it manifests one level further out: a
timeout's own cleanup of its *own*, never-committed write can still destroy
something that *became* live through an unrelated chain of events while that
write sat unconfirmed. Reaching it in this trace needed the `G.12` family to
fire first (to make `w1`'s own fresh write "accidentally" the live pointer);
I did not find a shorter, independent trace that reaches a `G4` violation
through `G.14` alone within the time available -- flagged as a second,
related finding for the file-storage team, not confirmed fully independent
of `G.12`. The same remedy applies: holding the lease through *all* of an
attempt's own best-effort cleanup (not releasing it until `G.13`) prevents
step 2 from ever starting while step 1's cleanup is still outstanding,
which is exactly what the `leasethrough` fix candidate already does --
confirmed below.

### Fix candidate re-verified after adding G2-G5 and at larger scale

`leasethrough` (hold the lease through `PostCommit`/`Timeout`/`Cancel`'s
`"post_commit"` branch, clear it only at `Release`) was regenerated from the
current module (now carrying `G2`-`G5`'s real checks) and re-run:

- small, `SYMMETRY Symm`, all of `TypeOK`/`G1`/`G2`/`G3`/`G4`/`G5`:
  **exhaustive, no error** (same as phase 1's result on the pre-G2-G5
  module -- adding the new invariants changed nothing).
- medium (3 backends/migrators, 2 deleters/readers), `SYMMETRY Symm`: no
  error in 180s, 20M+/7M+ states, depth 17 reached, not exhaustive.
- large (3 backends/migrators, 2 deleters/readers, no symmetry): no error in
  300s, 160M+/32M+ states, depth 17 reached, not exhaustive.
- **random simulation**, large config, `-simulate -depth 150`, 450s: **no
  error** across ~350M states checked / ~1.8M traces (mean trace length 127,
  close to the depth cap) -- by far the deepest exploration this model has
  had, and the strongest evidence yet that the fix is sound, short of a full
  exhaustive proof at this scale.

### Item 2: searching for *other* `G1` causes with the `G.12` race structurally excluded

`NoG12Race` (scratchpad only): `Start(w)` additionally excludes, from its
target choice, every backend any *other* still-live migrator currently has
as its own `src_snap` or `target` (`Busy(w2)`/`LiveBusy(w)`) -- a narrower,
purely target-selection-level restriction than `leasethrough`, chosen so it
stays orthogonal to a real code fix and only answers "is there anything
*else* wrong, once this one family can't fire". At 3 backends/migrators, 2
deleters/readers, **all invariants including `G1`**: two independent runs
(300s and 240s, `-workers 3`/`4`), **no violation**, ~99-142M states / 24-34M
distinct, depth 17 reached each time, neither exhaustive. No other `G1`
cause (delete-vs-migrate, timeout, cancellation, or the tail rule alone) was
found within ~9 CPU-minutes of search at this scale.

### Mutations (phase 2)

Each is a scratchpad copy of the current module with exactly one guard
removed/weakened, run on the small config (2 backends/migrators) unless
noted; "isolated on `leasethrough`" reruns the same mutation on top of the
fix candidate, to tell the mutation's *own* effect apart from the
already-known `G.12`/`G.14` noise the unpatched base model would otherwise
surface first.

| # | Mutation | Caught by | Depth | States gen/distinct |
|---|---|---|---|---|
| m1 | `G.8` tail rule: drop the `row.backend = src_snap[w]` ("still on source") check -- always treat `created:false` as a reclaimable tail | `G1_NoDanglingPointer` | 9 | 4,251 / 1,803 |
| m2 | `Timeout`'s `"cas"` branch: best-effort delete `target[w]` even when the CAS turns out ambiguous-committed (`cas_started` no longer gates it) | `G1_NoDanglingPointer` | 6 | 444 / 231 |
| m3 | `Release`: never clears the lease on *any* exit path | *(on the unpatched base: `G1` at depth 13 -- but that is the pre-existing `G.12` trace, unaffected by this mutation; see m3-isolated)* | 13 | 76,773 / 25,184 |
| m3 (isolated on `leasethrough`) | same mutation, on top of the fix (so success no longer clears the lease via `Release` either) | **no violation** in 120s / ~49M states, depth 34 reached -- consistent with the predicted effect: availability only (every later attempt gets `conflict_lease` until `LeaseExpire`), not a safety break | -- | ~49M / ~11.6M |
| m4 | `LeaseExpire`: drop the `pc[row.lease] = "idle"` gate phase 1 added (instance-clock skew: the lease can look expired to the database before its holder's own local timeout fires) | `G1_NoDanglingPointer` | 10 | 20,584 / 7,226 |
| m5 | `Commit`/`Timeout`/`Cancel`'s `ok`: drop the `row.backend = src_snap[w]` snapshot check, keep only the lease-owner check | *(on the unpatched base: `G1` at depth 13 -- again the pre-existing `G.12` trace; see m5-isolated)* | 13 | 77,288 / 25,364 |
| m5 (isolated on `leasethrough`) | same mutation, on top of the fix | **no violation** in 60-120s / ~1.7-2M+ states (not exhaustive) -- plausible explanation: once the lease spans the *whole* attempt including cleanup, nothing else can change `row.backend` while a migrator holds it, so the snapshot check's own protection is redundant in that narrower regime; it remains necessary against today's (unpatched) lease-release timing | -- | ~1.7-2M |

m1, m2 and m4 are clean, independent confirmations (each reaches its
violation through a trace the mutation itself enables, not through the
pre-existing `G.12`/`G.14` family). m3 and m5's *base-model* runs just
re-surface the already-known finding faster than the mutation's own effect
can be observed, which the isolated reruns on `leasethrough` correct for --
both come back clean within the time available, matching the coordinator's
own prediction for m3 and a newly-reasoned (not previously predicted)
explanation for m5.

### G7, run as a witness (both models)

`G7_DeleteVsMigrate_AtRest` (quiescent + version gone => no backend still
`"present"`): violated on **both** the unpatched base model (depth 3:
`DeleteStep1` then `DeleteStep2` choosing "keep", i.e. the best-effort blob
delete simply fails) and `leasethrough` (depth 3, identical shape) --
confirms the predicted #5106-shaped residual and nothing worse, on both
models (expected: `G.D2`'s own logic is untouched by the lease-timing fix).

### Updated run table (phase 2 additions; phase 1's table is above/in the report)

| Run | Model | Constants | Invariants | States gen/distinct | Depth | Time | Result |
|---|---|---|---|---|---|---|---|
| small, no-G1, `SYMMETRY` | base (repo) | 2B/2M/1D/1R | TypeOK,G2,G3,G4,G5 | 389,832 / 109,009 | 17 | 1s | **G4 violated** (second finding, above) |
| medium, no-G1, `SYMMETRY` | base (repo) | 3B/3M/2D/2R | TypeOK,G2,G3,G4,G5 | 28,614,741 / 5,934,520 | 17 | 1m23s | **G4 violated** (same finding, reproduces) |
| `NoG12Race` #1 | scratchpad | 3B/3M/2D/2R | all incl. G1 | ~142M / ~34M | 17 | 300s (`-workers 3`) | no error, not exhaustive |
| `NoG12Race` #2 | scratchpad | 3B/3M/2D/2R | all incl. G1 | ~99M / ~24M | 17 | 240s (`-workers 4`) | no error, not exhaustive |
| `leasethrough` medium, `SYMMETRY` | scratchpad | 3B/3M/2D/2R | all incl. G1 | ~36M / ~7M | 17 | 180s | no error, not exhaustive |
| `leasethrough` large | scratchpad | 3B/3M/2D/2R | all incl. G1 | 160M+ / 32M+ | 17 | 300s | no error, not exhaustive |
| `-simulate -depth 150`, base (no G1) | scratchpad run against repo module | 3B/3M/2D/2R | TypeOK,G2,G3,G4,G5 | ~355M checked / 1.8M traces | mean 127 | 450s | no error |
| `-simulate -depth 150`, `leasethrough` | scratchpad | 3B/3M/2D/2R | all incl. G1 | ~350M checked / 1.8M traces | mean 127 | 450s | no error |
| m1 | scratchpad mutation | 2B/2M/1D/1R | all | 4,251 / 1,803 | 9 | <1s | **G1 violated** |
| m2 | scratchpad mutation | 2B/2M/1D/1R | all | 444 / 231 | 6 | <1s | **G1 violated** |
| m3 (isolated) | scratchpad mutation on `leasethrough` | 2B/2M/1D/1R | all | ~49M / ~11.6M | 34 | 120s | no error, not exhaustive |
| m4 | scratchpad mutation | 2B/2M/1D/1R | all | 20,584 / 7,226 | 10 | <1s | **G1 violated** |
| m5 (isolated) | scratchpad mutation on `leasethrough` | 2B/2M/1D/1R | all | ~1.7-2M | n/a | 60-120s | no error, not exhaustive |
| G7 witness, base | base (repo) | 2B/2M/1D/1R | G7 only | 161 / 103 | 3-6 | <1s | **G7 violated** (expected, #5106 shape) |
| G7 witness, `leasethrough` | scratchpad | 2B/2M/1D/1R | G7 only | 140 / 90 | 6 | <1s | **G7 violated** (same shape) |

## Not modelled

PDP/authorization (`G.1`, `G.4`); the versioned-file and not-yet-`Available`
rejections (`G.2`, the model is scoped to the one case the feature supports);
the no-op short-circuit (`G.3`, performs no write, nothing to check);
content-hash verification failure / a broken source stream (folds into
branches already covered: delete-what-we-wrote-or-not, touch nothing else);
real timestamps for the lease (`migration_lease_until`) -- abstracted to a
single nondeterministic `LeaseExpire` action; the retention/orphan sweep
(confirmed never to touch `Available` versions, so cannot race a migration);
audit-row writes (same transaction as the CAS, never independently
observable, never fails the operation); multipart/versioned-file content
(out of this feature's scope entirely, `G.2`); backend-specific
`publish_exclusive` atomicity differences (the model takes the trait's
documented contract -- genuinely atomic create-exclusive -- as given for
every backend, per `local-fs`/`in-memory`/`s3`'s own implementations; the
*default*, non-atomic TOCTOU fallback in `infra/backend/mod.rs` is itself a
known gap the trait doc already calls out, orthogonal to `migrate_backend`'s
own protocol and not re-modelled here).
