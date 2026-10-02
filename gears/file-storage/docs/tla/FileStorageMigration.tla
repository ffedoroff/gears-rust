------------------------- MODULE FileStorageMigration -------------------------
(***************************************************************************)
(* `migrate_backend` (file-storage, branch `file-storage`): relocating one  *)
(* non-versioned file's single `Available` version's content from one      *)
(* storage backend to another.  One `file_versions` row is modelled        *)
(* (`row`): `exists` (the row itself), `backend` (its current              *)
(* `backend_id` -- `backend_path` is fixed/deterministic across every      *)
(* backend for this version, so it needs no dimension of its own, only     *)
(* "does backend b hold an object at that one path": `store[b]`), `lease`  *)
(* (`migration_lease_owner`, abstracted to a single value; the database-   *)
(* clock expiry of `migration_lease_until` is `LeaseExpire` below, not a    *)
(* real timestamp).  Step ids (`G.x`) refer to `states-migration.md` in    *)
(* this directory.                                                         *)
(*                                                                         *)
(* `store[b] \in {"absent", "present", "foreign"}`: nothing at the path /  *)
(* this version's correct bytes / an object with the WRONG bytes (only     *)
(* reachable via `Tamper`, i.e. `ExternalActor`, issue #5013 -- the gear    *)
(* itself never writes anything but verified bytes).                       *)
(*                                                                         *)
(* A `Migrator`'s own bookkeeping mirrors `migrate_backend`'s real local    *)
(* state exactly: `target` (the destination it picked), `src_snap` (the    *)
(* pre-migration pointer snapshot the CAS predicate is gated on, G.10),     *)
(* `created_by_us`/`cas_started` (the two `AtomicBool`s `backend.rs`'s own  *)
(* doc names by name), `cleared_tail` (G.8's "retried once" bound).         *)
(*                                                                         *)
(* `Timeout(w)` models `tokio::time::timeout` elapsing anywhere from G.7    *)
(* through G.12 (the whole timed body, including the CAS itself and its    *)
(* own lost-CAS recovery and the post-commit source delete) -- see         *)
(* `states-migration.md`'s "Known gap" section for the verdict on why this  *)
(* is safe even when it fires with `cas_started = TRUE` (the CAS may have   *)
(* already committed; the code deliberately does not try to clean up in    *)
(* that case).  `Cancel(w)` models the enclosing HTTP request future being  *)
(* dropped (client disconnect) -- reachable anywhere G.5 through G.13,      *)
(* strictly more destructive in *scope* (it can also hit lease-acquire and  *)
(* lease-release, which `Timeout` cannot) but strictly less destructive in  *)
(* *effect* (it never runs any best-effort cleanup at all, only resolves    *)
(* whatever DB transaction was genuinely in flight, same ambiguity as       *)
(* `Timeout`'s own "cas" case).                                            *)
(*                                                                         *)
(* `Deleters` model concurrent `delete_version`/`delete_file` (G.D): the    *)
(* row-delete and the snapshot of which backend to best-effort blob-delete  *)
(* happen in the same step (`DeleteStep1`), exactly as the real             *)
(* transaction re-reads the row immediately before its own `DELETE`.        *)
(*                                                                         *)
(* `Readers` model a caller holding a pre-migration `(backend_id,           *)
(* backend_path)` reference (a signed download URL, say): `RSnapshot`       *)
(* captures the pointer, `RGet` resolves it later against `store` --        *)
(* downloads never re-verify the content hash, so a `"foreign"` object      *)
(* served through a stale-but-still-live pointer reads as `"hit_bad"`.      *)
(*                                                                         *)
(* `ExternalActor` (issue #5013, constant `BOOLEAN`): `Tamper(b)` deletes   *)
(* or replaces whatever is at backend `b`'s copy of the deterministic path, *)
(* at ANY point in the global state -- not only the documented "between     *)
(* `stat` and the CAS" window.  `rebind_version_backend`'s CAS never        *)
(* inspects the blob at all (only DB-row fields), so there is nothing       *)
(* structurally different about any other window; generalizing is strictly *)
(* more thorough and costs nothing extra to model.                         *)
(*                                                                         *)
(* Not modelled: PDP/authorization; the versioned-file and not-yet-         *)
(* `Available` rejections (out of this feature's scope); the same-backend   *)
(* no-op short-circuit (performs no write); content-hash verification       *)
(* failure / a broken source stream (folds into branches already covered);  *)
(* real lease timestamps (abstracted to `LeaseExpire`); the retention/      *)
(* orphan sweep (confirmed never to touch `Available` versions); audit-row  *)
(* writes (same transaction as the CAS, never independently observable).    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Migrators, Deleters, Readers, Backends, ExternalActor, MaxGen,
          FixLeaseThroughCleanup
    \* FixLeaseThroughCleanup: TRUE = current code (`VersionRepo::rebind_backend`'s
    \* CAS no longer clears `migration_lease_owner`/`migration_lease_until` on a
    \* won CAS; only `release_migration_lease` does, called from
    \* `FileService::migrate_backend` AFTER the post-commit source delete).
    \* FALSE = the unpatched code (the CAS cleared the lease itself, in the same
    \* statement, before the post-commit delete ever ran) -- reproduces G.12/G.14.
ASSUME ExternalActor \in BOOLEAN
ASSUME Cardinality(Backends) >= 2
ASSUME MaxGen \in Nat
ASSUME FixLeaseThroughCleanup \in BOOLEAN

NoBackend == "nob"
NoOwner   == "noo"

PCs      == {"idle", "lease_wait", "transfer", "stat", "cas", "lost_refetch", "post_commit", "release"}
DPCs     == {"idle", "pending_blob", "done"}
RPCs     == {"idle", "pending", "done"}
Outcomes == {"none", "ok", "conflict_lease", "conflict_tail", "conflict_race", "notfound", "unavailable", "cancelled"}

VARIABLES
    row,            \* [exists, backend, lease] -- the file_versions row (one version)
    store,          \* [Backends -> {"absent","present","foreign"}] -- the deterministic path on each backend
    pc,             \* migrator program counter
    target,         \* migrator's chosen destination backend
    src_snap,       \* migrator's pre-migration pointer snapshot (the CAS predicate, G.10)
    created_by_us,  \* ghost AtomicBool, named as in backend.rs
    cas_started,    \* ghost AtomicBool, named as in backend.rs
    cleared_tail,   \* G.8: already retried once after clearing a tail
    outcome,        \* ghost: last terminal outcome of a migrator, for witnesses only
    dpc,            \* deleter program counter
    victim,         \* deleter's snapshot of which backend to best-effort blob-delete
    rpc,            \* reader program counter
    rid,            \* reader's snapshotted backend
    ans,            \* reader's last answer
    sawConflict,    \* ghost, monotonic: some migrator was ever refused with a conflict (409-shaped)
    sawTimeout,     \* ghost, monotonic: Timeout ever fired
    sawTailDelete,  \* ghost, monotonic: the G.8 tail-delete-and-retry branch ever fired
    genCounter,     \* ghost: one fresh generation number per successful AcquireLease (G2/G3)
    heldGen,        \* ghost: [Migrators -> Nat], the generation this migrator currently holds (0 = none)
    committedGens,  \* ghost, monotonic: every generation that ever won its CAS (G2/G3)
    doubleCommit,   \* ghost, monotonic: TRUE if the same generation ever won its CAS twice (G2/G3)
    deletedLiveTarget \* ghost, monotonic: TRUE if a G.8/G.11/G.14/Cancel delete ever targeted the
                      \* then-current live backend (G4) -- deliberately NOT tracked for G.12's own
                      \* post-commit source delete (PostCommit, and Timeout/Cancel's "post_commit"
                      \* branch), since that family's known gap is already reported separately
                      \* (states-migration.md's G.12 finding) and would otherwise swamp this check

vars == << row, store, pc, target, src_snap, created_by_us, cas_started, cleared_tail,
           outcome, dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
           genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget >>

Init ==
    LET b0 == CHOOSE b \in Backends : TRUE IN
    /\ row = [exists |-> TRUE, backend |-> b0, lease |-> NoOwner]
    /\ store = [b \in Backends |-> IF b = b0 THEN "present" ELSE "absent"]
    /\ pc = [w \in Migrators |-> "idle"]
    /\ target = [w \in Migrators |-> NoBackend]
    /\ src_snap = [w \in Migrators |-> NoBackend]
    /\ created_by_us = [w \in Migrators |-> FALSE]
    /\ cas_started = [w \in Migrators |-> FALSE]
    /\ cleared_tail = [w \in Migrators |-> FALSE]
    /\ outcome = [w \in Migrators |-> "none"]
    /\ dpc = [d \in Deleters |-> "idle"]
    /\ victim = [d \in Deleters |-> NoBackend]
    /\ rpc = [r \in Readers |-> "idle"]
    /\ rid = [r \in Readers |-> NoBackend]
    /\ ans = [r \in Readers |-> "none"]
    /\ sawConflict = FALSE
    /\ sawTimeout = FALSE
    /\ sawTailDelete = FALSE
    /\ genCounter = 0
    /\ heldGen = [w \in Migrators |-> 0]
    /\ committedGens = {}
    /\ doubleCommit = FALSE
    /\ deletedLiveTarget = FALSE

(***************************** migrators (G) *******************************)

\* G.1-G.4 (not modelled: PDP, versioned-file/not-Available rejections,
\* the same-backend no-op, the admin gate) collapse to: pick a destination
\* different from the current backend and snapshot the current pointer.
Start(w) ==
    /\ pc[w] = "idle"
    /\ \E b \in Backends \ {row.backend} :
         /\ target' = [target EXCEPT ![w] = b]
         /\ src_snap' = [src_snap EXCEPT ![w] = row.backend]
         /\ created_by_us' = [created_by_us EXCEPT ![w] = FALSE]
         /\ cas_started' = [cas_started EXCEPT ![w] = FALSE]
         /\ cleared_tail' = [cleared_tail EXCEPT ![w] = FALSE]
         /\ heldGen' = [heldGen EXCEPT ![w] = 0]
         /\ outcome' = [outcome EXCEPT ![w] = "none"]
         /\ pc' = [pc EXCEPT ![w] = "lease_wait"]
    /\ UNCHANGED <<row, store, dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, committedGens, doubleCommit, deletedLiveTarget>>

\* G.5: acquire_migration_lease -- one conditional UPDATE, free-or-expired only.
AcquireLease(w) ==
    /\ pc[w] = "lease_wait"
    /\ IF row.lease = NoOwner
       THEN /\ row' = [row EXCEPT !.lease = w]
            /\ pc' = [pc EXCEPT ![w] = "transfer"]
            /\ outcome' = outcome
            /\ sawConflict' = sawConflict
            /\ genCounter' = genCounter + 1
            /\ heldGen' = [heldGen EXCEPT ![w] = genCounter + 1]
       ELSE /\ UNCHANGED row
            /\ pc' = [pc EXCEPT ![w] = "idle"]
            /\ outcome' = [outcome EXCEPT ![w] = "conflict_lease"]
            /\ sawConflict' = TRUE
            /\ UNCHANGED <<genCounter, heldGen>>
    /\ UNCHANGED <<store, target, src_snap, created_by_us, cas_started, cleared_tail,
                   dpc, victim, rpc, rid, ans, sawTimeout, sawTailDelete,
                   committedGens, doubleCommit, deletedLiveTarget>>

\* Database-clock lease expiry. Gated on `pc[row.lease] = "idle"`: the
\* lease's own duration (`migrate_timeout_secs + migrate_lease_margin_secs`,
\* the margin sized exactly to absorb clock skew plus the tail of an
\* in-flight call) is a standing design assumption that the database never
\* considers a lease expired while its holder is still genuinely, locally
\* progressing -- a live holder either finishes normally (Release, clearing
\* it directly) or has its own `tokio::time::timeout` fire first (Timeout,
\* which also always reaches Release on this path). The only way the model
\* reaches a lease that is free to expire out from under someone still
\* "shown" as the owner is `Cancel` (the request future dropped before
\* `Release` ever ran): that always sets `pc[w] = "idle"` immediately, with
\* `row.lease` possibly still `w`. THIS is the realistic takeover case the
\* lease's third loss-reason (`version_repo.rs`'s own doc) names --
\* reclaiming an abandoned attempt, never racing a live one. (An earlier,
\* unrestricted version of this action let a second migrator's G.8 tail
\* check fire against a FIRST migrator's still in-flight, not-yet-committed
\* write, with both nominally "live" at once -- unreachable in the real
\* code, since nothing shortens a held lease to zero while its own instance
\* is still making progress; see the small-config run log for that trace.)
LeaseExpire ==
    /\ row.lease # NoOwner
    /\ pc[row.lease] = "idle"
    /\ row' = [row EXCEPT !.lease = NoOwner]
    /\ UNCHANGED <<store, pc, target, src_snap, created_by_us, cas_started, cleared_tail,
                   outcome, dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

\* G.7/G.8: publish_exclusive (create-exclusive) + the destination-tail rule.
\* `store[b] = "absent"`: fresh write, created_by_us := TRUE, go straight to
\* the pre-CAS stat (G.9). Otherwise `created: false`: resolved from the
\* POINTER alone, never by reading the object back.
Transfer(w) ==
    /\ pc[w] = "transfer"
    /\ LET b == target[w] IN
       IF store[b] = "absent"
       THEN /\ store' = [store EXCEPT ![b] = "present"]
            /\ created_by_us' = [created_by_us EXCEPT ![w] = TRUE]
            /\ pc' = [pc EXCEPT ![w] = "stat"]
            /\ outcome' = outcome
            /\ cleared_tail' = cleared_tail
            /\ sawConflict' = sawConflict
            /\ sawTailDelete' = sawTailDelete
            /\ deletedLiveTarget' = deletedLiveTarget
       ELSE IF row.backend = src_snap[w]
            THEN IF cleared_tail[w]
                 THEN \* second created:false after one retry: Conflict, no further retry, no delete
                      /\ UNCHANGED store
                      /\ pc' = [pc EXCEPT ![w] = "release"]
                      /\ outcome' = [outcome EXCEPT ![w] = "conflict_tail"]
                      /\ sawConflict' = TRUE
                      /\ created_by_us' = created_by_us
                      /\ cleared_tail' = cleared_tail
                      /\ sawTailDelete' = sawTailDelete
                      /\ deletedLiveTarget' = deletedLiveTarget
                 ELSE \* tail from an earlier interrupted attempt: best-effort delete, retry once
                      /\ \E keep \in {TRUE, FALSE} :
                           /\ store' = IF keep THEN store ELSE [store EXCEPT ![b] = "absent"]
                           /\ deletedLiveTarget' = IF keep THEN deletedLiveTarget
                                                    ELSE deletedLiveTarget \/ (row.exists /\ row.backend = b)
                      /\ cleared_tail' = [cleared_tail EXCEPT ![w] = TRUE]
                      /\ pc' = [pc EXCEPT ![w] = "transfer"]
                      /\ outcome' = outcome
                      /\ created_by_us' = created_by_us
                      /\ sawConflict' = sawConflict
                      /\ sawTailDelete' = TRUE
            ELSE \* pointer already moved: a concurrent migration claimed this path -- leave it untouched
                 /\ UNCHANGED store
                 /\ pc' = [pc EXCEPT ![w] = "release"]
                 /\ outcome' = [outcome EXCEPT ![w] = "conflict_tail"]
                 /\ sawConflict' = TRUE
                 /\ created_by_us' = created_by_us
                 /\ cleared_tail' = cleared_tail
                 /\ sawTailDelete' = sawTailDelete
                 /\ deletedLiveTarget' = deletedLiveTarget
    /\ UNCHANGED <<row, target, src_snap, cas_started, dpc, victim, rpc, rid, ans, sawTimeout,
                   genCounter, heldGen, committedGens, doubleCommit>>

\* G.9: the pre-CAS re-stat. A vanished/replaced object here (#5013's first
\* half, caught) means 503, CAS never attempted.
Stat(w) ==
    /\ pc[w] = "stat"
    /\ LET b == target[w] IN
       IF store[b] = "present"
       THEN /\ cas_started' = [cas_started EXCEPT ![w] = TRUE]
            /\ pc' = [pc EXCEPT ![w] = "cas"]
            /\ outcome' = outcome
       ELSE /\ UNCHANGED cas_started
            /\ pc' = [pc EXCEPT ![w] = "release"]
            /\ outcome' = [outcome EXCEPT ![w] = "unavailable"]
    /\ UNCHANGED <<row, store, target, src_snap, created_by_us, cleared_tail,
                   dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

\* G.10: rebind_version_backend's CAS, gated on the pre-migration snapshot
\* AND this attempt's own lease ownership. `cas_started` was already
\* stamped TRUE in Stat's success branch, immediately "before" this call --
\* matching backend.rs running right before the awaited CAS.
\* FixLeaseThroughCleanup = TRUE: the CAS itself no longer clears the lease
\* (`@` keeps `row.lease` unchanged, i.e. still `w` -- `ok` already requires
\* `row.lease = w`) -- it is released only later, by `Release(w)`, AFTER
\* `PostCommit(w)`'s source delete has run. FALSE: the unpatched code, which
\* cleared the lease in this SAME statement (G.12/G.14's root cause: a
\* second migrator can then acquire the now-free lease and commit onto the
\* same backend before this attempt's own, delayed source delete fires).
Commit(w) ==
    /\ pc[w] = "cas"
    /\ LET ok == row.exists /\ row.backend = src_snap[w] /\ row.lease = w IN
       IF ok
       THEN /\ row' = [row EXCEPT !.backend = target[w],
                                  !.lease = IF FixLeaseThroughCleanup THEN @ ELSE NoOwner]
            /\ pc' = [pc EXCEPT ![w] = "post_commit"]
            /\ doubleCommit' = IF heldGen[w] \in committedGens THEN TRUE ELSE doubleCommit
            /\ committedGens' = committedGens \union {heldGen[w]}
       ELSE /\ UNCHANGED row
            /\ pc' = [pc EXCEPT ![w] = "lost_refetch"]
            /\ UNCHANGED <<doubleCommit, committedGens>>
    /\ UNCHANGED <<store, target, src_snap, created_by_us, cas_started, cleared_tail,
                   outcome, dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, deletedLiveTarget>>

\* G.12: best-effort delete of the SOURCE blob after a won CAS. `row.backend`
\* is already `target[w]` (set in the same Commit step), never `src_snap[w]`
\* again, so this can never touch the live pointer (G4).
PostCommit(w) ==
    /\ pc[w] = "post_commit"
    /\ \E keep \in {TRUE, FALSE} :
         store' = IF keep THEN store ELSE [store EXCEPT ![src_snap[w]] = "absent"]
    /\ pc' = [pc EXCEPT ![w] = "release"]
    /\ outcome' = [outcome EXCEPT ![w] = "ok"]
    /\ UNCHANGED <<row, target, src_snap, created_by_us, cas_started, cleared_tail,
                   dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

\* G.11: lost-CAS recovery -- re-fetch and tell the three loss reasons apart.
LostRefetch(w) ==
    /\ pc[w] = "lost_refetch"
    /\ LET b == target[w] IN
       IF ~row.exists
       THEN \* genuine orphan: this attempt's own write, nobody's pointer -- best-effort delete it
            /\ \E keep \in {TRUE, FALSE} :
                 /\ store' = IF keep THEN store ELSE [store EXCEPT ![b] = "absent"]
                 /\ deletedLiveTarget' = IF keep THEN deletedLiveTarget
                                          ELSE deletedLiveTarget \/ (row.exists /\ row.backend = b)
            /\ outcome' = [outcome EXCEPT ![w] = "notfound"]
            /\ sawConflict' = sawConflict
       ELSE IF row.backend = b
            THEN \* same-target winner already committed: no-op success, NEVER delete (it's the winner's content)
                 /\ UNCHANGED store
                 /\ outcome' = [outcome EXCEPT ![w] = "ok"]
                 /\ sawConflict' = sawConflict
                 /\ deletedLiveTarget' = deletedLiveTarget
            ELSE \* a different migration won: this write cannot be live, best-effort delete it
                 /\ \E keep \in {TRUE, FALSE} :
                      /\ store' = IF keep THEN store ELSE [store EXCEPT ![b] = "absent"]
                      /\ deletedLiveTarget' = IF keep THEN deletedLiveTarget
                                               ELSE deletedLiveTarget \/ (row.exists /\ row.backend = b)
                 /\ outcome' = [outcome EXCEPT ![w] = "conflict_race"]
                 /\ sawConflict' = TRUE
    /\ pc' = [pc EXCEPT ![w] = "release"]
    /\ UNCHANGED <<row, target, src_snap, created_by_us, cas_started, cleared_tail,
                   dpc, victim, rpc, rid, ans, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit>>

\* G.13: best-effort lease release, outside the timeout wrapper, on every
\* exit path reached normally (owner-fenced: a lease already taken over is
\* left alone).
Release(w) ==
    /\ pc[w] = "release"
    /\ row' = IF row.lease = w THEN [row EXCEPT !.lease = NoOwner] ELSE row
    /\ pc' = [pc EXCEPT ![w] = "idle"]
    /\ target' = [target EXCEPT ![w] = NoBackend]
    /\ src_snap' = [src_snap EXCEPT ![w] = NoBackend]
    /\ created_by_us' = [created_by_us EXCEPT ![w] = FALSE]
    /\ cas_started' = [cas_started EXCEPT ![w] = FALSE]
    /\ cleared_tail' = [cleared_tail EXCEPT ![w] = FALSE]
    /\ UNCHANGED <<store, outcome, dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

\* G.14/G.Timeout: tokio::time::timeout elapses anywhere from G.7 through
\* G.12. The "cas" case is the documented ambiguous outcome (the CAS may
\* already have committed); no cleanup is attempted once cas_started = TRUE
\* ("transfer"/"stat" have it FALSE, the rest TRUE) -- this always still
\* proceeds to Release, since the release call is outside the timed block.
Timeout(w) ==
    /\ pc[w] \in {"transfer", "stat", "cas", "lost_refetch", "post_commit"}
    /\ LET b == target[w]
           ok == row.exists /\ row.backend = src_snap[w] /\ row.lease = w
       IN
       CASE pc[w] = "cas" ->
              \/ /\ ok
                 /\ row' = [row EXCEPT !.backend = b,
                                       !.lease = IF FixLeaseThroughCleanup THEN @ ELSE NoOwner]
                 /\ UNCHANGED store
                 /\ doubleCommit' = IF heldGen[w] \in committedGens THEN TRUE ELSE doubleCommit
                 /\ committedGens' = committedGens \union {heldGen[w]}
                 /\ UNCHANGED deletedLiveTarget
              \/ /\ UNCHANGED row
                 /\ UNCHANGED store
                 /\ UNCHANGED <<doubleCommit, committedGens, deletedLiveTarget>>
         [] pc[w] \in {"transfer", "stat"} ->
              /\ UNCHANGED row
              /\ UNCHANGED <<doubleCommit, committedGens>>
              /\ IF created_by_us[w]
                 THEN \E keep \in {TRUE, FALSE} :
                        /\ store' = IF keep THEN store ELSE [store EXCEPT ![b] = "absent"]
                        /\ deletedLiveTarget' = IF keep THEN deletedLiveTarget
                                                 ELSE deletedLiveTarget \/ (row.exists /\ row.backend = b)
                 ELSE /\ UNCHANGED store
                      /\ UNCHANGED deletedLiveTarget
         [] pc[w] = "lost_refetch" ->
              /\ UNCHANGED row
              /\ UNCHANGED <<doubleCommit, committedGens>>
              /\ IF (~row.exists) \/ row.backend # b
                 THEN \E keep \in {TRUE, FALSE} :
                        /\ store' = IF keep THEN store ELSE [store EXCEPT ![b] = "absent"]
                        /\ deletedLiveTarget' = IF keep THEN deletedLiveTarget
                                                 ELSE deletedLiveTarget \/ (row.exists /\ row.backend = b)
                 ELSE /\ UNCHANGED store
                      /\ UNCHANGED deletedLiveTarget
         [] pc[w] = "post_commit" ->
              \* excluded from G4 -- the G.12 family, see the VARIABLES comment
              /\ UNCHANGED row
              /\ UNCHANGED <<doubleCommit, committedGens, deletedLiveTarget>>
              /\ \E keep \in {TRUE, FALSE} :
                   store' = IF keep THEN store ELSE [store EXCEPT ![src_snap[w]] = "absent"]
    /\ outcome' = [outcome EXCEPT ![w] = "unavailable"]
    /\ pc' = [pc EXCEPT ![w] = "release"]
    /\ sawTimeout' = TRUE
    /\ UNCHANGED <<target, src_snap, created_by_us, cas_started, cleared_tail,
                   dpc, victim, rpc, rid, ans, sawConflict, sawTailDelete,
                   genCounter, heldGen>>

\* G.Cancel: the HTTP request future itself is dropped (client disconnect).
\* Reachable anywhere pc # "idle" (including lease-acquire and the release
\* call itself, which Timeout can never reach). Nothing downstream of the
\* drop point ever runs: no best-effort cleanup, no lease release -- only
\* whatever DB transaction was genuinely in flight resolves (same ambiguity
\* as Timeout's own "cas" case).
Cancel(w) ==
    /\ pc[w] # "idle"
    /\ LET b == target[w]
           ok == row.exists /\ row.backend = src_snap[w] /\ row.lease = w
       IN
       CASE pc[w] = "lease_wait" ->
              /\ UNCHANGED row /\ UNCHANGED store
              /\ UNCHANGED <<doubleCommit, committedGens, deletedLiveTarget>>
         [] pc[w] \in {"transfer", "stat"} ->
              /\ UNCHANGED row /\ UNCHANGED store
              /\ UNCHANGED <<doubleCommit, committedGens, deletedLiveTarget>>
         [] pc[w] = "cas" ->
              \/ /\ ok
                 /\ row' = [row EXCEPT !.backend = b,
                                       !.lease = IF FixLeaseThroughCleanup THEN @ ELSE NoOwner]
                 /\ UNCHANGED store
                 /\ doubleCommit' = IF heldGen[w] \in committedGens THEN TRUE ELSE doubleCommit
                 /\ committedGens' = committedGens \union {heldGen[w]}
                 /\ UNCHANGED deletedLiveTarget
              \/ /\ UNCHANGED row /\ UNCHANGED store
                 /\ UNCHANGED <<doubleCommit, committedGens, deletedLiveTarget>>
         [] pc[w] = "lost_refetch" ->
              /\ UNCHANGED row
              /\ UNCHANGED <<doubleCommit, committedGens>>
              /\ IF (~row.exists) \/ row.backend # b
                 THEN \E keep \in {TRUE, FALSE} :
                        /\ store' = IF keep THEN store ELSE [store EXCEPT ![b] = "absent"]
                        /\ deletedLiveTarget' = IF keep THEN deletedLiveTarget
                                                 ELSE deletedLiveTarget \/ (row.exists /\ row.backend = b)
                 ELSE /\ UNCHANGED store
                      /\ UNCHANGED deletedLiveTarget
         [] pc[w] = "post_commit" ->
              \* excluded from G4 -- the G.12 family, see the VARIABLES comment
              /\ UNCHANGED row
              /\ UNCHANGED <<doubleCommit, committedGens, deletedLiveTarget>>
              /\ \E keep \in {TRUE, FALSE} :
                   store' = IF keep THEN store ELSE [store EXCEPT ![src_snap[w]] = "absent"]
         [] pc[w] = "release" ->
              /\ UNCHANGED row /\ UNCHANGED store
              /\ UNCHANGED <<doubleCommit, committedGens, deletedLiveTarget>>
    /\ pc' = [pc EXCEPT ![w] = "idle"]
    /\ target' = [target EXCEPT ![w] = NoBackend]
    /\ src_snap' = [src_snap EXCEPT ![w] = NoBackend]
    /\ created_by_us' = [created_by_us EXCEPT ![w] = FALSE]
    /\ cas_started' = [cas_started EXCEPT ![w] = FALSE]
    /\ cleared_tail' = [cleared_tail EXCEPT ![w] = FALSE]
    /\ outcome' = [outcome EXCEPT ![w] = "cancelled"]
    /\ UNCHANGED <<dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen>>

(***************************** deleters (G.D) *******************************)

\* G.D1: delete_version's own transaction -- the row-delete and the
\* snapshot of which backend to blob-delete are atomic with each other (the
\* real transaction re-reads backend_id immediately before its own DELETE).
DeleteStep1(d) ==
    /\ dpc[d] = "idle"
    /\ row.exists
    /\ victim' = [victim EXCEPT ![d] = row.backend]
    /\ row' = [row EXCEPT !.exists = FALSE]
    /\ dpc' = [dpc EXCEPT ![d] = "pending_blob"]
    /\ UNCHANGED <<store, pc, target, src_snap, created_by_us, cas_started, cleared_tail,
                   outcome, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

\* G.D2: the service layer's best-effort blob delete, after the transaction committed.
DeleteStep2(d) ==
    /\ dpc[d] = "pending_blob"
    /\ \E keep \in {TRUE, FALSE} :
         /\ store' = IF keep THEN store ELSE [store EXCEPT ![victim[d]] = "absent"]
         /\ deletedLiveTarget' = IF keep THEN deletedLiveTarget
                                  ELSE deletedLiveTarget \/ (row.exists /\ row.backend = victim[d])
    /\ dpc' = [dpc EXCEPT ![d] = "done"]
    /\ UNCHANGED <<row, pc, target, src_snap, created_by_us, cas_started, cleared_tail,
                   outcome, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit>>

(***************************** readers (G.R) ********************************)

RSnapshot(r) ==
    /\ rpc[r] \in {"idle", "done"}
    /\ rid' = [rid EXCEPT ![r] = row.backend]
    /\ rpc' = [rpc EXCEPT ![r] = "pending"]
    /\ UNCHANGED <<row, store, pc, target, src_snap, created_by_us, cas_started, cleared_tail,
                   outcome, dpc, victim, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

RGet(r) ==
    /\ rpc[r] = "pending"
    /\ LET v == store[rid[r]] IN
       ans' = [ans EXCEPT ![r] = CASE v = "present" -> "hit"
                                    [] v = "foreign" -> "hit_bad"
                                    [] v = "absent"  -> "miss"]
    /\ rpc' = [rpc EXCEPT ![r] = "done"]
    /\ UNCHANGED <<row, store, pc, target, src_snap, created_by_us, cas_started, cleared_tail,
                   outcome, dpc, victim, rid, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

(***************************** external actor (G.X, #5013) ******************)

Tamper(b) ==
    /\ ExternalActor
    /\ store[b] \in {"present", "foreign"}
    /\ \E s \in ({"absent", "foreign"} \ {store[b]}) :
         store' = [store EXCEPT ![b] = s]
    /\ UNCHANGED <<row, pc, target, src_snap, created_by_us, cas_started, cleared_tail,
                   outcome, dpc, victim, rpc, rid, ans, sawConflict, sawTimeout, sawTailDelete,
                   genCounter, heldGen, committedGens, doubleCommit, deletedLiveTarget>>

Next ==
    \/ \E w \in Migrators : Start(w) \/ AcquireLease(w) \/ Transfer(w) \/ Stat(w)
                            \/ Commit(w) \/ PostCommit(w) \/ LostRefetch(w)
                            \/ Release(w) \/ Timeout(w) \/ Cancel(w)
    \/ LeaseExpire
    \/ \E d \in Deleters : DeleteStep1(d) \/ DeleteStep2(d)
    \/ \E r \in Readers : RSnapshot(r) \/ RGet(r)
    \/ \E b \in Backends : Tamper(b)

Spec == Init /\ [][Next]_vars

\* Model-checking-only bound: `Start` is re-enabled from "idle" forever (a
\* migrator may attempt the operation again after any outcome, matching the
\* real client's own retry-on-409/503 behaviour), and a FRESH `AcquireLease`
\* win mints a new, never-reused `genCounter` every time -- so the reachable
\* state space is genuinely infinite without some bound, exactly like
\* `MaxTick`/`MaxVersion`/`MaxWrites` bound the other clocks/counters in the
\* sibling models (FileStorageUpload.tla, FileStorageMultipart.tla). `MaxGen`
\* is that bound for this model's one unbounded counter; TLC is run with
\* `CONSTRAINT GenConstraint` (see the .cfg files) so a small `MaxGen` still
\* lets every migrator retry several times (enough depth for every finding
\* and mutation below) while keeping the search finite and exhaustive.
GenConstraint == genCounter <= MaxGen

------------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ row \in [exists : BOOLEAN, backend : Backends, lease : Migrators \cup {NoOwner}]
    /\ store \in [Backends -> {"absent", "present", "foreign"}]
    /\ pc \in [Migrators -> PCs]
    /\ target \in [Migrators -> Backends \cup {NoBackend}]
    /\ src_snap \in [Migrators -> Backends \cup {NoBackend}]
    /\ created_by_us \in [Migrators -> BOOLEAN]
    /\ cas_started \in [Migrators -> BOOLEAN]
    /\ cleared_tail \in [Migrators -> BOOLEAN]
    /\ outcome \in [Migrators -> Outcomes]
    /\ dpc \in [Deleters -> DPCs]
    /\ victim \in [Deleters -> Backends \cup {NoBackend}]
    /\ rpc \in [Readers -> RPCs]
    /\ rid \in [Readers -> Backends \cup {NoBackend}]
    /\ ans \in [Readers -> {"none", "hit", "hit_bad", "miss"}]
    /\ sawConflict \in BOOLEAN
    /\ sawTimeout \in BOOLEAN
    /\ sawTailDelete \in BOOLEAN
    /\ genCounter \in Nat
    /\ heldGen \in [Migrators -> Nat]
    /\ committedGens \subseteq Nat
    /\ doubleCommit \in BOOLEAN
    /\ deletedLiveTarget \in BOOLEAN

\* G1: the live row's pointer always names an object with this version's
\* correct bytes. With `FixLeaseThroughCleanup = FALSE` (the unpatched code),
\* violated by the G.12 finding (states-migration.md): a stale post-commit
\* source delete can race a later migration back onto the same backend --
\* see `FileStorageMigration_G12.cfg`. With `FixLeaseThroughCleanup = TRUE`
\* (the shipped fix: the CAS no longer clears the lease, so a second
\* migrator cannot even acquire it until this one's own post-commit cleanup
\* has run) and `ExternalActor = FALSE`, expected to HOLD -- part of the
\* main/medium invariant list. With `ExternalActor = TRUE`, still expected to
\* be a reachable witness regardless of the fix (#5013, outside this gear's
\* own coordination by definition) -- see `FileStorageMigration_ExternalActor.cfg`.
G1_NoDanglingPointer ==
    row.exists => store[row.backend] = "present"

\* G2/G3: the lease makes at most one migrator's CAS win per generation --
\* phase 1 observed that `row.lease` being single-valued makes this
\* trivially true *by representation* in this one-row model, so both names
\* are backed by the same independent ghost mechanism instead of relying on
\* that representational accident: `genCounter`/`heldGen` give every
\* successful `AcquireLease` its own generation number, `committedGens`
\* accumulates every generation that ever won its CAS (Commit/Timeout's
\* "cas" ambiguous-committed branch/Cancel's "cas" ambiguous-committed
\* branch -- the three places `ok` is checked and `Apply`'d), and
\* `doubleCommit` latches if the SAME generation ever wins twice. G2 and G3
\* are deliberately the same check (see states-migration.md) -- confirmed a
\* real, load-bearing guard by the `m_nolease` mutation (phase 1): dropping
\* `row.lease = w` from `ok` is caught by G1 at depth 13; it is caught by
\* THIS ghost mechanism too (phase 2 reruns it as `m5`).
G2_LeaseExclusive ==
    ~doubleCommit
G3_NoCommitWithoutLease ==
    ~doubleCommit

\* G4: no tail/loser/timeout-recovery delete (G.8, G.11, Timeout/Cancel's
\* "transfer"/"stat"/"lost_refetch" branches, G.D2) ever targets the
\* then-current live backend. Deliberately does NOT cover G.12's own
\* post-commit source delete (PostCommit, and Timeout/Cancel's
\* "post_commit" branch) -- that family's gap is the separately-reported
\* G.12/G.14 finding (states-migration.md), and folding it into this
\* invariant would just re-trip it immediately when
\* `FixLeaseThroughCleanup = FALSE`. G.14 (states-migration.md) is this same
\* invariant, found with G1 excluded: a timeout's own best-effort cleanup of
\* its OWN not-yet-committed write (`created_by_us`) does not recheck
\* whether the row's pointer has, meanwhile, come to equal that exact
\* backend through a G.12-style chain -- see `FileStorageMigration_G14.cfg`
\* (`FixLeaseThroughCleanup = FALSE`). With `FixLeaseThroughCleanup = TRUE`,
\* the SAME fix closes this too (holding the lease from `AcquireLease`
\* through `Release` serializes every migrator attempting this one version,
\* so nothing can change `row.backend` out from under a migrator that still
\* holds the lease) -- expected to HOLD, part of the main/medium list.
G4_TailDeleteSafe ==
    ~deletedLiveTarget

\* G5: a finished reader never reads foreign (wrong) bytes through a still-
\* live pointer. `miss` is availability, never a violation (see
\* states-migration.md). Same ExternalActor-gated expectation as G1 (same
\* root cause, not an independent bug).
G5_ReadExactOrMiss ==
    \A r \in Readers : rpc[r] = "done" => ans[r] # "hit_bad"

\* G7, "at rest": once every in-flight migrator and deleter has gone back
\* to idle/done (no best-effort cleanup still pending) and the version is
\* gone, no backend may still hold its bytes. NOT expected to hold in
\* general -- a failed best-effort delete (G.12 or G.D2, both
\* nondeterministic in this model exactly as `best_effort_blob_delete` can
\* silently fail in the real code) is the known, accepted residual #5106,
\* and nothing ever retries it (no sweep candidate covers this). Run as a
\* witness: expected to be reachable-violated, and the trace should show
\* nothing worse than that one known residual shape.
Quiescent ==
    /\ \A w \in Migrators : pc[w] = "idle"
    /\ \A d \in Deleters : dpc[d] \in {"idle", "done"}
G7_DeleteVsMigrate_AtRest ==
    (Quiescent /\ ~row.exists) => (\A b \in Backends : store[b] # "present")

\* Witnesses -- NOT safety invariants: each is expected to be VIOLATED by
\* TLC, confirming the scenario is actually reachable in this model (a
\* vacuously-always-TRUE "invariant" would prove nothing). See
\* states-migration.md / the agent's report for the counterexample traces.
Wit_NoConflict   == ~sawConflict     \* "migration never gets a 409-shaped conflict"
Wit_NoTimeout    == ~sawTimeout      \* "the timeout never fires"
Wit_NoTailDelete == ~sawTailDelete   \* "the destination tail is never deleted"

\* SYMMETRY (invariants only -- never combine with a PROPERTIES/temporal
\* check in the same run): Migrators are interchangeable since none of
\* Start's target choice, AcquireLease, or any later step distinguishes one
\* migrator identity from another except through the shared `row`/`store`.
Symm == Permutations(Migrators)

==============================================================================
