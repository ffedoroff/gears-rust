--------------------------- MODULE FileStorageMultipart ---------------------------
(***************************************************************************)
(* One multipart-upload session (file-storage control plane, upload-flow   *)
(* redesign): session state in {in_progress, completing, completed,        *)
(* aborted}; a plan of `Parts` parts, each with a physical backend         *)
(* register (`physPart`, written by the sidecar's per-part PUT, M.2) and a *)
(* DB-recorded row (`dbPart`, written by `report_part`, M.3). Step ids     *)
(* (M.x, MS.x) refer to `states-multipart.md` in this directory.           *)
(*                                                                         *)
(* FenceSamePart: FALSE reproduces the shipped `upsert_multipart_part`     *)
(* exactly (#5103 -- last-write-wins on the DB row, no check against the   *)
(* physical register); TRUE is the hypothetical fix (a report is dropped,  *)
(* not applied, once the physical register has moved past the etag the    *)
(* report carries).                                                       *)
(*                                                                         *)
(* NativeBackend: TRUE models the shipped S3/in-memory backends, whose     *)
(* `complete_multipart` (M.4.8.5) validates every part's DB-recorded etag  *)
(* against the backend's own current per-part register before assembling  *)
(* anything (a mismatch fails the whole call, nothing is assembled).       *)
(* FALSE models the hypothetical, currently-unreachable (see              *)
(* states-multipart.md, Discrepancy #1) offset-object backend, whose       *)
(* `complete_multipart` would have no such check.                         *)
(*                                                                         *)
(* Phase 2 additions: `returnedManifest`/`returnedAvailable` (per          *)
(* completer -- what its own HTTP response would show), `ReplayCompleted`  *)
(* (M.4.2's direct replay path, no lease needed), `completedSnapshot*`     *)
(* (frozen at the instant the session first reaches `completed`), and      *)
(* `staleRebindHappened` (did our own auto-bind CAS ever overwrite the     *)
(* pointer despite `contentPtr # boundTarget[c]` -- only reachable under   *)
(* mutation m5). See M9-M13 below.                                        *)
(*                                                                         *)
(* Not modelled: PDP/policy/quota checks, MIME sniffing, backend selection *)
(* and its three-way (version / session / default) fallback, audit rows,  *)
(* the REST/SDK status codes themselves (a terminal step is just "done"), *)
(* the orphan-file (zero-version `files` row) reclaim, retention/          *)
(* idempotency-key sweep phases, and every step of plain single-part       *)
(* upload (a separate protocol). `Uploaders` has no identity of its own:   *)
(* a physical write's effect never depends on *who* performed it, only on  *)
(* `(part, value)`, so `PhysicalWrite` is parameterized directly on those  *)
(* instead of tracking per-uploader program counters (a pure simplification,*)
(* loses no reachable interleaving of writes-vs-reports).                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Parts,              \* fixed small part plan, e.g. {p1, p2}
    Values,             \* distinct byte contents a part can physically hold
    Completers,         \* actors that may call `complete`
    FenceSamePart,      \* BOOLEAN -- hypothetical report-vs-physical fencing
    NativeBackend,      \* BOOLEAN -- S3-style per-part etag check at assembly
    SessionExpiresAt,   \* abstract clock tick at which the session itself expires
    LeaseDuration,       \* completion-lease length in clock ticks
    MaxTick,            \* clock upper bound (TLC finiteness)
    MaxWrites,          \* bound on total physical per-part writes (TLC finiteness)
    FixCloseFromInProgress, \* TRUE = current code (`MultipartRepo::finish_complete`'s
                            \* embedded, owner-blind CAS -- `expected_owner = None`
                            \* -- now matches `state IN ('completing', 'in_progress')`,
                            \* not just `'completing'`). FALSE = the unpatched code
                            \* (`'completing'` only) -- M7.
    FixDeleteAssembledObject \* TRUE = current code: (a) `MultipartService`'s complete
                             \* path best-effort deletes the backend object when
                             \* `finalize_multipart_version` rejects with "session is
                             \* no longer completing (aborted by cleanup)"; (b) the
                             \* sweep's `delete_pending_version` success path ALSO
                             \* best-effort deletes the version's backend object (on
                             \* top of the pre-existing `abort_multipart` call).
                             \* FALSE = the unpatched code (neither call exists) --
                             \* M8, deep shape.

ASSUME FenceSamePart \in BOOLEAN
ASSUME NativeBackend \in BOOLEAN
ASSUME SessionExpiresAt \in Nat
ASSUME LeaseDuration \in Nat \ {0}
ASSUME MaxTick \in Nat
ASSUME MaxWrites \in Nat
ASSUME FixCloseFromInProgress \in BOOLEAN
ASSUME FixDeleteAssembledObject \in BOOLEAN

NoVal   == "novalue"      \* a part not (yet) written / reported
NoOwner == "noowner"
NoPart  == [val |-> NoVal, etag |-> 0]

SessStates == {"in_progress", "completing", "completed", "aborted"}
PCs        == {"idle", "assemble", "finalize", "converge", "done"}
PtrVals    == {"none", "this", "other"}

(* All (part, value, etag) triples a physical write could ever produce --
   finite, so `pendingReports` (a SUBSET of this) is a legal TLC variable. *)
ReportRecs == [part : Parts, val : Values, etag : 1..MaxWrites]

VARIABLES
    sessState,          \* multipart_uploads.state
    leaseOwner,          \* multipart_uploads.lease_owner (Completers \cup {NoOwner})
    leaseUntil,          \* multipart_uploads.lease_until (clock tick, 0 = none)
    clock,               \* abstract shared clock (DB "now")
    dbPart,              \* [Parts -> [val, etag]]: multipart_upload_part rows (M.3.4)
    physPart,            \* [Parts -> [val, etag]]: backend physical register (M.2)
    physEtagCounter,     \* monotonic counter minting fresh physical etags
    pendingReports,      \* SUBSET ReportRecs: in-flight report_part deliveries
    backendObjectExists, \* the backend's final assembled object exists (M.4.8.5)
    backendAssembledObject, \* [Parts -> Values \cup {NoVal}]: its real bytes
    assembledManifest,   \* [Parts -> Values \cup {NoVal}]: manifest built from dbPart
                         \* at the SAME instant backendObjectExists first flips TRUE
    versionAvailable,    \* file_versions.status = available (M.4.8.8 step 2 CAS)
    completedManifest,   \* [Parts -> Values \cup {NoVal}]: persisted at finalize time
    completedCount,      \* M2 ghost: how many times the version CAS has won
    contentPtr,          \* files.content_id, relative to this session's version
    boundTarget,         \* [Completers -> PtrVals]: contentPtr snapshot at acquire-lease
    ctakeover,           \* [Completers -> BOOLEAN]: session was already `completing`
    pc,                  \* per-completer program counter
    backendCleaned,      \* M.5/MS.2's best-effort backend.abort_multipart has run
    pendingVersionDeleted, \* M.5/MS.2's delete_pending_version has run
    partsWiped,          \* ghost: dbPart was ever wiped by an abort CAS (M.5/MS.1-2)
    physWiped,           \* ghost: physPart was ever wiped by SweepCleanupBackend
    standaloneClosedBy,  \* M3 ghost: which completer closed the session via M.4.8.10
    standaloneClosedLeaseOwner, \* M3 ghost: leaseOwner at that same instant
    everTakeover,        \* W2 ghost
    everSweepAborted,    \* W3 ghost
    returnedManifest,    \* [Completers -> [Parts -> Values \cup {NoVal}]]: M9/M10 ghost --
                         \* what each completer's own HTTP response reported
    returnedAvailable,   \* [Completers -> BOOLEAN]: M9/M10 ghost -- did it report success
    completedSnapshotManifest, \* M11 ghost: completedManifest frozen the instant
                               \* sessState first became "completed"
    completedSnapshotAvailable, \* M11 ghost: set once, true after that instant
    staleRebindHappened, \* M12 ghost: our own auto-bind CAS ever overwrote
                         \* contentPtr despite contentPtr # boundTarget[c] (only
                         \* reachable under mutation m5)
    liveLeaseStolen,     \* M14 ghost: AcquireLease ever succeeded against a
                         \* DIFFERENT owner's still-live lease (only reachable
                         \* under mutation m3)
    deepCleanupAttempted \* ghost, monotonic: `FixDeleteAssembledObject`'s delete
                         \* (site (a) in `Finalize`'s "aborted" branch, or site
                         \* (b) in `SweepDeletePendingVersion`) was ever actually
                         \* ATTEMPTED against a real assembled object
                         \* (`backendObjectExists = TRUE` at that instant) --
                         \* distinguishes "attempted, best-effort call may still
                         \* have failed" (same residual class as M8 shallow) from
                         \* "no code path ever tried" (the pre-fix bug). See
                         \* `M8_DeepOrphan_NotReachable`'s own doc comment.

vars == <<sessState, leaseOwner, leaseUntil, clock, dbPart, physPart,
          physEtagCounter, pendingReports, backendObjectExists,
          backendAssembledObject, assembledManifest, versionAvailable,
          completedManifest, completedCount, contentPtr, boundTarget,
          ctakeover, pc, backendCleaned, pendingVersionDeleted, partsWiped,
          physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
          everTakeover, everSweepAborted, returnedManifest, returnedAvailable,
          completedSnapshotManifest, completedSnapshotAvailable,
          staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

AutoBind == TRUE  \* this session always requested bind:"auto" (exercises M6)

Symm == Permutations(Completers)   \* optional SYMMETRY (INVARIANTS only, not PROPERTIES)

Init ==
    /\ sessState = "in_progress"
    /\ leaseOwner = NoOwner
    /\ leaseUntil = 0
    /\ clock = 0
    /\ dbPart = [p \in Parts |-> NoPart]
    /\ physPart = [p \in Parts |-> NoPart]
    /\ physEtagCounter = 0
    /\ pendingReports = {}
    /\ backendObjectExists = FALSE
    /\ backendAssembledObject = [p \in Parts |-> NoVal]
    /\ assembledManifest = [p \in Parts |-> NoVal]
    /\ versionAvailable = FALSE
    /\ completedManifest = [p \in Parts |-> NoVal]
    /\ completedCount = 0
    /\ contentPtr = "none"
    /\ boundTarget = [c \in Completers |-> "none"]
    /\ ctakeover = [c \in Completers |-> FALSE]
    /\ pc = [c \in Completers |-> "idle"]
    /\ backendCleaned = FALSE
    /\ pendingVersionDeleted = FALSE
    /\ partsWiped = FALSE
    /\ physWiped = FALSE
    /\ standaloneClosedBy = NoOwner
    /\ standaloneClosedLeaseOwner = NoOwner
    /\ everTakeover = FALSE
    /\ everSweepAborted = FALSE
    /\ returnedManifest = [c \in Completers |-> [p \in Parts |-> NoVal]]
    /\ returnedAvailable = [c \in Completers |-> FALSE]
    /\ completedSnapshotManifest = [p \in Parts |-> NoVal]
    /\ completedSnapshotAvailable = FALSE
    /\ staleRebindHappened = FALSE
    /\ liveLeaseStolen = FALSE
    /\ deepCleanupAttempted = FALSE

(***************************** M.2 -- physical part write ******************)
PhysicalWrite(p, v) ==
    /\ sessState \in {"in_progress", "completing"}   \* see states-multipart.md
                                                      \* "not modelled": writes
                                                      \* after abort/complete
    /\ physEtagCounter < MaxWrites
    /\ LET newEtag == physEtagCounter + 1 IN
       /\ physEtagCounter' = newEtag
       /\ physPart' = [physPart EXCEPT ![p] = [val |-> v, etag |-> newEtag]]
       /\ pendingReports' = pendingReports \cup {[part |-> p, val |-> v, etag |-> newEtag]}
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, clock, dbPart,
                   backendObjectExists, backendAssembledObject, assembledManifest,
                   versionAvailable, completedManifest, completedCount, contentPtr,
                   boundTarget, ctakeover, pc, backendCleaned, pendingVersionDeleted,
                   partsWiped, physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(***************************** M.3.4 -- report_part delivery ***************)
DeliverReport(rep) ==
    /\ rep \in pendingReports
    /\ sessState = "in_progress"      \* upsert_part's self-CAS guard
    /\ pendingReports' = pendingReports \ {rep}
    /\ IF FenceSamePart /\ physPart[rep.part].etag # rep.etag
       THEN UNCHANGED dbPart          \* hypothetical fix: stale report dropped
       ELSE dbPart' = [dbPart EXCEPT ![rep.part] = [val |-> rep.val, etag |-> rep.etag]]
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, clock, physPart,
                   physEtagCounter, backendObjectExists, backendAssembledObject,
                   assembledManifest, versionAvailable, completedManifest,
                   completedCount, contentPtr, boundTarget, ctakeover, pc,
                   backendCleaned, pendingVersionDeleted, partsWiped, physWiped,
                   standaloneClosedBy, standaloneClosedLeaseOwner, everTakeover,
                   everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(***************************** M.4.6 -- acquire/takeover lease *************)
AcquireLease(c) ==
    /\ pc[c] = "idle"
    /\ clock < SessionExpiresAt
    /\ \/ sessState = "in_progress"
       \/ /\ sessState = "completing"
          /\ clock >= leaseUntil
    /\ ctakeover' = [ctakeover EXCEPT ![c] = (sessState = "completing")]
    /\ everTakeover' = (everTakeover \/ (sessState = "completing"))
    /\ boundTarget' = [boundTarget EXCEPT ![c] = contentPtr]
    /\ liveLeaseStolen' = (liveLeaseStolen \/
                            (sessState = "completing" /\ clock < leaseUntil /\ leaseOwner # c))
    /\ sessState' = "completing"
    /\ leaseOwner' = c
    /\ leaseUntil' = clock + LeaseDuration
    /\ pc' = [pc EXCEPT ![c] = "assemble"]
    /\ UNCHANGED <<clock, dbPart, physPart, physEtagCounter, pendingReports,
                   backendObjectExists, backendAssembledObject, assembledManifest,
                   versionAvailable, completedManifest, completedCount, contentPtr,
                   backendCleaned, pendingVersionDeleted, partsWiped, physWiped,
                   standaloneClosedBy, standaloneClosedLeaseOwner, everSweepAborted,
                   returnedManifest, returnedAvailable, completedSnapshotManifest,
                   completedSnapshotAvailable, staleRebindHappened, deepCleanupAttempted>>

(***************************** M.4.8.1 / M.4.8.2 / M.4.8.5 -- assemble *****)
AllPartsReported == \A p \in Parts : dbPart[p].val # NoVal

EtagsMatchPhysical == \A p \in Parts : dbPart[p].etag = physPart[p].etag

Assemble(c) ==
    /\ pc[c] = "assemble"
    /\ IF versionAvailable
       THEN  \* M.4.8.1 already-Available fast path -> converge
             /\ pc' = [pc EXCEPT ![c] = "converge"]
             /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, dbPart, physPart,
                            backendObjectExists, backendAssembledObject,
                            assembledManifest>>
       ELSE IF ~AllPartsReported
            THEN  \* M.4.8.2 missing parts -> hard error, this attempt is done
                  /\ pc' = [pc EXCEPT ![c] = "done"]
                  /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, dbPart,
                                 physPart, backendObjectExists,
                                 backendAssembledObject, assembledManifest>>
            ELSE IF backendObjectExists
                 THEN  \* the handle was already consumed by an earlier completer
                       IF ctakeover[c]
                       THEN  \* M.4.8.5 takeover recovery: converge locally, no new backend call
                             /\ pc' = [pc EXCEPT ![c] = "finalize"]
                             /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, dbPart,
                                            physPart, backendObjectExists,
                                            backendAssembledObject, assembledManifest>>
                       ELSE  \* not a takeover: propagate the backend error, stuck
                             /\ pc' = [pc EXCEPT ![c] = "done"]
                             /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, dbPart,
                                            physPart, backendObjectExists,
                                            backendAssembledObject, assembledManifest>>
                 ELSE IF NativeBackend /\ ~EtagsMatchPhysical
                      THEN  \* M.4.8.5 native: S3 CompleteMultipartUpload rejects a
                            \* stale/mismatched part etag -- nothing assembled;
                            \* release the lease (best-effort, owner-scoped) so a
                            \* later complete can retry once a fresh report lands.
                            /\ pc' = [pc EXCEPT ![c] = "idle"]
                            /\ IF sessState = "completing" /\ leaseOwner = c
                               THEN /\ sessState' = "in_progress"
                                    /\ leaseOwner' = NoOwner
                                    /\ leaseUntil' = 0
                               ELSE UNCHANGED <<sessState, leaseOwner, leaseUntil>>
                            /\ UNCHANGED <<dbPart, physPart, backendObjectExists,
                                           backendAssembledObject, assembledManifest>>
                      ELSE  \* M.4.8.5 succeeds: physically assemble the object NOW,
                            \* independent of any later DB transaction.
                            /\ backendObjectExists' = TRUE
                            /\ backendAssembledObject' = [p \in Parts |-> physPart[p].val]
                            /\ assembledManifest' = [p \in Parts |-> dbPart[p].val]
                            /\ pc' = [pc EXCEPT ![c] = "finalize"]
                            /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, dbPart, physPart>>
    /\ UNCHANGED <<clock, physEtagCounter, pendingReports, versionAvailable,
                   completedManifest, completedCount, contentPtr, boundTarget,
                   ctakeover, backendCleaned, pendingVersionDeleted, partsWiped,
                   physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(***************************** M.4.8.8 -- finalize_multipart_version *******)
(* One atomic PG transaction: lock_session_state, version CAS, (manifest), *)
(* auto-bind CAS, finish_complete(owner-blind).                            *)
(*                                                                         *)
(* MUTATION m1 target: the first `IF sessState = "aborted" THEN reject`    *)
(* branch below is `lock_session_state`'s own "reclaimed by cleanup" guard *)
(* -- m1 deletes this whole branch (falls through to the versionAvailable  *)
(* check unconditionally instead).                                        *)
(*                                                                         *)
(* MUTATION m2 target: the embedded, deliberately owner-blind session-     *)
(* close below (`sessState = "completing"` with no owner check) is what    *)
(* `f2_stale_completer_converges_instead_of_stranding_after_owner_fencing_  *)
(* fix` protects -- m2 adds `/\ leaseOwner = c` to that same condition.    *)
(*                                                                         *)
(* MUTATION m5 target: the auto-bind CAS `contentPtr = boundTarget[c]`     *)
(* inside the bind IF below -- m5 removes it (binds unconditionally).      *)
(*                                                                         *)
(* FIX M7 (`FixCloseFromInProgress`): the embedded session-close CAS        *)
(* (`MultipartRepo::finish_complete`, `expected_owner = None`) now also     *)
(* matches `state = "in_progress"`, not just `"completing"` -- closing the  *)
(* session even when an intervening takeover's own failed attempt already   *)
(* released the lease back to `in_progress` moments before this call's      *)
(* version CAS won. `CanEmbeddedClose` below is the only thing this fix     *)
(* changes; `FALSE` reproduces the unpatched `state = "completing"`-only    *)
(* condition (M7: `sessState` is left stuck `in_progress` forever even      *)
(* though the version is now genuinely available and bound).               *)
(*                                                                         *)
(* FIX M8-deep, site (a) (`FixDeleteAssembledObject`): when this call's own  *)
(* backend-side assembly already succeeded (`pc[c] = "finalize"` is only    *)
(* reached via `Assemble`'s success/takeover-recovery branches, so           *)
(* `backendObjectExists` is always already TRUE here) but the transaction    *)
(* is rejected because the abandoned-session sweep already reclaimed         *)
(* (aborted) this session -- `MultipartService`'s own match on                *)
(* `MULTIPART_SESSION_RECLAIMED_BY_CLEANUP_MESSAGE` -- best-effort delete the *)
(* now-orphaned backend object. `FALSE` reproduces the unpatched code (no     *)
(* cleanup attempted here at all) -- M8, deep shape.                          *)
Finalize(c) ==
    /\ pc[c] = "finalize"
    /\ IF sessState = "aborted"
       THEN  \* lock_session_state sees `aborted` -> whole transaction rejected;
             \* the physical object assembled in the preceding Assemble step is
             \* NOT rolled back (it was never part of this transaction).
             /\ pc' = [pc EXCEPT ![c] = "done"]
             /\ IF FixDeleteAssembledObject
                THEN \E ok \in BOOLEAN :
                       /\ backendObjectExists' = IF ok THEN FALSE ELSE backendObjectExists
                       /\ deepCleanupAttempted' = TRUE
                ELSE UNCHANGED <<backendObjectExists, deepCleanupAttempted>>
             /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, versionAvailable,
                            completedManifest, completedCount, contentPtr,
                            returnedManifest, returnedAvailable,
                            completedSnapshotManifest, completedSnapshotAvailable,
                            staleRebindHappened, liveLeaseStolen>>
       ELSE IF versionAvailable
            THEN  \* lost the version CAS (someone else already finalized it)
                  /\ pc' = [pc EXCEPT ![c] = "converge"]
                  /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, versionAvailable,
                                 completedManifest, completedCount, contentPtr,
                                 returnedManifest, returnedAvailable,
                                 completedSnapshotManifest, completedSnapshotAvailable,
                                 staleRebindHappened, liveLeaseStolen,
                                 backendObjectExists, deepCleanupAttempted>>
            ELSE  \* wins the version CAS
                  /\ versionAvailable' = TRUE
                  /\ completedManifest' = assembledManifest
                  /\ completedCount' = completedCount + 1
                  /\ returnedManifest' = [returnedManifest EXCEPT ![c] = assembledManifest]
                  /\ returnedAvailable' = [returnedAvailable EXCEPT ![c] = TRUE]
                  /\ IF AutoBind
                     THEN IF contentPtr = boundTarget[c]
                          THEN /\ contentPtr' = "this"
                               /\ UNCHANGED staleRebindHappened
                          ELSE /\ UNCHANGED contentPtr   \* CAS lost: Conflict, no overwrite
                               /\ UNCHANGED staleRebindHappened
                     ELSE /\ UNCHANGED contentPtr
                          /\ UNCHANGED staleRebindHappened
                  /\ LET CanEmbeddedClose ==
                         IF FixCloseFromInProgress
                         THEN sessState \in {"completing", "in_progress"}
                         ELSE sessState = "completing"
                     IN
                     IF CanEmbeddedClose
                     THEN /\ sessState' = "completed"
                          /\ leaseOwner' = NoOwner
                          /\ leaseUntil' = 0
                          /\ completedSnapshotManifest' =
                                IF completedSnapshotAvailable
                                THEN completedSnapshotManifest ELSE assembledManifest
                          /\ completedSnapshotAvailable' = TRUE
                     ELSE /\ UNCHANGED <<sessState, leaseOwner, leaseUntil>>
                          /\ UNCHANGED <<completedSnapshotManifest, completedSnapshotAvailable>>
                  /\ pc' = [pc EXCEPT ![c] = "done"]
                  /\ UNCHANGED <<backendObjectExists, deepCleanupAttempted>>
    /\ UNCHANGED <<clock, dbPart, physPart, physEtagCounter, pendingReports,
                   backendAssembledObject, assembledManifest,
                   boundTarget, ctakeover, backendCleaned, pendingVersionDeleted,
                   partsWiped, physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, everSweepAborted, liveLeaseStolen>>

(***************************** M.4.8.9/10 -- converge (standalone close) ***)
(* MUTATION m2's counterpart does NOT touch this action (it is already     *)
(* owner-fenced, by design -- m2 only fences the EMBEDDED close above).    *)
Converge(c) ==
    /\ pc[c] = "converge"
    /\ IF sessState = "completing" /\ leaseOwner = c
       THEN /\ sessState' = "completed"
            /\ leaseOwner' = NoOwner
            /\ leaseUntil' = 0
            /\ standaloneClosedBy' = c
            /\ standaloneClosedLeaseOwner' = leaseOwner  \* = c, by this branch's own guard
            /\ returnedManifest' = [returnedManifest EXCEPT ![c] = completedManifest]
            /\ returnedAvailable' = [returnedAvailable EXCEPT ![c] = TRUE]
            /\ completedSnapshotManifest' =
                  IF completedSnapshotAvailable THEN completedSnapshotManifest ELSE completedManifest
            /\ completedSnapshotAvailable' = TRUE
       ELSE IF sessState = "completed"
            THEN  \* someone else already closed it -- converge silently, success
                  /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, standaloneClosedBy,
                                 standaloneClosedLeaseOwner>>
                  /\ returnedManifest' = [returnedManifest EXCEPT ![c] = completedManifest]
                  /\ returnedAvailable' = [returnedAvailable EXCEPT ![c] = TRUE]
                  /\ UNCHANGED <<completedSnapshotManifest, completedSnapshotAvailable>>
            ELSE  \* genuine error (e.g. reclaimed by cleanup in the meantime
                  \* -- Discrepancy #3/M7): no success recorded, nothing changes
                  /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, standaloneClosedBy,
                                 standaloneClosedLeaseOwner>>
                  /\ UNCHANGED <<returnedManifest, returnedAvailable>>
                  /\ UNCHANGED <<completedSnapshotManifest, completedSnapshotAvailable>>
    /\ pc' = [pc EXCEPT ![c] = "done"]
    /\ UNCHANGED <<clock, dbPart, physPart, physEtagCounter, pendingReports,
                   backendObjectExists, backendAssembledObject, assembledManifest,
                   versionAvailable, completedManifest, completedCount, contentPtr,
                   boundTarget, ctakeover, backendCleaned, pendingVersionDeleted,
                   partsWiped, physWiped, everTakeover, everSweepAborted,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(***************************** M.4.2 -- direct replay (no lease needed) *****)
ReplayCompleted(c) ==
    /\ pc[c] = "idle"
    /\ sessState = "completed"
    /\ returnedManifest' = [returnedManifest EXCEPT ![c] = completedManifest]
    /\ returnedAvailable' = [returnedAvailable EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, clock, dbPart, physPart,
                   physEtagCounter, pendingReports, backendObjectExists,
                   backendAssembledObject, assembledManifest, versionAvailable,
                   completedManifest, completedCount, contentPtr, boundTarget,
                   ctakeover, pc, backendCleaned, pendingVersionDeleted, partsWiped,
                   physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, everSweepAborted, completedSnapshotManifest,
                   completedSnapshotAvailable, staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(***************************** crash between any two completer steps *******)
CrashCompleter(c) ==
    /\ pc[c] \notin {"idle", "done"}
    /\ pc' = [pc EXCEPT ![c] = "done"]
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, clock, dbPart, physPart,
                   physEtagCounter, pendingReports, backendObjectExists,
                   backendAssembledObject, assembledManifest, versionAvailable,
                   completedManifest, completedCount, contentPtr, boundTarget,
                   ctakeover, backendCleaned, pendingVersionDeleted, partsWiped,
                   physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(***************************** M.5 -- user-driven abort *********************)
UserAbort ==
    /\ sessState = "in_progress"
    /\ sessState' = "aborted"
    /\ dbPart' = [p \in Parts |-> NoPart]
    /\ leaseOwner' = NoOwner
    /\ leaseUntil' = 0
    /\ partsWiped' = TRUE
    /\ UNCHANGED <<clock, physPart, physEtagCounter, pendingReports,
                   backendObjectExists, backendAssembledObject, assembledManifest,
                   versionAvailable, completedManifest, completedCount, contentPtr,
                   boundTarget, ctakeover, pc, backendCleaned, pendingVersionDeleted,
                   physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(***************************** MS.1/MS.2/MS.3 -- sweep: abort expired ******)
(* MUTATION m3 target: `AcquireLease`'s own `clock >= leaseUntil` guard --  *)
(* m3 removes it (a live lease can be taken over).                         *)
(* MUTATION m4 target: the second disjunct below (`clock >= leaseUntil`)   *)
(* -- m4 removes it (sweep reclaims a `completing` session regardless of   *)
(* whether its lease is still live).                                      *)
SweepAbortExpired ==
    /\ \/ /\ sessState = "in_progress"
          /\ clock >= SessionExpiresAt
       \/ /\ sessState = "completing"
          /\ clock >= leaseUntil
    /\ sessState' = "aborted"
    /\ dbPart' = [p \in Parts |-> NoPart]
    /\ leaseOwner' = NoOwner
    /\ leaseUntil' = 0
    /\ partsWiped' = TRUE
    /\ everSweepAborted' = TRUE
    /\ UNCHANGED <<clock, physPart, physEtagCounter, pendingReports,
                   backendObjectExists, backendAssembledObject, assembledManifest,
                   versionAvailable, completedManifest, completedCount, contentPtr,
                   boundTarget, ctakeover, pc, backendCleaned, pendingVersionDeleted,
                   physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(* M.5/MS.2's best-effort backend.abort_multipart. A no-op once the backend *)
(* handle has already been consumed by a successful Assemble (M.4.8.5).    *)
SweepCleanupBackend ==
    /\ sessState = "aborted"
    /\ ~backendCleaned
    /\ backendCleaned' = TRUE
    /\ \/ /\ backendObjectExists
          /\ UNCHANGED physPart
          /\ physWiped' = physWiped
       \/ /\ ~backendObjectExists
          /\ physPart' = [p \in Parts |-> NoPart]
          /\ physWiped' = TRUE
       \/ /\ ~backendObjectExists
          /\ UNCHANGED physPart
          /\ physWiped' = physWiped
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, clock, dbPart,
                   physEtagCounter, pendingReports, backendObjectExists,
                   backendAssembledObject, assembledManifest, versionAvailable,
                   completedManifest, completedCount, contentPtr, boundTarget,
                   ctakeover, pc, pendingVersionDeleted, partsWiped,
                   standaloneClosedBy, standaloneClosedLeaseOwner, everTakeover,
                   everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(* M.5/MS.2's status-guarded delete_pending_version.
   FIX M8-deep, site (b) (`FixDeleteAssembledObject`): `cleanup.rs`'s sweep,
   on EVERY `delete_pending_version` that actually removes a pending row
   (unconditionally -- real code does not check whether an object exists at
   the path first; the delete call is simply a no-op if there is nothing
   there), ALSO best-effort deletes the version's backend object -- on top
   of the pre-existing `SweepCleanupBackend`/`abort_multipart` call, which is
   a guaranteed no-op once a completer's own assembly already consumed the
   upload handle (M8, deep shape). Covers the case where this sweep step
   runs AFTER some completer's `Assemble` already succeeded
   (`backendObjectExists = TRUE`) but that completer's own `Finalize` has
   not (yet, or ever) run -- site (a), inside `Finalize`'s "aborted" branch,
   covers the complementary case where the completer's own call DOES reach
   `Finalize` and observes the rejection itself.
   NOTE: if THIS step runs BEFORE that completer's `Assemble` call (i.e.
   `backendObjectExists = FALSE` right now), the delete attempted here is a
   real no-op (there is genuinely nothing at the path yet) -- `~ok`'s
   `deepCleanupAttempted'` is deliberately NOT latched in that case, so it
   stays an accurate "was a REAL object ever targeted" ghost, not "did this
   code path run". If the completer's assembly succeeds only afterwards AND
   that completer never reaches `Finalize` either (crashed/abandoned before
   its own finalize call, `CrashCompleter`), NEITHER site re-fires -- see
   `M8_DeepOrphan_NotReachable`'s own doc comment for this residual. *)
SweepDeletePendingVersion ==
    /\ sessState = "aborted"
    /\ ~pendingVersionDeleted
    /\ ~versionAvailable
    /\ pendingVersionDeleted' = TRUE
    /\ IF FixDeleteAssembledObject
       THEN \E ok \in BOOLEAN :
              /\ backendObjectExists' = IF ok THEN FALSE ELSE backendObjectExists
              /\ deepCleanupAttempted' = (deepCleanupAttempted \/ backendObjectExists)
       ELSE UNCHANGED <<backendObjectExists, deepCleanupAttempted>>
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, clock, dbPart, physPart,
                   physEtagCounter, pendingReports,
                   backendAssembledObject, assembledManifest, versionAvailable,
                   completedManifest, completedCount, contentPtr, boundTarget,
                   ctakeover, pc, backendCleaned, partsWiped, physWiped,
                   standaloneClosedBy, standaloneClosedLeaseOwner, everTakeover,
                   everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen>>

(***************************** abstract clock *******************************)
Tick ==
    /\ clock < MaxTick
    /\ clock' = clock + 1
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, dbPart, physPart,
                   physEtagCounter, pendingReports, backendObjectExists,
                   backendAssembledObject, assembledManifest, versionAvailable,
                   completedManifest, completedCount, contentPtr, boundTarget,
                   ctakeover, pc, backendCleaned, pendingVersionDeleted,
                   partsWiped, physWiped, standaloneClosedBy,
                   standaloneClosedLeaseOwner, everTakeover, everSweepAborted,
                   returnedManifest, returnedAvailable, completedSnapshotManifest,
                   completedSnapshotAvailable, staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

(* A legitimate concurrent rebind of the file's content pointer away from   *)
(* this session's version -- exercises the auto-bind CAS's losing branch.  *)
ExternalRebind ==
    /\ contentPtr # "other"
    /\ contentPtr' = "other"
    /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, clock, dbPart, physPart,
                   physEtagCounter, pendingReports, backendObjectExists,
                   backendAssembledObject, assembledManifest, versionAvailable,
                   completedManifest, completedCount, boundTarget, ctakeover,
                   pc, backendCleaned, pendingVersionDeleted, partsWiped,
                   physWiped, standaloneClosedBy, standaloneClosedLeaseOwner,
                   everTakeover, everSweepAborted, returnedManifest, returnedAvailable,
                   completedSnapshotManifest, completedSnapshotAvailable,
                   staleRebindHappened, liveLeaseStolen, deepCleanupAttempted>>

Next ==
    \/ \E p \in Parts, v \in Values : PhysicalWrite(p, v)
    \/ \E rep \in ReportRecs : DeliverReport(rep)
    \/ \E c \in Completers : AcquireLease(c) \/ Assemble(c) \/ Finalize(c)
                              \/ Converge(c) \/ CrashCompleter(c)
                              \/ ReplayCompleted(c)
    \/ UserAbort
    \/ SweepAbortExpired
    \/ SweepCleanupBackend
    \/ SweepDeletePendingVersion
    \/ Tick
    \/ ExternalRebind

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ sessState \in SessStates
    /\ leaseOwner \in Completers \cup {NoOwner}
    /\ leaseUntil \in 0..(MaxTick + LeaseDuration)
    /\ clock \in 0..MaxTick
    /\ dbPart \in [Parts -> [val : Values \cup {NoVal}, etag : 0..MaxWrites]]
    /\ physPart \in [Parts -> [val : Values \cup {NoVal}, etag : 0..MaxWrites]]
    /\ physEtagCounter \in 0..MaxWrites
    /\ pendingReports \subseteq ReportRecs
    /\ backendObjectExists \in BOOLEAN
    /\ backendAssembledObject \in [Parts -> Values \cup {NoVal}]
    /\ assembledManifest \in [Parts -> Values \cup {NoVal}]
    /\ versionAvailable \in BOOLEAN
    /\ completedManifest \in [Parts -> Values \cup {NoVal}]
    /\ completedCount \in Nat
    /\ contentPtr \in PtrVals
    /\ boundTarget \in [Completers -> PtrVals]
    /\ ctakeover \in [Completers -> BOOLEAN]
    /\ pc \in [Completers -> PCs]
    /\ backendCleaned \in BOOLEAN
    /\ pendingVersionDeleted \in BOOLEAN
    /\ partsWiped \in BOOLEAN
    /\ physWiped \in BOOLEAN
    /\ standaloneClosedBy \in Completers \cup {NoOwner}
    /\ standaloneClosedLeaseOwner \in Completers \cup {NoOwner}
    /\ everTakeover \in BOOLEAN
    /\ everSweepAborted \in BOOLEAN
    /\ returnedManifest \in [Completers -> [Parts -> Values \cup {NoVal}]]
    /\ returnedAvailable \in [Completers -> BOOLEAN]
    /\ completedSnapshotManifest \in [Parts -> Values \cup {NoVal}]
    /\ completedSnapshotAvailable \in BOOLEAN
    /\ staleRebindHappened \in BOOLEAN
    /\ liveLeaseStolen \in BOOLEAN
    /\ deepCleanupAttempted \in BOOLEAN

(* M1 (states-multipart.md): once Available, the persisted manifest equals  *)
(* the bytes the backend actually assembled at the same instant.           *)
M1_ManifestMatchesBytes ==
    versionAvailable => (\A p \in Parts : completedManifest[p] = backendAssembledObject[p])

(* M2: the version-row CAS (M.4.8.8 step 2) commits at most once. *)
M2_SingleFinalize == completedCount <= 1

(* M3: the standalone, owner-fenced close (M.4.8.10) only ever closes the  *)
(* session while that completer still held the live lease at that instant. *)
M3_LeaseSafety ==
    standaloneClosedBy # NoOwner => standaloneClosedBy = standaloneClosedLeaseOwner

(* M4: completed/aborted are absorbing. *)
M4_TerminalAbsorbing ==
    [][ (sessState = "completed" => sessState' = "completed") /\
        (sessState = "aborted"   => sessState' = "aborted") ]_vars

(* M5: a session that is completed, or completing with a still-live lease, *)
(* is never the target of a part-row wipe, a physical-register wipe, or a  *)
(* pending-version delete. Phase 2 fix: the original plain-state form      *)
(* (`(sessState = completed \/ (completing /\ clock<leaseUntil)) =>         *)
(* ~partsWiped/physWiped/pendingVersionDeleted`) checked the POST-state --  *)
(* a sweep action that wipes these AND flips sessState away from           *)
(* "completing" in the SAME step (exactly what SweepAbortExpired does)      *)
(* changes the antecedent to FALSE in that very same transition, so the    *)
(* violation was never observed (mutation m4 slipped straight past it,     *)
(* caught only downstream by M7). Restated as a two-state property over    *)
(* the PRE-state condition, like M4/M13: a transition that starts with a    *)
(* still-live `completing` lease (or an already-`completed` session) must  *)
(* leave these three ghosts unchanged. *)
M5_SweepSafe ==
    [][ (sessState = "completed" \/ (sessState = "completing" /\ clock < leaseUntil))
          => /\ partsWiped' = partsWiped
             /\ physWiped' = physWiped
             /\ pendingVersionDeleted' = pendingVersionDeleted
      ]_vars

(* M6: the file's content pointer, when it names this session's version,  *)
(* only ever does so for an Available version whose backend object exists. *)
M6_NoDanglingAfterAutoBind ==
    contentPtr = "this" => (versionAvailable /\ backendObjectExists)

(* M7: the backend-side best-effort discard and a completed version        *)
(* pointing at that same session never both happen. With
   `FixCloseFromInProgress = FALSE` (the unpatched code), violated (the M7
   finding, states-multipart.md): the embedded session-close CAS can lose on
   the very same transaction that just won the version CAS (a takeover's own
   failed attempt released the lease moments earlier, reverting `sessState`
   to `"in_progress"`), leaving the session readable as an ordinary
   abandoned upload forever -- `UserAbort`/`SweepAbortExpired` then CAS it to
   `"aborted"` off a truthful-but-stale `"in_progress"` read, and
   `SweepCleanupBackend` marks `backendCleaned` while `versionAvailable` is
   (and remains) TRUE. With `FixCloseFromInProgress = TRUE` (the shipped
   fix: the embedded close also matches `"in_progress"`), expected to HOLD
   -- part of the main/medium invariant list. *)
M7_AbortCompleteExclusive == ~(backendCleaned /\ versionAvailable)

(* M8 (at rest): once a session is aborted AND both of its own cleanup     *)
(* steps (M.5/MS.2) have run, no physical part register and no assembled   *)
(* backend object may still exist. Violated by BOTH orphan shapes below
   regardless of `FixDeleteAssembledObject` -- the "shallow" shape
   (`backend.abort_multipart`'s own best-effort, no-retry discard can simply
   fail) is a separate, still-open issue the fix does not touch at all (see
   `M8_DeepOrphan_NotReachable` below for the deep shape the fix DOES
   address). Always excluded from the main/medium invariant list; reproduced
   in isolation by `FileStorageMultipart_M8_shallow.cfg`. *)
M8_NoPermanentOrphan ==
    (sessState = "aborted" /\ backendCleaned /\ pendingVersionDeleted)
        => (~backendObjectExists /\ (\A p \in Parts : physPart[p] = NoPart))

(* M8, deep shape ONLY, isolated from the still-open shallow one above --
   a plain TLC search for the combined `M8_NoPermanentOrphan` always finds
   the shallower shape first (Discrepancy #2, states-multipart.md's "M8
   orphan classification").
   Revised from phase 1's simple reachability witness (`~backendObjectExists`,
   which a fully successful, never-aborted completion also -- correctly --
   violates forever, so it could never be asserted as a general invariant):
   this version is scoped to the SAME "at rest" antecedent as
   `M8_NoPermanentOrphan` (a session that has reached BOTH of its own
   cleanup steps), so a normal successful completion (which never reaches
   `sessState = "aborted"`) never trips it.
   With `FixDeleteAssembledObject = FALSE` (the unpatched code), violated:
   a completer's own `backend.complete_multipart` call (M.4.8.5) already
   physically succeeded -- the final object genuinely, completely exists --
   before the session was reclaimed, and NOTHING in the unpatched code ever
   targets that specific object for cleanup (`FileStorageMultipart_M8_deep.cfg`).
   With `FixDeleteAssembledObject = TRUE` (the shipped fix: both site (a),
   `Finalize`'s "aborted" branch, and site (b), `SweepDeletePendingVersion`,
   now best-effort delete it), expected to HOLD in the SAME sense every
   other best-effort cleanup in this family of models does -- `deepCleanupAttempted`
   (see its own VARIABLES comment) distinguishes "a real attempt was made and
   this nondeterministic choice modelled it failing" (an accepted residual,
   same risk class as M8 shallow) from "no code path ever tried" (the
   pre-fix bug); only the LATTER would still violate this invariant. If
   `FixDeleteAssembledObject = TRUE` and this invariant is STILL violated
   with `deepCleanupAttempted = FALSE` (neither site ever ran), that is a
   genuine, NOT-yet-covered residual (see the report: the sweep's delete can
   run BEFORE a stalled completer's own backend-side assembly finishes, and
   that completer then never calls `Finalize` at all, so neither site (a)
   nor site (b) is reached for that specific object) -- the config below
   reports whichever shape it actually finds. *)
M8_DeepOrphan_NotReachable ==
    (sessState = "aborted" /\ backendCleaned /\ pendingVersionDeleted /\ backendObjectExists)
        => deepCleanupAttempted

(* M9 (phase 2, (a)): a completer that reported success (200/201) always   *)
(* reported exactly the manifest that is (or becomes) the persisted one -- *)
(* no completer's own HTTP response can show stale/different hash data.    *)
M9_ReplayMatchesStored ==
    \A c \in Completers : returnedAvailable[c] => returnedManifest[c] = completedManifest

(* M10 (phase 2, (b)): once completed, a repeat `complete` call always     *)
(* replays successfully (M.4.2) -- never a 409/error, for any completer    *)
(* that has not already consumed its own attempt. *)
M10_RepeatCompleteReplays ==
    \A c \in Completers :
        (pc[c] = "idle" /\ sessState = "completed") => ENABLED ReplayCompleted(c)

(* M11 (phase 2, (c)): once the session has reached `completed`, its       *)
(* persisted manifest/availability are frozen forever (abort cannot touch  *)
(* a completed version). *)
M11_NoChangeAfterCompleted ==
    completedSnapshotAvailable => (versionAvailable /\ completedManifest = completedSnapshotManifest)

(* M12 (phase 2, (d)): our own auto-bind CAS never overwrites the file's   *)
(* content pointer when it did not match what we observed at request time *)
(* -- a late/stale completer can never silently clobber a newer bind. *)
M12_NoStaleRebind == ~staleRebindHappened

(* M14 (phase 2, mutation m3's target): `AcquireLease` never succeeds       *)
(* against a DIFFERENT owner's still-live lease -- a completer that is      *)
(* actively, legitimately working (its lease has not expired) can never be  *)
(* stolen from by another attempt. *)
M14_NoLiveLeaseSteal == ~liveLeaseStolen

(* Witnesses -- meant to be VIOLATED (i.e. TLC finding a counterexample     *)
(* confirms the scenario is reachable, so the invariants above are not     *)
(* vacuous). *)
W1_NeverCompleting202 ==
    ~(\E c \in Completers : pc[c] = "idle" /\ sessState = "completing" /\ clock < leaseUntil)
W2_NeverTakeover == ~everTakeover
W3_NeverSweepReclaims == ~everSweepAborted

------------------------------------------------------------------------------
(* Phase 2 (c), the harder/complementary direction: once a session is       *)
(* `aborted`, no LATER action may still flip `versionAvailable` -- i.e. a   *)
(* finalize must never succeed "underneath" an already-reclaimed session.   *)
(* A temporal (two-state) property, like M4 -- run WITHOUT symmetry         *)
(* (TLC/credstore convention: symmetry reduction is only sound for          *)
(* INVARIANTS, not PROPERTIES). Mutation m1's target. *)
M13_NoFinalizeAfterAbort ==
    [][ sessState = "aborted" => versionAvailable' = versionAvailable ]_vars

==============================================================================
