----------------------- MODULE FileStorageMultipartTwoSessions -----------------------
(***************************************************************************)
(* Phase 3 (c): two independent multipart sessions against the SAME file,  *)
(* both with `auto_bind = TRUE`, racing for `files.content_id`. A MINIMAL  *)
(* extension of `FileStorageMultipart.tla` (same repo, same step ids in    *)
(* `states-multipart.md`) -- NOT a mechanical duplication of the full      *)
(* per-part/per-report machinery, which is already exhaustively validated  *)
(* by the single-session model and does not interact across sessions (two *)
(* multipart uploads never share a `dbPart`/`physPart`, only the file's    *)
(* content pointer). Every session-internal step up to "the backend has    *)
(* assembled this session's object and every part is accounted for"        *)
(* (M.4.8.1-M.4.8.7) is collapsed into one abstract action, `BecomeReady`.  *)
(* What is NOT abstracted, because it is exactly what this run is for, is  *)
(* M.4.8.8's lease machinery, its `sessState = aborted` guard, its version  *)
(* CAS, and -- the whole point -- its auto-bind CAS against the ONE shared *)
(* `contentPtr`, plus M.4.8.9/10's converge.                               *)
(*                                                                         *)
(* `contentPtr` ranges over `Sessions \cup {"none"}` directly (not the      *)
(* single-session model's abstract "this"/"other"): with two REAL sessions *)
(* in play there is no need for an abstract stand-in, and this is in fact  *)
(* MORE faithful than the single-session model's own simplification.      *)
(*                                                                         *)
(* `Completers` is shared across both sessions (any completer may call     *)
(* `complete` on either session's `upload_id` -- they are just different    *)
(* HTTP requests); `pc`/`boundTarget` are therefore indexed                *)
(* `[Sessions -> [Completers -> ...]]`.                                    *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Sessions,           \* e.g. {s1, s2} -- two multipart sessions on one file
    Completers,         \* shared across both sessions
    SessionExpiresAt,
    LeaseDuration,
    MaxTick

ASSUME SessionExpiresAt \in Nat
ASSUME LeaseDuration \in Nat \ {0}
ASSUME MaxTick \in Nat

NoOwner == "noowner"
SessStates == {"in_progress", "completing", "completed", "aborted"}
PCs == {"idle", "acquired", "converge", "done"}
PtrVals == Sessions \cup {"none"}

VARIABLES
    clock,               \* shared abstract clock
    contentPtr,          \* files.content_id -- the ONE shared resource (Sessions \cup {"none"})
    sessState,           \* [Sessions -> SessStates]
    leaseOwner,          \* [Sessions -> Completers \cup {NoOwner}]
    leaseUntil,          \* [Sessions -> Nat]
    ready,               \* [Sessions -> BOOLEAN]: abstracts M.4.8.1-7 (assembled, all parts present)
    versionAvailable,    \* [Sessions -> BOOLEAN]: file_versions.status = available (M.4.8.8 step 2)
    completedCount,      \* [Sessions -> Nat]: M2 ghost, per session
    boundTarget,         \* [Sessions -> [Completers -> PtrVals]]: contentPtr snapshot at acquire-lease
    pc,                  \* [Sessions -> [Completers -> PCs]]
    staleRebindHappened  \* shared M12 ghost: any session's auto-bind CAS fired despite a mismatch

vars == <<clock, contentPtr, sessState, leaseOwner, leaseUntil, ready,
          versionAvailable, completedCount, boundTarget, pc, staleRebindHappened>>

Init ==
    /\ clock = 0
    /\ contentPtr = "none"
    /\ sessState = [s \in Sessions |-> "in_progress"]
    /\ leaseOwner = [s \in Sessions |-> NoOwner]
    /\ leaseUntil = [s \in Sessions |-> 0]
    /\ ready = [s \in Sessions |-> FALSE]
    /\ versionAvailable = [s \in Sessions |-> FALSE]
    /\ completedCount = [s \in Sessions |-> 0]
    /\ boundTarget = [s \in Sessions |-> [c \in Completers |-> "none"]]
    /\ pc = [s \in Sessions |-> [c \in Completers |-> "idle"]]
    /\ staleRebindHappened = FALSE

(* Abstracts M.4.8.1-M.4.8.7: the backend has assembled this session's      *)
(* object and every planned part is accounted for -- fires at most once    *)
(* per session, any time before it reaches a terminal state. *)
BecomeReady(sess) ==
    /\ sessState[sess] \in {"in_progress", "completing"}
    /\ ~ready[sess]
    /\ ready' = [ready EXCEPT ![sess] = TRUE]
    /\ UNCHANGED <<clock, contentPtr, sessState, leaseOwner, leaseUntil,
                   versionAvailable, completedCount, boundTarget, pc,
                   staleRebindHappened>>

(* M.4.6 -- acquire/takeover lease, per session. *)
AcquireLease(sess, c) ==
    /\ pc[sess][c] = "idle"
    /\ clock < SessionExpiresAt
    /\ \/ sessState[sess] = "in_progress"
       \/ /\ sessState[sess] = "completing"
          /\ clock >= leaseUntil[sess]
    /\ boundTarget' = [boundTarget EXCEPT ![sess][c] = contentPtr]
    /\ sessState' = [sessState EXCEPT ![sess] = "completing"]
    /\ leaseOwner' = [leaseOwner EXCEPT ![sess] = c]
    /\ leaseUntil' = [leaseUntil EXCEPT ![sess] = clock + LeaseDuration]
    /\ pc' = [pc EXCEPT ![sess][c] = "acquired"]
    /\ UNCHANGED <<clock, contentPtr, ready, versionAvailable, completedCount,
                   staleRebindHappened>>

(* M.4.8.8: one atomic transaction -- lock_session_state, version CAS,      *)
(* auto-bind CAS against the SHARED contentPtr, embedded (owner-blind)      *)
(* session close. *)
Finalize(sess, c) ==
    /\ pc[sess][c] = "acquired"
    /\ ready[sess]
    /\ IF sessState[sess] = "aborted"
       THEN /\ pc' = [pc EXCEPT ![sess][c] = "done"]
            /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, versionAvailable,
                           contentPtr, completedCount, staleRebindHappened>>
       ELSE IF versionAvailable[sess]
            THEN /\ pc' = [pc EXCEPT ![sess][c] = "converge"]
                 /\ UNCHANGED <<sessState, leaseOwner, leaseUntil, versionAvailable,
                                contentPtr, completedCount, staleRebindHappened>>
            ELSE /\ versionAvailable' = [versionAvailable EXCEPT ![sess] = TRUE]
                 /\ completedCount' = [completedCount EXCEPT ![sess] = @ + 1]
                 /\ IF contentPtr = boundTarget[sess][c]
                    THEN /\ contentPtr' = sess
                         /\ UNCHANGED staleRebindHappened
                    ELSE /\ UNCHANGED contentPtr   \* CAS lost: Conflict, no overwrite
                         /\ UNCHANGED staleRebindHappened
                 /\ IF sessState[sess] = "completing"
                    THEN /\ sessState' = [sessState EXCEPT ![sess] = "completed"]
                         /\ leaseOwner' = [leaseOwner EXCEPT ![sess] = NoOwner]
                         /\ leaseUntil' = [leaseUntil EXCEPT ![sess] = 0]
                    ELSE /\ UNCHANGED <<sessState, leaseOwner, leaseUntil>>
                 /\ pc' = [pc EXCEPT ![sess][c] = "done"]
    /\ UNCHANGED <<clock, ready, boundTarget>>

(* M.4.8.9/10: standalone, owner-fenced close. *)
Converge(sess, c) ==
    /\ pc[sess][c] = "converge"
    /\ IF sessState[sess] = "completing" /\ leaseOwner[sess] = c
       THEN /\ sessState' = [sessState EXCEPT ![sess] = "completed"]
            /\ leaseOwner' = [leaseOwner EXCEPT ![sess] = NoOwner]
            /\ leaseUntil' = [leaseUntil EXCEPT ![sess] = 0]
       ELSE UNCHANGED <<sessState, leaseOwner, leaseUntil>>
    /\ pc' = [pc EXCEPT ![sess][c] = "done"]
    /\ UNCHANGED <<clock, contentPtr, ready, versionAvailable, completedCount,
                   boundTarget, staleRebindHappened>>

(* M.5 -- user-driven abort, per session. *)
UserAbort(sess) ==
    /\ sessState[sess] = "in_progress"
    /\ sessState' = [sessState EXCEPT ![sess] = "aborted"]
    /\ leaseOwner' = [leaseOwner EXCEPT ![sess] = NoOwner]
    /\ leaseUntil' = [leaseUntil EXCEPT ![sess] = 0]
    /\ UNCHANGED <<clock, contentPtr, ready, versionAvailable, completedCount,
                   boundTarget, pc, staleRebindHappened>>

(* MS.1/MS.2 -- sweep: abort expired, per session. *)
SweepAbortExpired(sess) ==
    /\ \/ /\ sessState[sess] = "in_progress"
          /\ clock >= SessionExpiresAt
       \/ /\ sessState[sess] = "completing"
          /\ clock >= leaseUntil[sess]
    /\ sessState' = [sessState EXCEPT ![sess] = "aborted"]
    /\ leaseOwner' = [leaseOwner EXCEPT ![sess] = NoOwner]
    /\ leaseUntil' = [leaseUntil EXCEPT ![sess] = 0]
    /\ UNCHANGED <<clock, contentPtr, ready, versionAvailable, completedCount,
                   boundTarget, pc, staleRebindHappened>>

Tick ==
    /\ clock < MaxTick
    /\ clock' = clock + 1
    /\ UNCHANGED <<contentPtr, sessState, leaseOwner, leaseUntil, ready,
                   versionAvailable, completedCount, boundTarget, pc,
                   staleRebindHappened>>

Next ==
    \/ Tick
    \/ \E sess \in Sessions : BecomeReady(sess) \/ UserAbort(sess) \/ SweepAbortExpired(sess)
    \/ \E sess \in Sessions, c \in Completers :
           AcquireLease(sess, c) \/ Finalize(sess, c) \/ Converge(sess, c)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ clock \in 0..MaxTick
    /\ contentPtr \in PtrVals
    /\ sessState \in [Sessions -> SessStates]
    /\ leaseOwner \in [Sessions -> Completers \cup {NoOwner}]
    /\ leaseUntil \in [Sessions -> 0..(MaxTick + LeaseDuration)]
    /\ ready \in [Sessions -> BOOLEAN]
    /\ versionAvailable \in [Sessions -> BOOLEAN]
    /\ completedCount \in [Sessions -> Nat]
    /\ boundTarget \in [Sessions -> [Completers -> PtrVals]]
    /\ pc \in [Sessions -> [Completers -> PCs]]
    /\ staleRebindHappened \in BOOLEAN

(* M2: each session's version-row CAS commits at most once. *)
M2_SingleFinalize == \A sess \in Sessions : completedCount[sess] <= 1

(* M4: completed/aborted are absorbing, per session. *)
M4_TerminalAbsorbing ==
    [][ \A sess \in Sessions :
          (sessState[sess] = "completed" => sessState'[sess] = "completed") /\
          (sessState[sess] = "aborted"   => sessState'[sess] = "aborted")
      ]_vars

(* M6 (generalized to two real, competing sessions): the shared pointer,    *)
(* whenever it names a session, names one that is genuinely available and  *)
(* whose backend object genuinely exists -- no dangling pointer. *)
M6_NoDanglingAfterAutoBind ==
    \A sess \in Sessions : contentPtr = sess => (versionAvailable[sess] /\ ready[sess])

(* Coordinator's exact phrasing, restated existentially (equivalent to M6,  *)
(* kept as its own name for direct traceability): "the file pointer points  *)
(* at an available version". *)
M15_PointerAlwaysValidWinner ==
    contentPtr # "none" => (versionAvailable[contentPtr] /\ ready[contentPtr])

(* M12: no session's auto-bind CAS ever overwrites the shared pointer       *)
(* despite a mismatch against what it observed at acquire-lease time --     *)
(* "the auto-bind winner matches the CAS". *)
M12_NoStaleRebind == ~staleRebindHappened

==============================================================================
