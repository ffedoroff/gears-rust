---------------------------- MODULE FileStorageUpload ----------------------------
(***************************************************************************)
(* FileStorage: create -> sidecar PUT -> finalize -> bind -> delete ->     *)
(* sweep -> read, as implemented (ventral slice: single-part upload only,  *)
(* no multipart, no Range reads).  `Files` is a small, REUSABLE pool of     *)
(* symbolic file names (unlike the real file_id, a Uuid::now_v7() never    *)
(* reused -- see states-upload.md's closing note for why this is sound here).     *)
(* `VerIds` is a pool of version ids that, once minted (`minted`), are      *)
(* NEVER reused -- this mirrors the real backend_path being deterministic  *)
(* in (file_id, version_id) and lets the model key the backend purely by   *)
(* version id (`blob`).  Step ids (U.x, B.x, D.x, S.x, R.x) refer to       *)
(* states-upload.md in this directory.                                            *)
(*                                                                         *)
(* Every action is one atomic transaction or one backend call, matching a  *)
(* single real step (create tx / publish_exclusive / finalize tx / bind tx *)
(* / delete tx / one sweep reclaim / download-url issuance / sidecar read).*)
(* There is no third "ambiguous, might-not-have-committed" outcome         *)
(* distinct from an ordinary CAS pass/fail here (unlike the credstore      *)
(* sibling model): nothing in this protocol reacts to "my write might not  *)
(* have landed" by deleting anything -- see states-upload.md's U.3 note. A lost   *)
(* response is simply `Crash` after the transaction already ran; the next  *)
(* actor to touch that version id just retries U.2/U.3, which converges    *)
(* (U.3.3).                                                                *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Files,          \* finite, reusable pool of file names
    VerIds,         \* finite pool of version ids, minted at most once each
    Values,         \* finite pool of abstract content bytes
    IdemKeys,       \* finite pool of idempotency keys
    Clients,        \* upload-flow actors: create/replay, PUT, finalize, (manual) bind
    Deleters,       \* delete-flow actors: delete_version / delete_file (stateless -- see states-upload.md)
    Readers,        \* read-flow actors: download-url + sidecar read
    MaxTick,        \* abstract clock bound
    PendingGrace,   \* S.1: orphan_grace_secs, collapsed to Tick units
    RetentionGrace, \* S.2: a retention rule's age bound, collapsed to Tick units
    FixDownloadHashCheck, \* TRUE = current code (the GET download claims carry the
                          \* version's whole-object SHA-256 at issuance, `Claims::
                          \* content_sha256`; the sidecar verifies the full,
                          \* non-Range stream against it and aborts on mismatch).
                          \* FALSE = the unpatched code (no check at all) -- F1.
    FixDeleteIfMatchInTx  \* TRUE = current code (`delete_file_inner` /
                          \* `Store::delete_file_collecting_versions` re-verify
                          \* `expected_etag` against the row's `content_id`
                          \* INSIDE the transaction, right after `lock_for_update`).
                          \* FALSE = the unpatched code (the early, pre-transaction
                          \* check is the only one; `delete_file_inner` wipes
                          \* unconditionally) -- F3.

ASSUME MaxTick \in Nat /\ PendingGrace \in Nat /\ RetentionGrace \in Nat
ASSUME FixDownloadHashCheck \in BOOLEAN /\ FixDeleteIfMatchInTx \in BOOLEAN

NoFile == "noFile"
NoVer  == "noVer"
NoVal  == "noVal"
Miss   == "miss"
Star   == "star"     \* If-Match: "*"
NoKey  == "noKey"

CPCs == {"idle", "put", "finalize", "holding_etag"}
RPCs == {"idle", "holding"}
DPCs == {"idle", "ready"}

VARIABLES
    ex,          \* [Files -> BOOLEAN]: file row exists
    content,     \* [Files -> VerIds \cup {NoVer}]: files.content_id
    createdF,    \* [Files -> 0..MaxTick]: file row creation tick (for S.2)
    verOwner,    \* [VerIds -> Files \cup {NoFile}]: file_versions row's owner (NoFile = row gone)
    verStatus,   \* [VerIds -> {"pending","available"}]: meaningless while verOwner = NoFile
    verAutoBind, \* [VerIds -> BOOLEAN]: token carried bind_on_finalize (fixed at mint time)
    fileGen,     \* [Files -> Nat]: ghost, incremented every FRESH CreateNewFile for this
                 \* symbolic name -- distinguishes one incarnation of a reused `Files` slot from
                 \* the next (see the closing note: `Files` is a small, reusable pool of names,
                 \* unlike the real file_id, a Uuid::now_v7() never reused). Needed so
                 \* DoDelete/D.2b -- keyed by the real `file_id` in the code, which CANNOT
                 \* alias a later incarnation -- does not accidentally wipe a RECREATED file
                 \* that happens to reuse the same symbolic name while a stale D.2a check is
                 \* still "ready" (see dGen and F3's SpecificEtag config)
    verCreated,  \* [VerIds -> 0..MaxTick]: version row creation tick (for S.1)
    verVal,      \* [VerIds -> Values \cup {NoVal}]: file_versions' OWN recorded hash/size (U.3.2),
                 \* compared against on a later U.3.3 convergence check -- NOT the real backend
                 \* bytes (`blob`); only equals `blob[v]` because U.3.2's read-back verification
                 \* enforces it (mutation u1 drops that guard to show what breaks without it)
    everVal,     \* [VerIds -> Values \cup {NoVal}]: ghost, sticky "ground truth" bytes, set once
                 \* by the FIRST successful U.2 write -- the real, physical backend content this
                 \* version id has ever held, independent of what any DB row claims (used only by I5)
    blob,        \* [VerIds -> Values \cup {NoVal}]: backend content at this version's path, NOW
    minted,      \* SUBSET VerIds: version ids ever minted (never reused)
    idemFile,    \* [IdemKeys -> Files \cup {NoFile}]: idempotency ticket target file (write-once)
    idemVer,     \* [IdemKeys -> VerIds \cup {NoVer}]: idempotency ticket target version
    tick,        \* 0..MaxTick: abstract clock
    pc,          \* [Clients -> CPCs]
    cf,          \* [Clients -> Files \cup {NoFile}]: client's in-flight file
    cv,          \* [Clients -> VerIds \cup {NoVer}]: client's in-flight version
    cval,        \* [Clients -> Values \cup {NoVal}]: bytes THIS client attempted to PUT
    rpc,         \* [Readers -> RPCs]
    rver,        \* [Readers -> VerIds \cup {NoVer}]: reader's ticket target (sticky after read)
    ans,         \* [Readers -> Values \cup {NoVal, Miss}]: last finished read's answer
    rExpect,     \* [Readers -> Values \cup {NoVal}]: the GET claims' `content_sha256`,
                 \* carried as the DB-recorded hash (verVal[v]) AT ISSUANCE time when
                 \* `FixDownloadHashCheck`; `DoRead` verifies the actual blob against
                 \* this instead of trusting it unconditionally (F1's fix)
    dPc,         \* [Deleters -> DPCs]: D.2's check-then-act delete -- see CheckDelete
    dFile,       \* [Deleters -> Files \cup {NoFile}]: file this deleter read an ETag for
    dExpect,     \* [Deleters -> VerIds \cup {NoVer}]: the content pointer value it saved
    dStar,       \* [Deleters -> BOOLEAN]: ghost, TRUE iff THIS check used If-Match: "*"
                 \* (the client-chosen `expected = Star` disjunct of CheckDelete) rather than
                 \* a concrete etag (a specific VerId, or NoVer meaning "no content bound") --
                 \* used only to tell F3's two counterexample shapes apart (see
                 \* I9_SavedDeleteRespectsCAS_SpecificEtag below and states-upload.md's F3 entry)
    dGen         \* [Deleters -> Nat]: ghost, the `fileGen` of `dFile[d]` AT CHECK TIME --
                 \* lets DoDelete tell "the file I checked is still the SAME incarnation" apart
                 \* from "this symbolic name got deleted and recreated since my check", which the
                 \* real `file_id`-keyed DELETE can never confuse (see `fileGen`)

fileVars    == <<ex, content, createdF, fileGen>>
verVars     == <<verOwner, verStatus, verAutoBind, verCreated, verVal>>
blobVars    == <<blob, everVal, minted>>
idemVars    == <<idemFile, idemVer>>
clientVars  == <<pc, cf, cv, cval>>
readerVars  == <<rpc, rver, ans, rExpect>>
deleterVars == <<dPc, dFile, dExpect, dStar, dGen>>

vars == <<ex, content, createdF, fileGen, verOwner, verStatus, verAutoBind, verCreated, verVal,
          blob, everVal, minted, idemFile, idemVer, tick,
          pc, cf, cv, cval, rpc, rver, ans, rExpect, dPc, dFile, dExpect, dStar, dGen>>

Init ==
    /\ ex          = [f \in Files |-> FALSE]
    /\ content     = [f \in Files |-> NoVer]
    /\ createdF    = [f \in Files |-> 0]
    /\ fileGen     = [f \in Files |-> 0]
    /\ verOwner    = [v \in VerIds |-> NoFile]
    /\ verStatus   = [v \in VerIds |-> "pending"]
    /\ verAutoBind = [v \in VerIds |-> FALSE]
    /\ verCreated  = [v \in VerIds |-> 0]
    /\ verVal      = [v \in VerIds |-> NoVal]
    /\ everVal     = [v \in VerIds |-> NoVal]
    /\ blob        = [v \in VerIds |-> NoVal]
    /\ minted      = {}
    /\ idemFile    = [k \in IdemKeys |-> NoFile]
    /\ idemVer     = [k \in IdemKeys |-> NoVer]
    /\ tick        = 0
    /\ pc          = [w \in Clients |-> "idle"]
    /\ cf          = [w \in Clients |-> NoFile]
    /\ cv          = [w \in Clients |-> NoVer]
    /\ cval        = [w \in Clients |-> NoVal]
    /\ rpc         = [r \in Readers |-> "idle"]
    /\ rver        = [r \in Readers |-> NoVer]
    /\ ans         = [r \in Readers |-> NoVal]
    /\ rExpect     = [r \in Readers |-> NoVal]
    /\ dPc         = [d \in Deleters |-> "idle"]
    /\ dFile       = [d \in Deleters |-> NoFile]
    /\ dExpect     = [d \in Deleters |-> NoVer]
    /\ dStar       = [d \in Deleters |-> FALSE]
    /\ dGen        = [d \in Deleters |-> 0]

ClientDone(w) ==
    /\ pc'   = [pc   EXCEPT ![w] = "idle"]
    /\ cf'   = [cf   EXCEPT ![w] = NoFile]
    /\ cv'   = [cv   EXCEPT ![w] = NoVer]
    /\ cval' = [cval EXCEPT ![w] = NoVal]

(* Remove file `f` and every (still-live) version it owns -- D.1's whole-  *)
(* file branch, D.2, and S.2 all reduce to this.  The backend blob delete  *)
(* for the whole batch is ONE nondeterministic best-effort choice (a model *)
(* simplification over the real per-version independent best-effort calls *)
(* -- see states-upload.md -- that keeps the branching factor flat instead of     *)
(* 2^|liveions|, without losing coverage of the "garbage can be left       *)
(* behind" scenario, already exercised per-version by D.1's single-version *)
(* branch and S.1).                                                        *)
WipeFile(f) ==
    LET live == {u \in minted : verOwner[u] = f} IN
    /\ \E ok \in BOOLEAN :
          blob' = [u \in VerIds |-> IF u \in live /\ ok THEN NoVal ELSE blob[u]]
    /\ verOwner' = [u \in VerIds |-> IF u \in live THEN NoFile ELSE verOwner[u]]
    /\ ex' = [ex EXCEPT ![f] = FALSE]
    /\ content' = [content EXCEPT ![f] = NoVer]

(***************************** U: upload **********************************)

(* U.1.1 create_file, fresh (Store::create_file_with_pending_version_and_event):
   one tx mints a new file row + its first pending version, optionally an
   idempotency ticket (only when no live ticket already uses that key -- a
   live key takes ReplayIdempotency below instead). auto_bind is fixed to
   the version at mint time (claims.bind_on_finalize). *)
CreateNewFile(w) ==
    /\ pc[w] = "idle"
    /\ \E f \in Files :
       /\ ~ex[f]
       /\ \E v \in VerIds \ minted :
          \E auto \in BOOLEAN :
          \E useKey \in IdemKeys \cup {NoKey} :
             /\ (useKey # NoKey) => idemFile[useKey] = NoFile
             /\ ex'         = [ex         EXCEPT ![f] = TRUE]
             /\ content'    = [content    EXCEPT ![f] = NoVer]
             /\ createdF'   = [createdF   EXCEPT ![f] = tick]
             /\ fileGen'    = [fileGen    EXCEPT ![f] = fileGen[f] + 1]
             /\ minted'     = minted \cup {v}
             /\ verOwner'   = [verOwner   EXCEPT ![v] = f]
             /\ verStatus'  = [verStatus  EXCEPT ![v] = "pending"]
             /\ verAutoBind' = [verAutoBind EXCEPT ![v] = auto]
             /\ verCreated' = [verCreated EXCEPT ![v] = tick]
             /\ idemFile'   = IF useKey = NoKey THEN idemFile
                               ELSE [idemFile EXCEPT ![useKey] = f]
             /\ idemVer'    = IF useKey = NoKey THEN idemVer
                               ELSE [idemVer  EXCEPT ![useKey] = v]
             /\ pc' = [pc EXCEPT ![w] = "put"]
             /\ cf' = [cf EXCEPT ![w] = f]
             /\ cv' = [cv EXCEPT ![w] = v]
    /\ UNCHANGED <<cval, verVal, blob, everVal, tick, deleterVars, readerVars>>

(* U.1.2 replay_idempotency_key: a live ticket re-targets its stored
   (file, version) pair instead of minting anything new -- I7.  Requires the
   target to still be `pending`, exactly matching the real code's own
   "idempotency key's target version is no longer pending" 409 (otherwise a
   replay could reopen an already-finalized version for a fresh PUT through
   a path the real code explicitly closes -- see StaleRetryPut below for the
   REAL way a stale-but-valid token can still do that). The owner-changed
   check is not modelled (no owner/tenant is tracked at all). *)
ReplayIdempotency(w) ==
    /\ pc[w] = "idle"
    /\ \E k \in IdemKeys :
       /\ idemFile[k] # NoFile
       /\ ex[idemFile[k]]
       /\ verStatus[idemVer[k]] = "pending"
       /\ pc' = [pc EXCEPT ![w] = "put"]
       /\ cf' = [cf EXCEPT ![w] = idemFile[k]]
       /\ cv' = [cv EXCEPT ![w] = idemVer[k]]
    /\ UNCHANGED <<cval, fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>

(* "Stale token retry": a client may, at any time, re-present a PUT token it
   was handed by SOME earlier create/presign call for ANY version id that
   was ever minted -- whether or not that version's row (or even its file)
   still exists, and whether or not this particular client is the one that
   originally finalized it.  This is not a shortcut superset: it is exactly
   what `bin/sidecar.rs::upload` actually allows, since it authenticates
   purely from the token's own signature + `exp` and never re-checks the
   control plane's DB before calling `publish_exclusive` (states-upload.md's U.2
   note). A token's signature covers `op`/`file_id`/`version_id`/size/hash
   CONSTRAINTS, never the body bytes (ADR-0003) -- so a still-valid token,
   replayed after its version's row AND backend blob were both legitimately
   deleted, can publish genuinely DIFFERENT bytes at the exact same path a
   dangling download ticket (R.1, issued before the delete) still names. *)
StaleRetryPut(w) ==
    /\ pc[w] = "idle"
    /\ \E v \in minted :
       /\ pc' = [pc EXCEPT ![w] = "put"]
       /\ cf' = [cf EXCEPT ![w] = verOwner[v]]
       /\ cv' = [cv EXCEPT ![w] = v]
    /\ UNCHANGED <<cval, fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>

(* U.4 presign_version: a new pending version on an EXISTING file; never
   auto-binds. *)
PresignAddVersion(w) ==
    /\ pc[w] = "idle"
    /\ \E f \in Files :
       /\ ex[f]
       /\ \E v \in VerIds \ minted :
          /\ minted'      = minted \cup {v}
          /\ verOwner'    = [verOwner    EXCEPT ![v] = f]
          /\ verStatus'   = [verStatus   EXCEPT ![v] = "pending"]
          /\ verAutoBind' = [verAutoBind EXCEPT ![v] = FALSE]
          /\ verCreated'  = [verCreated  EXCEPT ![v] = tick]
          /\ pc' = [pc EXCEPT ![w] = "put"]
          /\ cf' = [cf EXCEPT ![w] = f]
          /\ cv' = [cv EXCEPT ![w] = v]
    /\ UNCHANGED <<cval, fileVars, verVal, blob, everVal, idemVars, tick, deleterVars, readerVars>>

(* U.2 sidecar PUT -> publish_exclusive: create-exclusive, backend-only --
   fires regardless of whether the DB row for cv[w] still exists (the
   sidecar never checks; see states-upload.md, this is the source of I4's known,
   documented residual).  `val` is remembered in cval[w] (this attempt's
   claimed bytes) whether or not it actually won the write. *)
(* `everVal` is write-once-EVER per version id (gated on `everVal = NoVal`,
   not on `blob = NoVal`) -- it must stay the version's ORIGINAL, legitimate
   content even after the row is deleted and a later `StaleRetryPut`
   reuses the now-empty path for different (adversarial/accidental) bytes
   (`blob` DOES change in that case -- it is the live physical backend,
   correctly reusable). Without this distinction `everVal` would drift to
   whatever was written last, making it useless as I5's ground truth -- see
   the report's phase-3 note on this exact subtlety. *)
Put(w) ==
    /\ pc[w] = "put"
    /\ \E val \in Values :
       /\ cval' = [cval EXCEPT ![w] = val]
       /\ IF blob[cv[w]] = NoVal
          THEN blob' = [blob EXCEPT ![cv[w]] = val]
          ELSE UNCHANGED blob
       /\ IF everVal[cv[w]] = NoVal
          THEN everVal' = [everVal EXCEPT ![cv[w]] = val]
          ELSE UNCHANGED everVal
    /\ pc' = [pc EXCEPT ![w] = "finalize"]
    /\ UNCHANGED <<fileVars, verVars, minted, idemVars, tick, cf, cv, deleterVars, readerVars>>

(* U.3 finalize_upload[_by_token] -> Store::finalize_version: one tx, the
   pending -> available CAS, optionally the B.2 auto-bind CAS inline. *)
Finalize(w) ==
    /\ pc[w] = "finalize"
    /\ LET v == cv[w] IN
       \/ (* U.3.1: row already gone -- version_not_found, no-op *)
          /\ verOwner[v] = NoFile
          /\ ClientDone(w)
          /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>
       \/ (* U.3.3: already available -- no read-back; compares this
            caller's claim against the DB row's OWN recorded verVal[v]
            (finalize_upload_by_token's "idempotent PUT-retry convergence"
            compares against `version.size`/`version.hash_value`, never a
            fresh read-back). Converge (matching claim) or hash mismatch
            (differing claim) either way have no state effect besides the
            client finishing. Auto-bind, if any, was already decided by the
            original U.3.2 commit and is replayed, never re-run. *)
          /\ verOwner[v] # NoFile /\ verStatus[v] = "available"
          /\ ClientDone(w)
          /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>
       \/ (* still pending, nothing was ever actually written at this path:
            "no uploaded content found" -- no-op *)
          /\ verOwner[v] # NoFile /\ verStatus[v] = "pending" /\ blob[v] = NoVal
          /\ ClientDone(w)
          /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>
       \/ (* still pending, bytes present but this caller lost the U.2 race
            (claims a different value than the one actually stored) --
            hash mismatch, no-op: the version stays pending, untouched *)
          /\ verOwner[v] # NoFile /\ verStatus[v] = "pending"
          /\ blob[v] # NoVal /\ blob[v] # cval[w]
          /\ ClientDone(w)
          /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>
       \/ (* U.3.2 commit: real read-back matches this caller's claim -- the
            DB row's own recorded hash (verVal) is persisted as that
            VERIFIED value, which is why it is provably equal to blob[v]
            here (mutation u1 drops the "blob[v] = cval[w]" guard on this
            disjunct and persists the UNVERIFIED claim instead, see
            FileStorageUpload_u1.tla in the mutations directory). *)
          /\ verOwner[v] # NoFile /\ verStatus[v] = "pending"
          /\ blob[v] # NoVal /\ blob[v] = cval[w]
          /\ LET f == verOwner[v] IN
             /\ verStatus' = [verStatus EXCEPT ![v] = "available"]
             /\ verVal' = [verVal EXCEPT ![v] = cval[w]]
             /\ IF verAutoBind[v] /\ content[f] = NoVer
                THEN content' = [content EXCEPT ![f] = v]   \* B.2
                ELSE UNCHANGED content
          /\ ClientDone(w)
          /\ UNCHANGED <<ex, createdF, fileGen, verOwner, verAutoBind, verCreated,
                         blobVars, idemVars, tick, deleterVars, readerVars>>

(* U.5 crash: abandon mid-flow at any point; the version stays exactly as
   it is (possibly pending with real bytes already published). *)
Crash(w) ==
    /\ pc[w] # "idle"
    /\ ClientDone(w)
    /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>

(***************************** B: bind *************************************)

(* B.1 manual bind -> bind_atomic_with_event -> bind_content_cas +
   clear_current/set_current. `bind()`'s precondition check (If-Match None / "*" /
   a specific etag) is NOT what the DB CAS itself compares against --
   re-reading `domain/service/write.rs::bind` + `FileRepo::bind_content_cas`
   confirms `bind_atomic_with_event` is ALWAYS called with
   `expected_content_id = file.content_id`, i.e. THIS SAME call's own
   fresh read, taken moments earlier in the SAME function -- for all three
   If-Match modes. The precondition check only decides whether the request
   is even attempted; the actual `UPDATE ... WHERE content_id = :expected`
   never compares against anything a client could have cached from an
   EARLIER, separate call. So:
   - **None** (no header): legal only when that fresh read is already
     `NULL` -- checked and used in the very same instant, so it can never
     be "stale" the way a client-cached value can.
   - **"*"**: skips the MATCH check but the CAS still runs against the
     fresh read -- also never stale in that sense.
   - **a specific etag**: the precondition compares the CLIENT's
     POSSIBLY-OLD cached etag (from an earlier GET, or an earlier bind's
     own response) against the fresh read; if they still agree the CAS
     proceeds with (trivially) the same value. This is the ONLY mode
     where real cross-request staleness can bite -- modelled as a genuine
     two-phase action (`ReadEtag` now, `BindWithSaved` arbitrarily later,
     with anything at all allowed to interleave). *)

(* B.1 None/"*": both resolve to a same-call fresh CAS -- `BindFresh`
   covers them in one action, since neither can ever observe a value
   other than content[f] has RIGHT NOW. *)
BindFresh(w) ==
    /\ pc[w] = "idle"
    /\ \E f \in Files :
       /\ ex[f]
       /\ \E v \in VerIds :
          /\ verOwner[v] = f /\ verStatus[v] = "available"
          /\ content' = [content EXCEPT ![f] = v]
    /\ UNCHANGED <<ex, createdF, fileGen, verVars, blobVars, idemVars, tick, clientVars, deleterVars, readerVars>>

(* B.1a: the client reads (a GET, or a previous bind/create response) and
   holds `content[f]` as its cached expectation -- ANY other action may
   run before it is ever presented back (B.1b). *)
ReadEtag(w) ==
    /\ pc[w] = "idle"
    /\ \E f \in Files :
       /\ ex[f]
       /\ pc' = [pc EXCEPT ![w] = "holding_etag"]
       /\ cf' = [cf EXCEPT ![w] = f]
       /\ cv' = [cv EXCEPT ![w] = content[f]]
    /\ UNCHANGED <<cval, fileVars, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>

(* B.1b: present the SAVED etag. The precondition (does it still match?)
   and the CAS collapse into the same check here, exactly like the real
   code's "if they still agree the CAS proceeds with the same value" --
   `cv[w] # content[f]` (something else bound/rebound/deleted meanwhile)
   is a genuine lost-update, caught by I8 below, not by this action's own
   guard (there IS no separate guard -- a stale `cv[w]` just makes the
   `THEN` branch not fire, same as a real failed CAS). *)
BindWithSaved(w) ==
    /\ pc[w] = "holding_etag"
    /\ LET f == cf[w] IN
       /\ \E v \in VerIds :
          /\ verOwner[v] = f /\ verStatus[v] = "available"
          /\ IF cv[w] = content[f]
             THEN content' = [content EXCEPT ![f] = v]
             ELSE UNCHANGED content
    /\ ClientDone(w)
    /\ UNCHANGED <<ex, createdF, fileGen, verVars, blobVars, idemVars, tick, deleterVars, readerVars>>

(***************************** D: delete ***********************************)

(* D.1 delete_version_or_whole_file. *)
DeleteVersion(d, f, v) ==
    /\ ex[f]
    /\ v \in minted /\ verOwner[v] = f
    /\ LET live == {u \in minted : verOwner[u] = f} IN
       \/ /\ live = {v}                                 \* only version: whole-file delete
          /\ WipeFile(f)
       \/ /\ live # {v} /\ content[f] = v                \* IsCurrent conflict: no-op
          /\ UNCHANGED <<ex, content, verOwner, blob>>
       \/ /\ live # {v} /\ content[f] # v                \* ordinary version delete
          /\ \E ok \in BOOLEAN : blob' = [blob EXCEPT ![v] = IF ok THEN NoVal ELSE @]
          /\ verOwner' = [verOwner EXCEPT ![v] = NoFile]
          /\ UNCHANGED <<ex, content>>
    /\ UNCHANGED <<createdF, fileGen, verStatus, verAutoBind, verCreated, verVal, everVal, minted,
                   idemVars, tick, clientVars, deleterVars, readerVars>>

(* D.2 delete_file: If-Match **required**. Re-reading
   `FileService::delete_file` + `Store::delete_file_collecting_versions`
   (phase-3b correction -- the earlier revision of this model was WRONG to
   let any variant of the If-Match check be atomic with the delete):
   `require_file` (step D.2a) runs OUTSIDE any transaction and compares
   `etag_for(&file)` from THAT read against the caller's header (`*` always
   passes; `None` never reaches the service, `IF_MATCH_REQUIRED`). If it
   passes, `delete_file_inner` runs as a SEPARATE, LATER transaction
   (step D.2b): it locks the `files` row and deletes it UNCONDITIONALLY,
   **never re-reading or re-comparing `content_id`/the etag**. So EVERY
   delete_file call -- "*" included -- has a real check-then-act gap
   between D.2a and D.2b in which anything (a concurrent bind, in
   particular) may run; there is no CAS here to make any variant of it
   atomic. `dExpect` records what D.2a saw, used only by `I9` to detect the
   lost update this gap allows -- `DoDelete` itself never looks at it
   (finding F3: confirmed violated on the model as written; see the
   report and states-upload.md's F3 entry for the fix). *)
CheckDelete(d) ==
    /\ dPc[d] = "idle"
    /\ \E f \in Files :
       /\ ex[f]
       /\ \E expected \in VerIds \cup {NoVer, Star} :
          IF expected = Star \/ expected = content[f]
          THEN /\ dPc'     = [dPc     EXCEPT ![d] = "ready"]
               /\ dFile'   = [dFile   EXCEPT ![d] = f]
               /\ dExpect' = [dExpect EXCEPT ![d] = content[f]]
               /\ dStar'   = [dStar   EXCEPT ![d] = (expected = Star)]
               /\ dGen'    = [dGen    EXCEPT ![d] = fileGen[f]]
          ELSE UNCHANGED <<dPc, dFile, dExpect, dStar, dGen>>   \* precondition failed: 409/412, no further step
    /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, clientVars, readerVars>>

(* D.2b: lock + delete -- `delete_file_inner` / `Store::
   delete_file_collecting_versions`. The real DELETE is keyed by `file_id`
   (never reused), so it can never land on a DIFFERENT incarnation of a
   recreated row -- it either targets the SAME row D.2a checked, or (if that
   row is truly gone) matches zero rows and no-ops. `fileGen[f] = dGen[d]` is
   exactly that "still the same incarnation" fact (see `fileGen`'s own
   comment); without it, this model's reusable `Files` pool would let a
   stale D.2a/D.2b pair straddle an unrelated delete-then-recreate of the
   same symbolic name, which is a modelling artifact, not F3 (see
   FileStorageUpload_F3.cfg).
   FIX F3 (`FixDeleteIfMatchInTx`): the transaction now re-compares
   `dExpect[d]` (D.2a's saved expectation) against `content[f]` as read
   fresh, in the SAME step as the wipe -- `delete_file`'s `"*"` case
   (`dStar[d]`) carries no `expected_etag` at all (`None`, skip the check,
   `delete_file_inner`'s own doc comment), exactly as before. `FALSE`
   (the unpatched code) wipes unconditionally, no recheck at all -- F3. *)
DoDelete(d) ==
    /\ dPc[d] = "ready"
    /\ LET f == dFile[d] IN
       IF /\ ex[f] /\ fileGen[f] = dGen[d]
          /\ (~FixDeleteIfMatchInTx \/ dStar[d] \/ dExpect[d] = content[f])
       THEN WipeFile(f) ELSE UNCHANGED <<ex, content, verOwner, blob>>
    /\ dPc'     = [dPc     EXCEPT ![d] = "idle"]
    /\ dFile'   = [dFile   EXCEPT ![d] = NoFile]
    /\ dExpect' = [dExpect EXCEPT ![d] = NoVer]
    /\ dStar'   = [dStar   EXCEPT ![d] = FALSE]
    /\ dGen'    = [dGen    EXCEPT ![d] = 0]
    /\ UNCHANGED <<createdF, fileGen, verStatus, verAutoBind, verCreated, verVal, everVal, minted,
                   idemVars, tick, clientVars, readerVars>>

(***************************** S: sweep ************************************)

(* S.1 sweep_abandoned_pending_page -> delete_abandoned_pending_version (+
   maybe_delete_orphaned_file when that was the file's last version and no
   content is bound).  "Any order, any time": always enabled once a
   candidate ages past PendingGrace. *)
SweepAbandonedPending ==
    \E v \in minted :
       /\ verOwner[v] # NoFile /\ verStatus[v] = "pending"
       /\ tick - verCreated[v] > PendingGrace
       /\ LET f == verOwner[v] IN
          /\ \E ok \in BOOLEAN : blob' = [blob EXCEPT ![v] = IF ok THEN NoVal ELSE @]
          /\ verOwner' = [verOwner EXCEPT ![v] = NoFile]
          /\ LET stillLive == {u \in minted : u # v /\ verOwner'[u] = f} IN
             IF stillLive = {} /\ content[f] = NoVer
             THEN ex' = [ex EXCEPT ![f] = FALSE]
             ELSE UNCHANGED ex
          /\ UNCHANGED content
    /\ UNCHANGED <<createdF, fileGen, verStatus, verAutoBind, verCreated, verVal, everVal, minted,
                   idemVars, tick, clientVars, deleterVars, readerVars>>

(* S.2 sweep_retention_expiry_page -> expire_file: unconditional whole-file
   wipe once a file ages past RetentionGrace, no CAS / If-Match. *)
RetentionExpire ==
    \E f \in Files :
       /\ ex[f]
       /\ tick - createdF[f] > RetentionGrace
       /\ WipeFile(f)
    /\ UNCHANGED <<createdF, fileGen, verStatus, verAutoBind, verCreated, verVal, everVal, minted,
                   idemVars, tick, clientVars, deleterVars, readerVars>>

(***************************** R: read *************************************)

(* R.1 download_url: requires the target to be a live, available version of
   an existing file (current or explicitly named -- both are just "some
   available version of f", no special case needed). *)
(* A fresh ticket resets `ans[r]` to `NoVal` -- otherwise I5 could compare
   a PREVIOUS ticket's already-delivered answer against the NEW `rver[r]`
   it no longer describes (a reader issuing ticket #2 before anything
   re-checks ticket #1's answer), a model-formulation artifact unrelated to
   any real protocol race -- see the report's phase-3 note. *)
(* FIX F1 (`FixDownloadHashCheck`): the signed GET claims now carry the
   whole-object hash the DB recorded for this version AT ISSUANCE
   (`Claims::content_sha256`, `rExpect` here) whenever that version is
   whole-object-hash mode (the model has only one hash mode -- see
   states-upload.md's F1 entry for the Range/multipart-composite carve-out,
   not modelled here, this model has no Range/multipart reads at all).
   `DoRead` independently verifies the actual bytes against it before ever
   serving them, instead of trusting the backend path unconditionally.
   `FixDownloadHashCheck = FALSE` leaves `rExpect` unused (`NoVal`) --
   `DoRead` falls back to the unpatched "whatever's at the path" behaviour. *)
IssueDownloadUrl(r) ==
    /\ rpc[r] = "idle"
    /\ \E f \in Files :
       /\ ex[f]
       /\ \E v \in VerIds :
          /\ verOwner[v] = f /\ verStatus[v] = "available"
          /\ rpc'     = [rpc     EXCEPT ![r] = "holding"]
          /\ rver'    = [rver    EXCEPT ![r] = v]
          /\ rExpect' = [rExpect EXCEPT ![r] = IF FixDownloadHashCheck THEN verVal[v] ELSE NoVal]
          /\ ans'     = [ans     EXCEPT ![r] = NoVal]
    /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, clientVars, deleterVars>>

(* R.2 sidecar download: never consults the DB -- only the physical blob at
   this version id's path matters, so a ticket can outlive its row (D/S
   deleted it after R.1) and still read correctly, or correctly miss once
   the blob is actually gone. With `FixDownloadHashCheck`, a mismatch between
   the live blob and the hash recorded at issuance (`rExpect[r]`) aborts the
   stream mid-flight (`verify_whole_object_download_stream`) instead of
   completing it -- modelled as `Miss` (no value is ever actually delivered
   to the caller either way; I5 only cares that a WRONG value is never
   returned as if it were good). *)
DoRead(r) ==
    /\ rpc[r] = "holding"
    /\ ans' = [ans EXCEPT ![r] =
                 IF blob[rver[r]] = NoVal THEN Miss
                 ELSE IF FixDownloadHashCheck /\ blob[rver[r]] # rExpect[r]
                      THEN Miss
                      ELSE blob[rver[r]]]
    /\ rpc' = [rpc EXCEPT ![r] = "idle"]
    /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, tick, clientVars, deleterVars, rver, rExpect>>

(***************************** clock ***************************************)

Tick ==
    /\ tick < MaxTick
    /\ tick' = tick + 1
    /\ UNCHANGED <<fileVars, verVars, blobVars, idemVars, clientVars, deleterVars, readerVars>>

(***************************** next / spec *********************************)

CoreNext ==
    \/ \E w \in Clients :
          CreateNewFile(w) \/ ReplayIdempotency(w) \/ PresignAddVersion(w)
          \/ StaleRetryPut(w) \/ Put(w) \/ Finalize(w) \/ Crash(w)
          \/ BindFresh(w) \/ ReadEtag(w) \/ BindWithSaved(w)
    \/ \E d \in Deleters, f \in Files, v \in VerIds : DeleteVersion(d, f, v)
    \/ \E d \in Deleters :
          CheckDelete(d) \/ DoDelete(d)
    \/ SweepAbandonedPending
    \/ RetentionExpire
    \/ Tick

Next ==
    \/ CoreNext
    \/ \E r \in Readers : IssueDownloadUrl(r) \/ DoRead(r)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* TypeOK *)

TypeOK ==
    /\ ex          \in [Files -> BOOLEAN]
    /\ content     \in [Files -> VerIds \cup {NoVer}]
    /\ createdF    \in [Files -> 0..MaxTick]
    /\ fileGen     \in [Files -> Nat]   \* naturally bounded by Cardinality(VerIds): CreateNewFile
                                        \* needs an unminted version id, and `minted` only grows
    /\ verOwner    \in [VerIds -> Files \cup {NoFile}]
    /\ verStatus   \in [VerIds -> {"pending", "available"}]
    /\ verAutoBind \in [VerIds -> BOOLEAN]
    /\ verCreated  \in [VerIds -> 0..MaxTick]
    /\ verVal      \in [VerIds -> Values \cup {NoVal}]
    /\ everVal     \in [VerIds -> Values \cup {NoVal}]
    /\ blob        \in [VerIds -> Values \cup {NoVal}]
    /\ minted      \subseteq VerIds
    /\ idemFile    \in [IdemKeys -> Files \cup {NoFile}]
    /\ idemVer     \in [IdemKeys -> VerIds \cup {NoVer}]
    /\ tick        \in 0..MaxTick
    /\ pc          \in [Clients -> CPCs]
    /\ cf          \in [Clients -> Files \cup {NoFile}]
    /\ cv          \in [Clients -> VerIds \cup {NoVer}]
    /\ cval        \in [Clients -> Values \cup {NoVal}]
    /\ rpc         \in [Readers -> RPCs]
    /\ rver        \in [Readers -> VerIds \cup {NoVer}]
    /\ ans         \in [Readers -> Values \cup {NoVal, Miss}]
    /\ rExpect     \in [Readers -> Values \cup {NoVal}]
    /\ dPc         \in [Deleters -> DPCs]
    /\ dFile       \in [Deleters -> Files \cup {NoFile}]
    /\ dExpect     \in [Deleters -> VerIds \cup {NoVer}]
    /\ dStar       \in [Deleters -> BOOLEAN]
    /\ dGen        \in [Deleters -> Nat]

(* I1 (J1): files.content_id always resolves to a live, available version
   whose DB-recorded hash (verVal, file_versions.hash_value/size) matches
   the real backend bytes at its path -- this is exactly the guarantee
   U.3.2's read-back verification exists to provide (mutation u1 breaks
   it). *)
I1_NoDanglingContent ==
    \A f \in Files :
       (ex[f] /\ content[f] # NoVer) =>
          /\ verOwner[content[f]] = f
          /\ verStatus[content[f]] = "available"
          /\ verVal[content[f]] # NoVal
          /\ blob[content[f]] = verVal[content[f]]

(* I2 (J2): every available version's recorded hash really matches its
   bytes, right now. *)
I2_AvailableHasBlob ==
    \A v \in VerIds :
       (verOwner[v] # NoFile /\ verStatus[v] = "available") =>
          /\ verVal[v] # NoVal
          /\ blob[v] = verVal[v]

(* I3 (J3), action property: content[f] only ever changes to NoVer (a
   delete ran) or to a version that is live + available in the NEXT state
   -- no step corrupts the pointer to an illegitimate target. *)
I3_BoundNotLost ==
    [][ \A f \in Files :
          (content[f] # content'[f]) =>
             \/ content'[f] = NoVer
             \/ (verOwner'[content'[f]] = f /\ verStatus'[content'[f]] = "available")
      ]_vars

(* I4 (candidate finding, see states-upload.md / the report): in a fully quiesced
   state (every actor idle, every clock exhausted), no blob should survive
   with no row referencing it.  Expected to be VIOLATED -- this is the
   model-checked confirmation of the documented P2 gap ("Backend
   blob-without-row reconciliation... is deferred to P3",
   concurrency-and-failure-model.md Sec. 5), not a new bug.  Kept out of
   the main invariant list (see FileStorageUpload_witness.cfg) so a hit
   here does not stop TLC from exhaustively checking I1/I2/I3/I5/I6/I7. *)
Quiescent ==
    /\ tick = MaxTick
    /\ \A w \in Clients : pc[w] = "idle"
    /\ \A r \in Readers : rpc[r] = "idle"

I4_NoPermanentOrphan ==
    Quiescent => (\A v \in VerIds : ~(blob[v] # NoVal /\ verOwner[v] = NoFile))

(* I5 (J5): a finished read never returns anything but the one-true,
   ever-published content of the version id its ticket names, or a miss.
   With `FixDownloadHashCheck = FALSE` (the unpatched code), violated by
   finding F1: a stale-but-unexpired PUT token can publish NEW bytes at a
   version id's path after that version's row AND backend blob were both
   legitimately deleted, and a download ticket issued before the delete
   then observes those new bytes instead of a miss -- see
   `FileStorageUpload_F1.cfg`. With `FixDownloadHashCheck = TRUE` (the
   shipped fix: the GET claims carry the hash recorded at issuance, the
   sidecar aborts the stream on a mismatch), expected to HOLD -- part of the
   main/medium invariant list. *)
I5_ReadExactOrMiss ==
    \A r \in Readers : ans[r] \in Values => ans[r] = everVal[rver[r]]

(* I6 (J6), action property: "bytes never mutate in place" -- a blob goes
   NoVal -> val (first PUT) or val -> NoVal (a delete/sweep's best-effort
   removal), never val1 -> val2. *)
I6_AvailableImmutable ==
    [][ \A v \in VerIds : (blob[v] # NoVal /\ blob'[v] # NoVal) => blob'[v] = blob[v] ]_vars

(* I7 (J7), action property: an idempotency key, once bound to a file, is
   bound to that same file forever -- it can never be replayed into a
   second, different file. *)
I7_IdempotencyNoDuplicate ==
    [][ \A k \in IdemKeys : idemFile[k] # NoFile => idemFile'[k] = idemFile[k] ]_vars

(* I8 (phase 3), action property: a two-phase bind (`BindWithSaved`) that
   actually changes `content[cf[w]]` must have found its SAVED expectation
   (`cv[w]`, read at the earlier `ReadEtag`) still equal to the live
   pointer at the moment it committed -- the lost-update guarantee
   `bind_content_cas`'s `WHERE content_id = :expected` exists to provide.
   Mutation u2 (CAS removed from `BindWithSaved`) violates exactly this. *)
I8_SavedBindRespectsCAS ==
    [][ \A w \in Clients :
          (pc[w] = "holding_etag" /\ pc'[w] = "idle" /\ content[cf[w]] # content'[cf[w]])
             => cv[w] = content[cf[w]]
      ]_vars

(* I9 (phase 3b): `delete_file`'s If-Match pass (D.2a, `CheckDelete`) saw
   `content[f] = dExpect[d]` at check time; this asks whether that is STILL
   true the instant `DoDelete` (D.2b) actually commits the wipe -- i.e.
   whether delete_file_inner's missing recheck can ever destroy content the
   checked precondition never approved. With `FixDeleteIfMatchInTx = FALSE`
   (the unpatched code), VIOLATED (finding F3, states-upload.md) because
   `DoDelete` genuinely never rechecks. With `FixDeleteIfMatchInTx = TRUE`,
   `DoDelete` now DOES recheck -- but this GENERAL form is still expected to
   be violated, by design, via the `"*"`/`dStar[d]` disjunct (`If-Match: *`
   deliberately skips the check -- "delete whatever is there" is not a lost
   update): see `I9_SavedDeleteRespectsCAS_SpecificEtag` below for the
   restricted form the fix actually closes. *)
I9_SavedDeleteRespectsCAS ==
    [][ \A d \in Deleters :
          (dPc[d] = "ready" /\ dPc'[d] = "idle" /\ ex[dFile[d]] /\ ~ex'[dFile[d]])
             => dExpect[d] = content[dFile[d]]
      ]_vars

(* I9, restricted to a CONCRETE etag (`dStar[d] = FALSE`) that named a REAL
   bound version (`dExpect[d] # NoVer`) -- i.e. excludes both the `*`
   wildcard ("delete whatever is there", not a lost update by the client's
   own request) and the trivial "If-Match: <no content bound yet>" shape.
   With `FixDeleteIfMatchInTx = FALSE`, violated: the F3 finding config
   (FileStorageUpload_F3.cfg) reports "client read etag E_v1 for a file
   bound to v1, the check passed, a concurrent bind retargeted the file to
   v2, then the unconditional wipe destroyed v2's binding" -- the scenario
   states-upload.md's F3 entry describes, not the `If-Match: *` shape (which
   is not a bug: `*` means "delete whatever it is"). With
   `FixDeleteIfMatchInTx = TRUE` (the shipped fix), expected to HOLD -- part
   of the main/medium PROPERTIES list. *)
I9_SavedDeleteRespectsCAS_SpecificEtag ==
    [][ \A d \in Deleters :
          (dPc[d] = "ready" /\ dPc'[d] = "idle" /\ ex[dFile[d]] /\ ~ex'[dFile[d]]
             /\ ~dStar[d] /\ dExpect[d] # NoVer)
             => dExpect[d] = content[dFile[d]]
      ]_vars

(* sanity witnesses (not part of the main verification -- see
   FileStorageUpload_witness.cfg and the report) *)
NeverBound    == \A f \in Files : content[f] = NoVer
NeverMiss     == \A r \in Readers : ans[r] # Miss
NeverIdemUsed == \A k \in IdemKeys : idemFile[k] = NoFile

(* Optional SYMMETRY (invariants only -- see the credstore sibling's own
   README: sound for state invariants, not for the action PROPERTIES
   (I3/I6/I7), so a cfg using this drops the PROPERTIES section). Clients
   and Readers are each fully interchangeable (no identity-dependent
   state); Deleters already carries no state at all. *)
SymmClients  == Permutations(Clients)
SymmReaders  == Permutations(Readers)
SymmDeleters == Permutations(Deleters)
Symmetry == SymmClients \cup SymmReaders \cup SymmDeleters
==============================================================================
