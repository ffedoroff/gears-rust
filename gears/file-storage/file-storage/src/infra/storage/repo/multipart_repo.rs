//! Repository for `multipart_uploads` and `multipart_upload_parts`.
//!
//! No `tenant_id` column, so all queries use `AccessScope::allow_all()`; the tenant
//! boundary is enforced through the parent `files` row before a session is created.

use sea_orm::sea_query::LockType;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set};
use time::OffsetDateTime;
use toolkit_db::secure::{
    DBRunner, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureOnConflict, SecureUpdateExt,
    secure_insert,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::multipart::{MultipartPart, MultipartUploadSession, MultipartUploadState};
use crate::infra::storage::db::db_err;
use crate::infra::storage::entity::multipart_upload::{
    ActiveModel as UploadActiveModel, Column as UploadColumn, Entity as UploadEntity,
    Model as UploadModel,
};
use crate::infra::storage::entity::multipart_upload_part::{
    ActiveModel as PartActiveModel, Column as PartColumn, Entity as PartEntity, Model as PartModel,
};

/// Repository for multipart upload sessions and their parts.
#[derive(Clone, Default)]
pub struct MultipartRepo;

impl MultipartRepo {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Insert a new multipart upload session row. `backend_id`/`backend_path` are the
    /// backend and object path of the pending version; `None` only for a hand-built legacy
    /// test row.
    #[allow(clippy::too_many_arguments)]
    pub async fn create<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
        backend_upload_handle: &str,
        backend_id: Option<&str>,
        backend_path: Option<&str>,
        declared_mime: &str,
        declared_size: u64,
        part_size: u64,
        auto_bind: bool,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let declared_size_i64 = i64::try_from(declared_size)
            .map_err(|_| DomainError::validation("declared_size", "declared_size overflows i64"))?;
        let part_size_i64 = i64::try_from(part_size)
            .map_err(|_| DomainError::validation("part_size", "part_size overflows i64"))?;
        let am = UploadActiveModel {
            upload_id: Set(upload_id),
            file_id: Set(file_id),
            version_id: Set(version_id),
            backend_upload_handle: Set(backend_upload_handle.to_owned()),
            state: Set("in_progress".to_owned()),
            declared_mime: Set(declared_mime.to_owned()),
            mime_validated: Set(false),
            declared_size: Set(declared_size_i64),
            part_size: Set(part_size_i64),
            auto_bind: Set(auto_bind),
            lease_until: Set(None),
            lease_owner: Set(None),
            complete_result: Set(None),
            backend_id: Set(backend_id.map(str::to_owned)),
            backend_path: Set(backend_path.map(str::to_owned)),
            created_at: Set(now),
            expires_at: Set(expires_at),
        };
        secure_insert::<UploadEntity>(am, &AccessScope::allow_all(), conn)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// Lock a `multipart_uploads` row with `SELECT ... FOR UPDATE` and return its `state`, or
    /// `None` if no such session exists.
    ///
    /// Call only as the transaction's FIRST statement (parent-before-children ordering, no
    /// I/O while held; see `FileRepo::lock_for_update`). `Store::finalize_multipart_version`
    /// takes it before touching `file_versions`/`files`, so it cannot commit against a session
    /// that the abandoned-session sweep concurrently moved out of `completing`
    /// (`Self::abort_expired_completing`): one transaction blocks until the other commits.
    ///
    /// On `SQLite`, `.lock(..)` renders nothing; its single-writer model gives the guarantee.
    pub async fn lock_session_state<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
    ) -> Result<Option<String>, DomainError> {
        let found = UploadEntity::find()
            .filter(UploadColumn::UploadId.eq(upload_id))
            .lock(LockType::Update)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .one(conn)
            .await
            .map_err(db_err)?;
        Ok(found.map(|m| m.state))
    }

    /// Fetch a multipart upload session by `upload_id`.
    pub async fn get<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
    ) -> Result<Option<MultipartUploadSession>, DomainError> {
        let found = UploadEntity::find()
            .filter(UploadColumn::UploadId.eq(upload_id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .one(conn)
            .await
            .map_err(db_err)?;
        found.map(session_from_model).transpose()
    }

    /// Compare-and-set the session `state`: transitions to `new_state` only if currently
    /// `expected_state`. Returns `false` on a stale transition (e.g. a `complete`/`abort`
    /// race).
    ///
    /// `mime_validated`, when `Some`, is set in the same UPDATE (`complete` passes `true` after
    /// sniffing; `abort` passes `None`).
    ///
    /// [`Self::upsert_part`] also uses it with `expected_state == new_state == "in_progress"`
    /// purely to take the row lock of a matching `UPDATE`.
    pub async fn update_state<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        expected_state: &str,
        new_state: &str,
        mime_validated: Option<bool>,
    ) -> Result<bool, DomainError> {
        use sea_orm::sea_query::Expr;
        let mut update =
            UploadEntity::update_many().col_expr(UploadColumn::State, Expr::value(new_state));
        if let Some(validated) = mime_validated {
            update = update.col_expr(UploadColumn::MimeValidated, Expr::value(validated));
        }
        let res = update
            .filter(
                sea_orm::Condition::all()
                    .add(UploadColumn::UploadId.eq(upload_id))
                    .add(UploadColumn::State.eq(expected_state)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Acquire (or take over) the completion lease: one conditional UPDATE moving the session
    /// to `completing` from `in_progress` or an **expired** `completing`. Never blocks and
    /// never holds a transaction across I/O; `false` = a live lease is held elsewhere, the
    /// session is terminal, or it has expired.
    ///
    /// Fenced by `expires_at > now` in the CAS itself: the service's `expires_at <= now` check
    /// runs on an earlier-loaded snapshot and cannot see a session that expired since, so the
    /// row, not a stale copy, decides.
    pub async fn acquire_complete_lease<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        owner: &str,
        lease_until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        use sea_orm::sea_query::Expr;
        let res = UploadEntity::update_many()
            .col_expr(UploadColumn::State, Expr::value("completing"))
            .col_expr(UploadColumn::LeaseUntil, Expr::value(lease_until))
            .col_expr(UploadColumn::LeaseOwner, Expr::value(owner))
            .filter(
                sea_orm::Condition::all()
                    .add(UploadColumn::UploadId.eq(upload_id))
                    .add(UploadColumn::ExpiresAt.gt(now))
                    .add(
                        sea_orm::Condition::any()
                            .add(UploadColumn::State.eq("in_progress"))
                            .add(
                                sea_orm::Condition::all()
                                    .add(UploadColumn::State.eq("completing"))
                                    .add(UploadColumn::LeaseUntil.lt(now)),
                            ),
                    ),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Release a held completion lease back to `in_progress` (assembly failed, so the next
    /// `complete` retries immediately). Scoped to `owner` so a takeover's lease is never
    /// clobbered by the crashed original.
    pub async fn release_complete_lease<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        owner: &str,
    ) -> Result<bool, DomainError> {
        use sea_orm::sea_query::Expr;
        let res = UploadEntity::update_many()
            .col_expr(UploadColumn::State, Expr::value("in_progress"))
            .col_expr(
                UploadColumn::LeaseUntil,
                Expr::value(Option::<OffsetDateTime>::None),
            )
            .col_expr(
                UploadColumn::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .filter(
                sea_orm::Condition::all()
                    .add(UploadColumn::UploadId.eq(upload_id))
                    .add(UploadColumn::State.eq("completing"))
                    .add(UploadColumn::LeaseOwner.eq(owner)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Abort a `completing` session whose lease has EXPIRED (completer died mid-assembly):
    /// CAS `completing AND lease_until < now` -> `aborted`. A live lease never matches.
    pub async fn abort_expired_completing<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        use sea_orm::sea_query::Expr;
        let res = UploadEntity::update_many()
            .col_expr(UploadColumn::State, Expr::value("aborted"))
            .col_expr(
                UploadColumn::LeaseUntil,
                Expr::value(Option::<OffsetDateTime>::None),
            )
            .col_expr(
                UploadColumn::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .filter(
                sea_orm::Condition::all()
                    .add(UploadColumn::UploadId.eq(upload_id))
                    .add(UploadColumn::State.eq("completing"))
                    .add(UploadColumn::LeaseUntil.lt(now)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Terminal transition `completing -> completed`, persisting the response snapshot
    /// (`complete_result` JSON) and clearing the lease.
    ///
    /// `expected_owner`: when `Some`, the CAS also requires `lease_owner = expected_owner`, so
    /// a foreign or taken-over lease cannot complete the session (as
    /// `release_complete_lease`/`acquire_complete_lease` already fence).
    ///
    /// `None` omits that predicate for one caller only: `Store::finalize_multipart_version`'s
    /// embedded call, in the SAME transaction as that caller's just-won finalize CAS. That CAS
    /// is fenced only by `status = 'pending'`, so a completer whose lease was taken over can
    /// still win it, and the outcome is correct regardless (deterministic reassembly from the
    /// same persisted parts). Requiring the owner here would re-strand the race covered by
    /// `f2_stale_completer_converges_instead_of_stranding_after_owner_fencing_fix`. Every other
    /// caller passes `Some`.
    ///
    /// `None` also accepts `state = 'in_progress'`, not just `'completing'`: after the finalize
    /// CAS the version is becoming `available`, but another completer that took over the lease
    /// may since have lost its race and released it back to `in_progress`. Without that arm the
    /// session would stay stuck there although its version is `available`. `aborted` and
    /// `completed` are deliberately never matched.
    pub async fn finish_complete<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        expected_owner: Option<&str>,
        result_json: &str,
    ) -> Result<bool, DomainError> {
        use sea_orm::sea_query::Expr;
        let mut condition = sea_orm::Condition::all().add(UploadColumn::UploadId.eq(upload_id));
        condition = match expected_owner {
            Some(owner) => condition
                .add(UploadColumn::State.eq("completing"))
                .add(UploadColumn::LeaseOwner.eq(owner)),
            None => condition.add(
                sea_orm::Condition::any()
                    .add(UploadColumn::State.eq("completing"))
                    .add(UploadColumn::State.eq("in_progress")),
            ),
        };
        let res = UploadEntity::update_many()
            .col_expr(UploadColumn::State, Expr::value("completed"))
            .col_expr(UploadColumn::MimeValidated, Expr::value(true))
            .col_expr(UploadColumn::CompleteResult, Expr::value(result_json))
            .col_expr(
                UploadColumn::LeaseUntil,
                Expr::value(Option::<OffsetDateTime>::None),
            )
            .col_expr(
                UploadColumn::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .filter(condition)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Force-set a session's `expires_at`. **Test-support only; do not call in production.**
    ///
    /// Lets tests backdate a session after a successful `complete` without a real sleep.
    /// `#[doc(hidden)]` rather than `#[cfg(test)]` or a feature, because the external
    /// integration-test crate calls it and a feature would break plain `cargo test`.
    #[doc(hidden)]
    pub async fn set_expires_at<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        use sea_orm::sea_query::Expr;
        UploadEntity::update_many()
            .col_expr(UploadColumn::ExpiresAt, Expr::value(expires_at))
            .filter(UploadColumn::UploadId.eq(upload_id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// Insert or update one part row, guarded by a same-transaction check that the parent
    /// session is still `in_progress`. `conn` must be bound to the same transaction as the
    /// caller's other work (see `Store::upsert_multipart_part`, the only caller). This closes
    /// a part accepted after `complete` snapshotted the part list, and a part inserted after
    /// `abort` already deleted the parts (a permanent orphan, as session rows are never
    /// deleted).
    ///
    /// The guard is a dummy `in_progress -> in_progress` self-CAS through
    /// [`Self::update_state`], not a plain `SELECT`: Postgres row-locks every row an `UPDATE`
    /// matches, so this both checks the state now and makes any concurrent CAS on the same
    /// session (`abort`'s `-> aborted`, `acquire_complete_lease`'s `-> completing`) block until
    /// this transaction ends and re-evaluate its `WHERE`. An unlocked re-read would not close
    /// the race: under `READ COMMITTED` both transactions can read `in_progress` and commit in
    /// either order, leaving a part row after the abort's cleanup already ran.
    ///
    /// # Returns
    ///
    /// `true` if the part row was written; `false` if the session is not `in_progress`, in
    /// which case the part row is left untouched.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_part<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
        part_number: i32,
        backend_etag: &str,
        part_hash: Vec<u8>,
        size: i64,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let locked = self
            .update_state(conn, upload_id, "in_progress", "in_progress", None)
            .await?;
        if !locked {
            return Ok(false);
        }

        // Single `INSERT ... ON CONFLICT (upload_id, part_number) DO UPDATE`: a
        // DELETE-then-INSERT pair would leave an instant with no row, which a racing
        // `complete_multipart_upload` could snapshot. `SecureOnConflict` is the standard
        // entry point (its tenant check is moot: this entity has no tenant column).
        let on_conflict =
            SecureOnConflict::<PartEntity>::columns([PartColumn::UploadId, PartColumn::PartNumber])
                .update_columns([
                    PartColumn::BackendEtag,
                    PartColumn::PartHash,
                    PartColumn::Size,
                    PartColumn::UploadedAt,
                ])
                .map_err(db_err)?;

        let am = PartActiveModel {
            upload_id: Set(upload_id),
            part_number: Set(part_number),
            backend_etag: Set(backend_etag.to_owned()),
            part_hash: Set(part_hash),
            size: Set(size),
            uploaded_at: Set(now),
        };
        PartEntity::insert(am)
            .secure()
            .scope_unchecked(&AccessScope::allow_all())
            .map_err(db_err)?
            .on_conflict(on_conflict)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(true)
    }

    /// Delete all `multipart_upload_parts` rows for `upload_id`; returns the number removed.
    ///
    /// Called from the abort flow (user abort and expired-session cleanup). The session row
    /// is never deleted and nothing cascades from a state flip, so part rows would
    /// otherwise grow unbounded. Not called from `complete`.
    pub async fn delete_parts_for_upload<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
    ) -> Result<u64, DomainError> {
        let res = PartEntity::delete_many()
            .filter(PartColumn::UploadId.eq(upload_id))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected)
    }

    /// List all parts for an upload, ordered by `part_number` ascending.
    pub async fn list_parts<C: DBRunner>(
        &self,
        conn: &C,
        upload_id: Uuid,
    ) -> Result<Vec<MultipartPart>, DomainError> {
        let rows = PartEntity::find()
            .filter(PartColumn::UploadId.eq(upload_id))
            .order_by_asc(PartColumn::PartNumber)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(part_from_model).collect()
    }

    /// List `in_progress` (or lease-lapsed `completing`) sessions whose `expires_at` is
    /// before `now`, for the cleanup sweep.
    ///
    /// Ordered `(expires_at, upload_id)` ascending, up to `limit` rows. `after`, when `Some`,
    /// restricts to rows strictly after that key (keyset pagination, portable across
    /// `PostgreSQL` and `SQLite`), so the sweep can page past candidates it did not reap
    /// (see `CleanupEngine::run_sweep`).
    pub async fn list_expired<C: DBRunner>(
        &self,
        conn: &C,
        now: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<MultipartUploadSession>, DomainError> {
        let mut filter = sea_orm::Condition::all()
            .add(UploadColumn::ExpiresAt.lt(now))
            .add(
                sea_orm::Condition::any()
                    .add(UploadColumn::State.eq("in_progress"))
                    // A `completing` session past its lifetime is abandoned only once its lease
                    // has expired too, so a live completer is never reaped mid-flight.
                    .add(
                        sea_orm::Condition::all()
                            .add(UploadColumn::State.eq("completing"))
                            .add(UploadColumn::LeaseUntil.lt(now)),
                    ),
            );
        if let Some((after_expires_at, after_upload_id)) = after {
            filter = filter.add(super::tuple_gt(
                (UploadEntity, UploadColumn::ExpiresAt),
                (UploadEntity, UploadColumn::UploadId),
                after_expires_at,
                after_upload_id,
            ));
        }
        let rows = UploadEntity::find()
            .filter(filter)
            .order_by_asc(UploadColumn::ExpiresAt)
            .order_by_asc(UploadColumn::UploadId)
            .limit(limit)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(session_from_model).collect()
    }

    /// Whether `file_id` has an active (`in_progress` or `completing`) multipart session,
    /// regardless of `expires_at`/`lease_until`.
    ///
    /// Guards orphan-file reconciliation: a pending version keyed only on age can look
    /// abandoned while a not-yet-reaped session uses it, and deleting the `files` row would
    /// cascade the session away. A `completing` session with an expired lease still counts
    /// until `sweep_expired_multipart` reaps it.
    ///
    /// Existence uses `LIMIT 1` + `one()`, never `COUNT(*)`.
    pub async fn has_active_for_file<C: DBRunner>(
        &self,
        conn: &C,
        file_id: Uuid,
    ) -> Result<bool, DomainError> {
        let row = UploadEntity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(UploadColumn::FileId.eq(file_id))
                    .add(
                        sea_orm::Condition::any()
                            .add(UploadColumn::State.eq("in_progress"))
                            .add(UploadColumn::State.eq("completing")),
                    ),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .limit(1)
            .one(conn)
            .await
            .map_err(db_err)?;
        Ok(row.is_some())
    }
}

fn session_from_model(m: UploadModel) -> Result<MultipartUploadSession, DomainError> {
    // A persisted state we cannot parse is a data-contract violation, not an
    // `in_progress` session — surface it rather than manufacturing a default
    // that would let callers operate on a bogus session.
    let state = MultipartUploadState::parse(&m.state).ok_or_else(|| {
        DomainError::database(format!(
            "invalid multipart upload state in DB for {}: {}",
            m.upload_id, m.state
        ))
    })?;
    let declared_size = u64::try_from(m.declared_size).unwrap_or(0);
    let part_size = u64::try_from(m.part_size).unwrap_or(0);
    Ok(MultipartUploadSession {
        upload_id: m.upload_id,
        file_id: m.file_id,
        version_id: m.version_id,
        backend_upload_handle: m.backend_upload_handle,
        state,
        declared_mime: m.declared_mime,
        mime_validated: m.mime_validated,
        declared_size,
        part_size,
        auto_bind: m.auto_bind,
        lease_until: m.lease_until,
        complete_result: m.complete_result,
        backend_id: m.backend_id,
        backend_path: m.backend_path,
        created_at: m.created_at,
        expires_at: m.expires_at,
    })
}

fn part_from_model(m: PartModel) -> Result<MultipartPart, DomainError> {
    // Part numbers are `> 0` by DB CHECK; a value that does not fit `u32` is
    // corruption, not part `0`.
    let part_number = u32::try_from(m.part_number).map_err(|_| {
        DomainError::database(format!(
            "invalid part_number in DB for upload {}: {}",
            m.upload_id, m.part_number
        ))
    })?;
    Ok(MultipartPart {
        upload_id: m.upload_id,
        part_number,
        backend_etag: m.backend_etag,
        part_hash: m.part_hash,
        size: m.size,
        uploaded_at: m.uploaded_at,
    })
}
