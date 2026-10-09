//! Repository for the `idempotency_keys` table.
//!
//! Insert-or-fetch: the first call stores the record, a retry gets it back unchanged.
//! Queries are keyed by `(tenant_id, owner_kind, owner_id, key)`.

use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set};
use time::OffsetDateTime;
use toolkit_db::secure::{DBRunner, SecureDeleteExt, SecureEntityExt, secure_insert};
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::idempotency::IdempotencyRecord;
use crate::infra::storage::db::{conflict_on_unique_violation, db_err};
use crate::infra::storage::entity::idempotency_key::{ActiveModel, Column, Entity, Model};
use crate::infra::storage::store::IdempotencyInsert;

/// Repository for idempotency key records.
#[derive(Clone, Default)]
pub struct IdempotencyRepo;

impl IdempotencyRepo {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Fetch an idempotency record if it exists and has not expired.
    pub async fn get<C: DBRunner>(
        &self,
        conn: &C,
        tenant_id: Uuid,
        owner_kind: &str,
        owner_id: Uuid,
        key: &str,
        now: OffsetDateTime,
    ) -> Result<Option<IdempotencyRecord>, DomainError> {
        let found = Entity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(Column::TenantId.eq(tenant_id))
                    .add(Column::OwnerKind.eq(owner_kind))
                    .add(Column::OwnerId.eq(owner_id))
                    .add(Column::IdempotencyKey.eq(key))
                    .add(Column::ExpiresAt.gt(now)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .one(conn)
            .await
            .map_err(db_err)?;
        Ok(found.map(record_from_model))
    }

    /// Insert an idempotency record, first deleting an **expired** row for the same key.
    ///
    /// Runs in the same transaction as the file creation it records. Failures
    /// propagate so the transaction rolls back; a live-key conflict from a racing
    /// create rolls that creation back and the client retries and replays the
    /// winner's record via `get`.
    pub async fn insert<C: DBRunner>(
        &self,
        conn: &C,
        idem: &IdempotencyInsert,
        file_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        // Only a lapsed row is removed; a live row stays so the insert below hits the
        // PK and rolls back, preventing a duplicate file.
        Entity::delete_many()
            .filter(
                Condition::all()
                    .add(Column::TenantId.eq(idem.tenant_id))
                    .add(Column::OwnerKind.eq(idem.owner_kind.clone()))
                    .add(Column::OwnerId.eq(idem.owner_id))
                    .add(Column::IdempotencyKey.eq(idem.key.clone()))
                    .add(Column::ExpiresAt.lte(now)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;

        let am = ActiveModel {
            tenant_id: Set(idem.tenant_id),
            owner_kind: Set(idem.owner_kind.clone()),
            owner_id: Set(idem.owner_id),
            idempotency_key: Set(idem.key.clone()),
            subject_id: Set(idem.subject_id),
            file_id: Set(file_id),
            response_status: Set(idem.response_status),
            response_body: Set(idem.response_body.clone()),
            response_etag: Set(idem.response_etag.clone()),
            request_hash: Set(idem.request_hash.clone()),
            created_at: Set(now),
            expires_at: Set(idem.expires_at),
        };
        // Losing the PK race to a concurrent identical request is the expected dedup
        // path: report a 409 (client re-fetches via `get`), not an opaque 500.
        secure_insert::<Entity>(am, &AccessScope::allow_all(), conn)
            .await
            .map_err(|e| {
                conflict_on_unique_violation(
                    e,
                    "a request with this idempotency key is already being processed or has \
                     already completed",
                )
            })?;
        Ok(())
    }

    /// Delete at most `limit` rows whose `expires_at` is at or before `now`, oldest first.
    ///
    /// Batched so a large backlog never holds one long transaction; fewer than `limit`
    /// removed means the backlog is cleared. Called by the cleanup sweep, because
    /// [`Self::insert`] only removes a lapsed row for its own key.
    ///
    /// The composite PK has no surrogate column and the delete builder lacks
    /// `RETURNING`/tuple-`IN`, so this selects the batch's keys, then deletes by an OR
    /// of exact 4-column matches. Safe because `expires_at` never un-expires, so a
    /// selected candidate stays expired.
    pub async fn delete_expired<C: DBRunner>(
        &self,
        conn: &C,
        now: OffsetDateTime,
        limit: u64,
    ) -> Result<u64, DomainError> {
        #[derive(sea_orm::FromQueryResult)]
        struct ExpiredKey {
            tenant_id: Uuid,
            owner_kind: String,
            owner_id: Uuid,
            idempotency_key: String,
        }

        let candidates = Entity::find()
            .filter(Column::ExpiresAt.lte(now))
            .secure()
            .scope_with(&AccessScope::allow_all())
            .project_all(conn, |q| {
                q.select_only()
                    .column(Column::TenantId)
                    .column(Column::OwnerKind)
                    .column(Column::OwnerId)
                    .column(Column::IdempotencyKey)
                    .order_by_asc(Column::ExpiresAt)
                    .order_by_asc(Column::TenantId)
                    .order_by_asc(Column::OwnerKind)
                    .order_by_asc(Column::OwnerId)
                    .order_by_asc(Column::IdempotencyKey)
                    .limit(limit)
                    .into_model::<ExpiredKey>()
            })
            .await
            .map_err(db_err)?;

        if candidates.is_empty() {
            return Ok(0);
        }

        let mut matches = Condition::any();
        for c in &candidates {
            matches = matches.add(
                Condition::all()
                    .add(Column::TenantId.eq(c.tenant_id))
                    .add(Column::OwnerKind.eq(c.owner_kind.clone()))
                    .add(Column::OwnerId.eq(c.owner_id))
                    .add(Column::IdempotencyKey.eq(c.idempotency_key.clone())),
            );
        }

        let res = Entity::delete_many()
            .filter(matches)
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected)
    }
}

fn record_from_model(m: Model) -> IdempotencyRecord {
    IdempotencyRecord {
        file_id: m.file_id,
        subject_id: m.subject_id,
        response_status: u16::try_from(m.response_status).unwrap_or(201),
        response_body: m.response_body,
        response_etag: m.response_etag,
        request_hash: m.request_hash,
    }
}
