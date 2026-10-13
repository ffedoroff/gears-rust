// Updated: 2026-10-06 by Constructor Tech
//! Consumer contract for tenant-scoped credential operations (ADR-0004,
//! "Read actions follow the projection"; ADR-0007 for writes).
//!
//! Defines anti-enumerating reads over one item shape — the record
//! ([`crate::models::Credential`]) and its value ([`crate::models::Secret`]),
//! served by a separate method — and explicit optimistic-concurrency
//! preconditions on every write.

use crate::models::{
    Credential, CredentialListItem, CredentialPatch, CredentialWrite, PutOutcome, PutPrecondition,
    Secret, SecretRef, Validator, WritePrecondition,
};
use async_trait::async_trait;
use toolkit_canonical_errors::CanonicalError;
use toolkit_odata::{ODataQuery, Page};
use toolkit_security::SecurityContext;

/// Consumer-facing API trait for credential storage operations.
///
/// Every fallible method returns [`CanonicalError`], the platform's canonical
/// error type (ADR 0005 of the platform error architecture); no
/// credstore-specific error type appears in the contract. Consumers that want
/// flat typed dispatch over what the gear emits can project with
/// [`CredStoreError`](crate::CredStoreError) (`.map_err(CredStoreError::from)`,
/// see the [`crate::error`] module docs); consumers that only propagate use
/// `?`. Reason and field codes are in [`crate::reason`] and [`crate::field`].
///
/// Six methods, none named `create` or `read_secrets`: `put` under
/// [`PutPrecondition::CreateOnly`] **is** create, and [`Self::list`] is the
/// collection read (`$select` containing `secret` additionally carries each
/// item's value on the same paginated read, ADR-0005; ADR-0004, "Read actions
/// follow the projection").
#[async_trait]
pub trait CredStoreClientV2: Send + Sync {
    /// Retrieves the credential **record** by reference, applying
    /// hierarchical resolution. Never carries the value — see
    /// [`Self::get_secret`].
    ///
    /// Returns `Ok(Some(_))` for an accessible record — including one whose
    /// caller-tenant row is `declared` (no value) — `Ok(None)` when the
    /// reference resolves to nothing the caller may see (a single 404
    /// surface that prevents enumeration; a record the PDP's constraints
    /// exclude is the same miss), and an error when the PDP or the registry
    /// cannot be reached. The PDP decision is taken before any lookup: a
    /// denial is an error, whether or not the record exists.
    ///
    /// Requires the `read` action.
    ///
    /// Named `get_record`, not `get`: in the v1 API `get` returned the secret
    /// value. The record read never does, so the rename makes every stale
    /// `get` call site fail to compile instead of silently returning `Some`
    /// for a value-less (`declared`) record.
    ///
    /// # Errors
    ///
    /// * [`CanonicalError::PermissionDenied`] → [`crate::CredStoreError::PermissionDenied`]: the caller lacks `read`, or the scope excludes the caller's own tenant (`ACCESS_DENIED`, [`crate::reason::permission_denied::ACCESS_DENIED`]); independent of whether the record exists.
    /// * [`CanonicalError::ServiceUnavailable`] → [`crate::CredStoreError::Unavailable`]: the PDP, the registry or the database is unreachable; a miss included.
    /// * [`CanonicalError::Internal`] → [`crate::CredStoreError::Internal`]: an unexpected internal failure.
    async fn get_record(
        &self,
        ctx: &SecurityContext,
        key: &SecretRef,
    ) -> Result<Option<Credential>, CanonicalError>;

    /// Retrieves the resolved **value**, applying hierarchical resolution. A
    /// winning record with no value (`declared`, or `suppressed`) is the
    /// canonical miss — `Ok(None)`, identical to "does not exist".
    ///
    /// A winning `active` record whose `expires_at` has passed fails with
    /// [`CanonicalError::FailedPrecondition`] (projection
    /// [`crate::CredStoreError::SecretExpired`]; only for a caller whose
    /// decision admits `read_secret` for that record's type): resolution does
    /// not continue to an ancestor's value, and `fallback` does not apply to
    /// expired records. A record the PDP's constraints exclude is the same
    /// miss as a missing one (`Ok(None)`); a denial of the decision itself,
    /// taken before any lookup, is an error whether or not the record exists.
    ///
    /// Requires the `read_secret` action.
    ///
    /// # Errors
    ///
    /// * [`CanonicalError::PermissionDenied`] → [`crate::CredStoreError::PermissionDenied`]: the caller lacks `read_secret`, or the scope excludes the caller's own tenant (`ACCESS_DENIED`, [`crate::reason::permission_denied::ACCESS_DENIED`]); independent of whether the record exists.
    /// * [`CanonicalError::FailedPrecondition`] with [`crate::reason::failed_precondition::SECRET_EXPIRED`] → [`crate::CredStoreError::SecretExpired`]: the winning `active` record is past its `expires_at` and the caller may read its secret.
    /// * [`CanonicalError::ServiceUnavailable`] → [`crate::CredStoreError::Unavailable`]: the PDP, the registry, the database or the storage backend is unreachable; no storage plugin is registered; the store refused the plugin's credentials; the backend still has no value for the record's current version after one re-read.
    /// * [`CanonicalError::Internal`] → [`crate::CredStoreError::Internal`]: a stored version that can never be read, a version gone although the pointer did not move, or an unexpected internal failure.
    async fn get_secret(
        &self,
        ctx: &SecurityContext,
        key: &SecretRef,
    ) -> Result<Option<Secret>, CanonicalError>;

    /// Creates or replaces the whole credential — record and, unless
    /// `write.secret` is an explicit [`crate::models::SecretWrite::Null`], its value
    /// together, in one call. `precondition` carries the intent:
    /// [`PutPrecondition::CreateOnly`] fails with
    /// [`CanonicalError::AlreadyExists`] if the caller's own tenant already
    /// holds a record under the reference; [`PutPrecondition::Exists`] /
    /// [`PutPrecondition::Matches`] fail with [`CanonicalError::Aborted`]
    /// (`OPTIMISTIC_LOCK_FAILURE`) if it does not (a `put` under either never
    /// creates).
    ///
    /// `put` replaces the whole record, so `expires_at: None` clears the
    /// expiry. To rotate the secret and keep the expiry, `patch` with only
    /// `secret`.
    ///
    /// `write.secret` is a [`crate::models::SecretWrite`]: `Set` stores a new value version;
    /// `Null` writes no value — on create the row is inserted `declared`; on
    /// replace of an `active` row the value is removed in the same
    /// transaction; on replace of an already-`declared` row nothing about the
    /// value changes (ADR-0007, "PUT: whole replace, secret tri-state"). A
    /// removal is always an explicit decision; to change metadata (for
    /// example `sharing`) without touching the secret, use `patch`.
    ///
    /// `write` always requires `write`; `write_secret` is additionally
    /// required when `write.secret` is `Set(_)`, or when a `Null` removes an
    /// existing value (replace of an `active` row) — never when `Null`
    /// creates or replaces an already value-less row. Both required actions
    /// are evaluated before any side effect — a caller missing either fails
    /// the whole request.
    ///
    /// # Errors
    ///
    /// * [`CanonicalError::AlreadyExists`] → [`crate::CredStoreError::AlreadyExists`]: `CreateOnly` over an existing own record, an expired one included.
    /// * [`CanonicalError::Aborted`] with [`crate::reason::aborted::OPTIMISTIC_LOCK_FAILURE`] → [`crate::CredStoreError::PreconditionFailed`]: `Exists` or `Matches` when no own record exists (or one of a type the caller may not write), or the `Matches` validator no longer holds.
    /// * [`CanonicalError::Aborted`] with [`crate::reason::aborted::TYPE_IMMUTABLE`] → [`crate::CredStoreError::TypeConflict`]: the replace names a type differing from the stored one; also [`crate::reason::aborted::TYPE_MISMATCH_WITH_INHERITED`] and [`crate::reason::aborted::TYPE_MISMATCH_WITH_DESCENDANT`] for a create over an ancestor's `shared` or a descendant's non-private record of another type.
    /// * [`CanonicalError::InvalidArgument`] → [`crate::CredStoreError::Invalid`]: a violated type trait ([`crate::field::UNKNOWN_SECRET_TYPE`], [`crate::field::SHARING_NOT_ALLOWED_FOR_TYPE`], [`crate::field::VALUE_TOO_LARGE`], [`crate::field::VALUE_NOT_UTF8`], [`crate::field::VALUE_SCHEMA_VIOLATION`], [`crate::field::EXPIRY_NOT_SUPPORTED_FOR_TYPE`], [`crate::field::EXPIRY_IN_THE_PAST`]), or a create naming no `secret_type` ([`crate::field::TYPE_REQUIRED`]).
    /// * [`CanonicalError::PermissionDenied`] → [`crate::CredStoreError::PermissionDenied`]: the caller lacks `write`, or a required `write_secret` (`ACCESS_DENIED`, [`crate::reason::permission_denied::ACCESS_DENIED`]).
    /// * [`CanonicalError::ServiceUnavailable`] → [`crate::CredStoreError::Unavailable`]: the PDP, the registry, the database or the storage backend is unreachable; no storage plugin is registered; the store refused the plugin's credentials (the last two carry no retry hint).
    /// * [`CanonicalError::Internal`] → [`crate::CredStoreError::Internal`]: an unexpected internal failure.
    async fn put(
        &self,
        ctx: &SecurityContext,
        key: &SecretRef,
        write: CredentialWrite,
        precondition: PutPrecondition,
    ) -> Result<PutOutcome, CanonicalError>;

    /// Applies a partial change to the record, the value, or both — RFC 7396
    /// JSON Merge Patch semantics: a field present is applied exactly as
    /// [`Self::put`] would apply it, a field absent is left untouched.
    /// `patch.secret` present as [`crate::models::PatchField::Null`] removes
    /// the value (the record becomes `declared`); as
    /// [`crate::models::PatchField::Set`] it rotates/creates it.
    ///
    /// The action set is derived from the body: any metadata field present
    /// (`sharing`/`fallback`/`secret_type`/`expires_at`) requires `write`;
    /// `secret` present (`Set` or `Null`) requires `write_secret`; both
    /// present require both — all required actions are evaluated before any
    /// side effect. Never creates: no own record under the reference is
    /// [`CanonicalError::NotFound`].
    ///
    /// A patch whose metadata equals the current record and carries no
    /// `secret` key is a no-op: it returns the current validator unchanged,
    /// without bumping the version.
    ///
    /// # Errors
    ///
    /// * [`CanonicalError::NotFound`] → [`crate::CredStoreError::NotFound`]: the caller holds no own record under the reference, or one of a type the caller may not write.
    /// * [`CanonicalError::Aborted`] with [`crate::reason::aborted::OPTIMISTIC_LOCK_FAILURE`] → [`crate::CredStoreError::PreconditionFailed`]: the `Matches` validator no longer holds (lost compare-and-set).
    /// * [`CanonicalError::Aborted`] with [`crate::reason::aborted::TYPE_IMMUTABLE`] → [`crate::CredStoreError::TypeConflict`]: the patch changes `secret_type`.
    /// * [`CanonicalError::InvalidArgument`] → [`crate::CredStoreError::Invalid`]: an empty patch ([`crate::field::EMPTY_PATCH`]) or a violated type trait ([`crate::field::UNKNOWN_SECRET_TYPE`], [`crate::field::SHARING_NOT_ALLOWED_FOR_TYPE`], [`crate::field::VALUE_TOO_LARGE`], [`crate::field::VALUE_NOT_UTF8`], [`crate::field::VALUE_SCHEMA_VIOLATION`], [`crate::field::EXPIRY_NOT_SUPPORTED_FOR_TYPE`], [`crate::field::EXPIRY_IN_THE_PAST`]).
    /// * [`CanonicalError::FailedPrecondition`] with [`crate::reason::failed_precondition::UNSUPPORTED_TRANSITION`] → [`crate::CredStoreError::UnsupportedTransition`]: `sharing` would move the record between private and tenant/shared.
    /// * [`CanonicalError::PermissionDenied`] → [`crate::CredStoreError::PermissionDenied`]: the caller lacks a required action (`ACCESS_DENIED`, [`crate::reason::permission_denied::ACCESS_DENIED`]).
    /// * [`CanonicalError::ServiceUnavailable`] → [`crate::CredStoreError::Unavailable`]: the PDP, the registry, the database or the storage backend is unreachable; no storage plugin is registered; the store refused the plugin's credentials (the last two carry no retry hint).
    /// * [`CanonicalError::Internal`] → [`crate::CredStoreError::Internal`]: an unexpected internal failure.
    async fn patch(
        &self,
        ctx: &SecurityContext,
        key: &SecretRef,
        patch: CredentialPatch,
        precondition: WritePrecondition,
    ) -> Result<Validator, CanonicalError>;

    /// Deletes the caller's own-tenant credential (record and value
    /// together), guarded by the mandatory `precondition`. Releases the
    /// reference at once.
    ///
    /// Requires the `delete` action.
    ///
    /// # Errors
    ///
    /// * [`CanonicalError::NotFound`] → [`crate::CredStoreError::NotFound`]: no own-tenant record exists, or its type is one the caller may not delete.
    /// * [`CanonicalError::Aborted`] with [`crate::reason::aborted::OPTIMISTIC_LOCK_FAILURE`] → [`crate::CredStoreError::PreconditionFailed`]: the `Matches` validator no longer holds, including a record that vanishes concurrently.
    /// * [`CanonicalError::PermissionDenied`] → [`crate::CredStoreError::PermissionDenied`]: the caller lacks `delete` (`ACCESS_DENIED`, [`crate::reason::permission_denied::ACCESS_DENIED`]).
    /// * [`CanonicalError::ServiceUnavailable`] → [`crate::CredStoreError::Unavailable`]: the PDP, the registry, the database or the storage backend is unreachable; no storage plugin is registered; the store refused the plugin's credentials.
    /// * [`CanonicalError::Internal`] → [`crate::CredStoreError::Internal`]: an unexpected internal failure.
    async fn delete(
        &self,
        ctx: &SecurityContext,
        key: &SecretRef,
        precondition: WritePrecondition,
    ) -> Result<(), CanonicalError>;

    /// Lists the credentials visible to the caller's tenant, rooted at that
    /// tenant and walking upward through its ancestor chain only — never
    /// downward (ADR-0005, "Upward-rooted collection read"). One item per
    /// reference: the same reduction a point read ([`Self::get_record`]) of that
    /// reference would apply, so the catalogue and the point read never
    /// disagree.
    ///
    /// `query.filter()` accepts `reference` and `type` (SQL-clamped;
    /// `eq`/`in` only) plus `sharing`, `fallback` and `expires_at` (applied
    /// after reduction, since they vary across a reference's chain);
    /// `inheritance`, `owner_tenant_id` and `updated_at` are never
    /// filterable or orderable. `query.order` accepts only `reference`
    /// (ascending by default). `query.selected_fields()` accepts the
    /// `Credential` field names plus `secret`; on the collection, `secret` may
    /// be combined only with `reference`, `type` and `expires_at` (anything
    /// else is `InvalidArgument` `SECRET_SELECT_FIELDS`).
    ///
    /// Selecting `secret` is the same paginated read — `limit`, `query.cursor`,
    /// `query.order` and `query.filter()` behave exactly as without it — and
    /// each returned item's [`CredentialListItem::secret`] carries the
    /// decrypted value for the items the caller may read: an item the caller
    /// may not read is omitted rather than reported; an expired item is
    /// returned with its metadata and without a secret; an item whose stored
    /// version the backend cannot return fails the whole request.
    ///
    /// The PDP decision is taken before any candidate lookup. A caller denied
    /// outright, or whose scope does not admit its own tenant, gets
    /// [`CanonicalError::PermissionDenied`], never an empty page, whether or
    /// not any record exists (ADR-0005).
    ///
    /// Requires the `list` action (or `read_secret` when `secret` is
    /// selected), evaluated once on the base credential type; a type the
    /// caller's constraints exclude is dropped from the page rather than
    /// failing the request.
    ///
    /// # Errors
    ///
    /// * [`CanonicalError::PermissionDenied`] → [`crate::CredStoreError::PermissionDenied`]: the caller lacks `list` (or `read_secret` when `secret` is selected), or the scope excludes the caller's own tenant (`ACCESS_DENIED`, [`crate::reason::permission_denied::ACCESS_DENIED`]); independent of whether any record exists.
    /// * [`CanonicalError::InvalidArgument`] → [`crate::CredStoreError::Invalid`]: an unsupported filter, order or selection, an out-of-range `limit` or a bad cursor ([`crate::field::INVALID_FILTER`], [`crate::field::INVALID_ORDERBY_FIELD`], [`crate::field::INVALID_SELECT`], [`crate::field::SECRET_SELECT_FIELDS`], [`crate::field::INVALID_CURSOR`], [`crate::field::INVALID_LIMIT`], [`crate::field::ORDER_MISMATCH`], [`crate::field::FILTER_MISMATCH`], [`crate::field::ORDER_WITH_CURSOR`]).
    /// * [`CanonicalError::ServiceUnavailable`] → [`crate::CredStoreError::Unavailable`]: the PDP, the registry, the database or the storage backend is unreachable; no storage plugin is registered; the store refused the plugin's credentials (the last two carry no retry hint).
    /// * [`CanonicalError::Internal`] → [`crate::CredStoreError::Internal`]: a stored version cannot be read, or an unexpected internal failure.
    async fn list(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<CredentialListItem>, CanonicalError>;
}
