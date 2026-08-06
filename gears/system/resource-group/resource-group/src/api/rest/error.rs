// Created: 2026-04-16 by Constructor Tech
// Updated: 2026-05-07 by Constructor Tech
//! Map domain errors to canonical errors (`toolkit-canonical-errors`) for
//! REST responses. Handlers return `ApiResult<T>` (= `Result<T,
//! CanonicalError>`); the canonical error middleware
//! (`toolkit::api::canonical_error_middleware`) converts the `CanonicalError`
//! to a wire `Problem` and fills `instance` / `trace_id` post-response.

use resource_group_sdk::{TENANT_RG_TYPE_PATH, field, precondition, reason};
use toolkit_canonical_errors::{CanonicalError, resource_error};

use crate::domain::error::DomainError;

/// Errors attributable to a resource group as a resource.
///
/// The macro literal mirrors [`resource_group_sdk::gts::GROUP_RESOURCE_TYPE`]
/// (proc-macros cannot resolve a const); the SDK round-trip tests pin the
/// two equal.
#[resource_error(gts_id!("cf.core.rg.group.v1~"))]
pub struct RgError;

/// Implement `From<DomainError> for CanonicalError` so `?` works in
/// handlers that return `ApiResult<T>`.
impl From<DomainError> for CanonicalError {
    #[allow(clippy::cognitive_complexity)]
    fn from(e: DomainError) -> Self {
        // Receive DomainError variant
        match e {
            DomainError::Validation { message } => {
                RgError::invalid_argument().with_format(message).create()
            }
            DomainError::TypeNotFound { code } => {
                RgError::not_found(format!("GTS type with code '{code}' was not found"))
                    .with_resource(code)
                    .create()
            }
            DomainError::GroupNotFound { id } => {
                RgError::not_found(format!("Resource group with id '{id}' was not found"))
                    .with_resource(id.to_string())
                    .create()
            }
            // a target tenant outside the caller's `create`
            // AccessScope maps to `not_found`, not `permission_denied` --
            // see `DomainError::TenantNotFound`'s doc for the anti-oracle
            // rationale (mirrors the membership gates below).
            DomainError::TenantNotFound { tenant_id } => {
                RgError::not_found(format!("Tenant '{tenant_id}' was not found"))
                    .with_resource(tenant_id.to_string())
                    .create()
            }
            DomainError::MembershipNotFound { key } => {
                RgError::not_found(format!("Membership '{key}' was not found"))
                    .with_resource(key)
                    .create()
            }
            DomainError::TypeAlreadyExists { code } => {
                RgError::already_exists(format!("GTS type with code '{code}' already exists"))
                    .with_resource(code)
                    .create()
            }
            // primary-key collision on `resource_group.id` (
            // deliberately keeps client-supplied `id` accepted on create) —
            // typed 409 instead of falling through to the `Database` (500) arm.
            DomainError::GroupAlreadyExists { id } => {
                RgError::already_exists(format!("Resource group with id '{id}' already exists"))
                    .with_resource(id.to_string())
                    .create()
            }
            DomainError::InvalidParentType { message } => RgError::invalid_argument()
                .with_field_violation(
                    field::PARENT_TYPE_FIELD,
                    message,
                    field::INVALID_PARENT_TYPE,
                )
                .create(),
            // ⚠ wire change accepted in the migration plan: 409 → 400.
            DomainError::AllowedParentTypesViolation { message } => RgError::failed_precondition()
                .with_precondition_violation(
                    precondition::ALLOWED_PARENTS_SUBJECT,
                    message,
                    precondition::STATE_TYPE,
                )
                .create(),
            // ⚠ wire change accepted in the migration plan: 409 → 400.
            DomainError::CycleDetected { message } => RgError::failed_precondition()
                .with_precondition_violation(
                    precondition::HIERARCHY_SUBJECT,
                    message,
                    precondition::STATE_TYPE,
                )
                .create(),
            // ⚠ wire change accepted in the migration plan: 409 → 400.
            DomainError::ConflictActiveReferences {
                message,
                blocking_entity_ids,
            } => RgError::failed_precondition()
                .with_precondition_violation(
                    precondition::ACTIVE_REFERENCES_SUBJECT,
                    message,
                    precondition::STATE_TYPE,
                )
                .with_precondition_violation_blocking_entity_ids(blocking_entity_ids)
                .create(),
            // ⚠ wire change accepted in the migration plan: 409 → 400.
            DomainError::LimitViolation { message } => RgError::failed_precondition()
                .with_precondition_violation(
                    precondition::LIMIT_SUBJECT,
                    message,
                    precondition::STATE_TYPE,
                )
                .create(),
            // ⚠ wire change accepted in the migration plan: 409 → 400.
            DomainError::TenantIncompatibility { message } => RgError::failed_precondition()
                .with_precondition_violation(
                    precondition::TENANT_SUBJECT,
                    message,
                    precondition::STATE_TYPE,
                )
                .create(),
            // Duplicate-on-create variants route through `already_exists`
            // with the structural resource id as `resource_name` (matches
            // the spec semantic for duplicate-on-create — see
            // `docs/arch/errors/categories/06-already-exists.md`).
            DomainError::DuplicateMembership { key, message } => {
                RgError::already_exists(message).with_resource(key).create()
            }
            // the conflicting root's **id never reaches the wire**.
            // It comes from `find_root_id_with_type_prefix`, which deliberately
            // bypasses `SecureORM` (tenant-root uniqueness is a forest-wide
            // invariant and has to see every tenant), so the existing root can
            // belong to a tenant the caller has no grant for -- and a
            // tenant-type group's `id` *is* its `tenant_id`, which makes the
            // leak a foreign *tenant* identifier, not merely a foreign group's.
            //
            // `already_exists` requires *some* `resource_name` by typestate
            // (duplicate-on-create must name what it collided with), so name
            // the violated singleton rather than the row: at most one root may
            // carry the tenant type path, and that path is derivable from the
            // caller's own rejected request. `detail`, built at the call site,
            // names only that request's code/name. The real id stays in this
            // debug log.
            DomainError::TenantRootAlreadyExists {
                existing_root_id,
                detail,
            } => {
                tracing::debug!(
                    existing_root_id = %existing_root_id,
                    "tenant-root uniqueness rejected a create/move"
                );
                RgError::already_exists(detail)
                    .with_resource(TENANT_RG_TYPE_PATH)
                    .create()
            }
            // Generic conflict carries no structural resource id — route
            // through `aborted` with a stable reason discriminator.
            DomainError::Conflict { message } => RgError::aborted(message)
                .with_reason(reason::aborted::CONFLICT)
                .create(),
            DomainError::AccessDenied { message } => {
                tracing::debug!(reason = %message, "resource-group access denied");
                RgError::permission_denied()
                    .with_reason(reason::permission::ACCESS_DENIED)
                    .create()
            }
            // ServiceUnavailable: no dedicated variant — DB / infra failures
            // fall through to the Database arm below and surface as a
            // canonical Internal (HTTP 500). A genuine 503 (e.g. AuthZ
            // Resolver unreachable) is produced by platform middleware
            // upstream of this mapper, not here.
            // Source description flows into the canonical's `ctx.description`
            // (recoverable via `diagnostic()`) so `canonical_error_middleware`
            // (DESIGN.md §3.6) logs it server-side with the request `trace_id`.
            // `Internal::description` is `#[serde(skip)]`, so the DB text
            // never reaches the wire `detail`.
            DomainError::Database(db_err) => {
                CanonicalError::internal(format!("resource-group DB error: {db_err}")).create()
            }
            DomainError::InternalError => {
                CanonicalError::internal("resource-group internal error").create()
            }
        }
    }
}
