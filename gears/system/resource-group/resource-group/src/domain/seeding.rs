// Created: 2026-04-16 by Constructor Tech
//! Idempotent seeding operations for types, groups, and memberships.
//!
//! All seed functions follow the same pattern: for each definition, check if
//! the entity already exists, create if missing, update if the definition
//! differs, and skip if unchanged. Repeated runs produce the same result.

use resource_group_sdk::models::{CreateGroupRequest, CreateTypeRequest, UpdateTypeRequest};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::group_service::GroupService;
use crate::domain::repo::{GroupRepositoryTrait, TypeRepositoryTrait};
use crate::domain::type_service::TypeService;

/// Seed result tracking.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Default)]
pub struct SeedResult {
    /// Number of entities created during this seed run.
    pub created: u32,
    /// Number of entities updated during this seed run.
    pub updated: u32,
    /// Number of entities that already matched the seed definition.
    pub unchanged: u32,
    /// Number of entities skipped due to incompatibility or missing prerequisites.
    pub skipped: u32,
}

/// Idempotent type seeding: create if missing, update if differs, skip if unchanged.
///
/// Seeding runs at gear init, before any caller `SecurityContext` exists —
/// same rationale as `seed_groups` below. Uses the dedicated `*_unscoped`
/// entry points on `TypeService`: domain invariants (placement
/// invariant, hierarchy safety, parent/membership existence) still run,
/// only the `PolicyEnforcer` gate is skipped.
pub async fn seed_types<TR: TypeRepositoryTrait>(
    type_service: &TypeService<TR>,
    seeds: &[CreateTypeRequest],
) -> Result<SeedResult, DomainError> {
    // Load seed definitions from configuration source
    let mut result = SeedResult::default();
    for seed in seeds {
        match type_service.get_type_unscoped(&seed.code).await {
            Ok(existing) => {
                // Normalize allowed-type lists before diffing: `load_full_type()`
                // returns these sorted, while the seed preserves caller order.
                // Without sorting, the same logical config rewrites the type on
                // every startup if the YAML happens to list members in a
                // different order, breaking idempotency.
                let mut seed_allowed_parent_types = seed.allowed_parent_types.clone();
                seed_allowed_parent_types.sort();
                let mut seed_allowed_membership_types = seed.allowed_membership_types.clone();
                seed_allowed_membership_types.sort();

                // Compare: if definition differs, update; otherwise skip
                if existing.can_be_root != seed.can_be_root
                    || existing.allowed_parent_types != seed_allowed_parent_types
                    || existing.allowed_membership_types != seed_allowed_membership_types
                    || existing.metadata_schema != seed.metadata_schema
                {
                    let update_req = UpdateTypeRequest {
                        can_be_root: seed.can_be_root,
                        allowed_parent_types: seed_allowed_parent_types,
                        allowed_membership_types: seed_allowed_membership_types,
                        metadata_schema: seed.metadata_schema.clone(),
                    };
                    type_service
                        .update_type_unscoped(&seed.code, update_req)
                        .await?;
                    result.updated += 1;
                } else {
                    result.unchanged += 1;
                }
            }
            Err(DomainError::TypeNotFound { .. }) => {
                type_service.create_type_unscoped(seed.clone()).await?;
                result.created += 1;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}

/// Group seed definition with stable identity.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct GroupSeedDef {
    /// Stable identifier for the seeded group.
    pub id: Uuid,
    /// GTS chained type code.
    pub code: String,
    /// Display name.
    pub name: String,
    /// Parent group ID (None for root groups).
    pub parent_id: Option<Uuid>,
    /// Type-specific metadata.
    pub metadata: Option<serde_json::Value>,
    /// Tenant scope.
    pub tenant_id: Uuid,
}

/// Idempotent group seeding: ordered by dependency (parents before children).
///
/// Callers must order `seeds` such that parent groups appear before their
/// children. Each seed is looked up by ID; if the group already exists it is
/// skipped (idempotent), otherwise it is created through the normal service
/// path which enforces type compatibility, tenant scope, and closure table
/// maintenance.
pub async fn seed_groups<GR: GroupRepositoryTrait, TR: TypeRepositoryTrait>(
    group_service: &GroupService<GR, TR>,
    seeds: &[GroupSeedDef],
) -> Result<SeedResult, DomainError> {
    // Load seed definitions, order by dependency (parents before children)
    // (callers must order `seeds` such that parent groups appear before children)
    let mut result = SeedResult::default();
    for seed in seeds {
        // Seeding runs at gear init, before any caller `SecurityContext`
        // exists; using `SecurityContext::anonymous()` would gate this path
        // on whether anonymous subjects are allowed to read/create groups,
        // which is brittle and outright fails in locked-down deployments.
        // Use the dedicated `*_unscoped` entry points instead — domain
        // invariants still run, only the `PolicyEnforcer` gate is skipped.
        match group_service.get_group_unscoped(seed.id).await {
            Ok(_existing) => {
                // Group exists AND definition matches → skip (unchanged)
                result.unchanged += 1;
            }
            // Group exists AND definition differs → update via update flow
            // (currently simplified: idempotent skip only)
            Err(DomainError::GroupNotFound { .. }) => {
                let req = CreateGroupRequest {
                    id: Some(seed.id),
                    code: seed.code.clone(),
                    name: seed.name.clone(),
                    parent_id: seed.parent_id,
                    // Seeding always resolves the target tenant via the
                    // trusted `seed.tenant_id` argument to
                    // `create_group_unscoped` below -- never via
                    // this field, so it stays `None` here.
                    tenant_id: None,
                    metadata: seed.metadata.clone(),
                };
                group_service
                    .create_group_unscoped(req, seed.tenant_id)
                    .await?;
                result.created += 1;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}

/// Membership seed definition.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct MembershipSeedDef {
    /// Target group to add the resource to.
    pub group_id: Uuid,
    /// GTS type path of the resource being linked.
    pub resource_type: String,
    /// Identifier of the resource being linked.
    pub resource_id: String,
}

/// Trait for membership operations required by the seeding function.
///
/// This allows seeding to work with any implementation that can add
/// memberships, decoupling from a concrete `MembershipService`.
#[async_trait::async_trait]
pub trait MembershipAdder: Send + Sync {
    /// Add a membership link. Returns `Ok(())` on success.
    async fn add_membership(
        &self,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), DomainError>;
}

/// Idempotent membership seeding: skip duplicates, validate tenant compat.
///
/// Each seed definition is attempted through the provided adder. Conflicts
/// (duplicate composite keys) are treated as idempotent successes.
/// Tenant-incompatible memberships are logged and skipped rather than
/// failing the entire seed run.
pub async fn seed_memberships(
    adder: &dyn MembershipAdder,
    seeds: &[MembershipSeedDef],
) -> Result<SeedResult, DomainError> {
    // Load seed definitions
    let mut result = SeedResult::default();
    for seed in seeds {
        match adder
            .add_membership(seed.group_id, &seed.resource_type, &seed.resource_id)
            .await
        {
            Ok(()) => result.created += 1,
            Err(DomainError::DuplicateMembership { .. }) => {
                // Already exists -- idempotent skip
                result.unchanged += 1;
            }
            Err(DomainError::TenantIncompatibility { .. }) => {
                // Tenant mismatch -- skip with warning
                tracing::warn!(
                    group_id = %seed.group_id,
                    resource_type = %seed.resource_type,
                    resource_id = %seed.resource_id,
                    "Skipping membership seed: tenant incompatibility"
                );
                result.skipped += 1;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(result)
}
