// Created: 2026-04-16 by Constructor Tech
//! Shared domain validation utilities.

use resource_group_sdk::TENANT_RG_TYPE_PATH;
use resource_group_sdk::models::GtsTypePath;
use toolkit_gts::gts_id;

use crate::domain::error::DomainError;

/// GTS type path prefix required for resource group types.
pub const RG_TYPE_PREFIX: &str = gts_id!("cf.core.rg.type.v1~");

/// Canonical form of a GTS code: whitespace-trimmed and lowercased.
///
/// This is the *only* normalization this gear applies to a GTS code, and it
/// matches what [`GtsTypePath::new`] and [`gts::GtsId::try_new`] do
/// internally, so a code that round-trips through this function compares
/// byte-for-byte against the value those parsers would accept.
///
/// Use this on **lookup** paths (`GET`/`PUT`/`DELETE /types/{code}`), where a
/// code that names nothing must stay a not-found rather than becoming a
/// validation error. Use [`canonical_type_code`] on **write** paths, which
/// additionally parse the code's structure.
#[must_use]
pub fn canonicalize_code(code: &str) -> String {
    code.trim().to_lowercase()
}

/// Whether a GTS type code designates a **tenant** type — i.e. a group of
/// this type opens a new tenant scope (`tenant_id = group.id`) instead of
/// inheriting its caller's/parent's tenant.
///
/// The prefix test is performed on the [canonical](canonicalize_code) form,
/// not on the raw string. That matters for rows written before type codes
/// were canonicalized on the way in: a stored `GTS.CF.CORE.RG.TYPE.V1~…` or
/// `" gts…"` would otherwise fail a case-sensitive `starts_with` and be
/// classified as an *ordinary* type, silently giving its group the caller's
/// tenant instead of its own id — a tenant-identity break, not merely a
/// cosmetic mismatch. Canonicalizing here keeps that classification correct
/// for legacy rows without a data migration.
#[must_use]
pub fn is_tenant_type_code(code: &str) -> bool {
    canonicalize_code(code).starts_with(TENANT_RG_TYPE_PATH)
}

/// Parse a resource-group GTS type code, returning its canonical form.
///
/// Performs the full write-path check in one place: non-empty, the RG
/// type-registry prefix, the 1024-char GTS limit, and — via
/// [`GtsTypePath::new`], which delegates to [`gts::GtsId::try_new`] — the
/// structure of every `~`-delimited segment
/// (`vendor.package.namespace.type.vMAJOR`).
///
/// **Callers must use the returned value, not their input.** The predecessor
/// of this function validated a trimmed/lowercased *copy* and returned `()`,
/// so the original string was what got persisted, looked up, and prefix-tested
/// for tenant-ness: an uppercase or space-padded tenant code passed validation
/// and was then classified as an ordinary type, putting the group in the
/// caller's tenant instead of its own. Returning the canonical form makes that
/// class of bug unrepresentable — there is nothing else to pass on.
///
/// # Errors
///
/// Returns [`DomainError::validation`] if the code is empty, lacks the
/// required prefix, exceeds 1024 characters, or is not a structurally valid
/// GTS type path.
pub fn canonical_type_code(code: &str) -> Result<String, DomainError> {
    let canonical = canonicalize_code(code);
    if canonical.is_empty() {
        return Err(DomainError::validation("Type code must not be empty"));
    }
    if !canonical.starts_with(RG_TYPE_PREFIX) {
        return Err(DomainError::validation(format!(
            "Type code must start with prefix '{RG_TYPE_PREFIX}', got: '{canonical}'"
        )));
    }
    if canonical.chars().count() > 1024 {
        return Err(DomainError::validation(
            "Type code must not exceed 1024 characters",
        ));
    }
    let path = GtsTypePath::new(canonical.as_str())
        .map_err(|e| DomainError::validation(format!("Invalid type code '{canonical}': {e}")))?;
    Ok(path.into())
}

/// Parse a GTS type code used as a membership resource type, returning its
/// canonical form.
///
/// Unlike [`canonical_type_code`], this does NOT require the
/// `gts.cf.core.rg.type.v1~` prefix. Per `DESIGN.md` ("RG type prefix
/// requirement"), `allowed_memberships` entries are external domain
/// types (e.g. `gts.cf.core.idp.user.v1~`, `gts.cf.vendor.lms.course.v1~`)
/// and need not live in the RG type-registry namespace.
///
/// Format validation is delegated to [`gts::GtsId::try_new`], the canonical
/// GTS parser. Only **exact** GTS IDs (`gts.cf.core.idp.user.v1~`) are
/// accepted; trailing-wildcard patterns (`gts.cf.core.am.*`) are
/// rejected. `allowed_memberships` entries must resolve to a registered
/// concrete type — `gts_type_allowed_membership` is a junction table
/// with `SMALLINT FK → gts_type.id`, which cannot store a pattern.
///
/// # Errors
///
/// Returns [`DomainError::validation`] if the code is not a valid GTS
/// ID, or if it is a wildcard pattern.
pub fn canonical_membership_type_code(code: &str) -> Result<String, DomainError> {
    if code.contains('*') {
        return Err(DomainError::validation(format!(
            "Membership type code '{code}' must be a concrete GTS type, not a wildcard pattern"
        )));
    }
    let canonical = canonicalize_code(code);
    gts::GtsId::try_new(&canonical).map_err(|e| {
        DomainError::validation(format!("Invalid membership type code '{canonical}': {e}"))
    })?;
    Ok(canonical)
}

/// Validate that a `metadata_schema` value is a valid JSON Schema.
///
/// Attempts to compile the schema via `jsonschema::validator_for`. If the value
/// cannot be interpreted as a JSON Schema, returns a [`DomainError::validation`].
///
/// # Errors
///
/// Returns [`DomainError`] if the value is not a valid JSON Schema.
pub fn validate_metadata_schema(schema: &serde_json::Value) -> Result<(), DomainError> {
    jsonschema::validator_for(schema).map_err(|e| {
        DomainError::validation(format!("metadata_schema is not a valid JSON Schema: {e}"))
    })?;
    Ok(())
}

/// Validate a metadata JSON value against a raw JSON Schema.
///
/// Synchronous counterpart to [`validate_metadata_via_gts`] that does not
/// resolve GTS types. When either `metadata` or `schema` is `None`, the
/// check passes trivially.
///
/// # Errors
///
/// Returns [`DomainError::validation`] when the schema fails to compile
/// or the metadata violates any schema constraint.
pub fn validate_metadata_against_schema(
    metadata: Option<&serde_json::Value>,
    schema: Option<&serde_json::Value>,
) -> Result<(), DomainError> {
    let (Some(metadata), Some(schema)) = (metadata, schema) else {
        return Ok(());
    };

    let validator = jsonschema::validator_for(schema)
        .map_err(|e| DomainError::validation(format!("metadata_schema is invalid: {e}")))?;

    let errors: Vec<String> = validator
        .iter_errors(metadata)
        .map(|e| e.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(DomainError::validation(format!(
            "Metadata does not match type schema: {}",
            errors.join("; ")
        )));
    }
    Ok(())
}

/// Validate a metadata value against a resolved GTS type schema.
///
/// Uses `TypesRegistryClient` to fetch the resolved schema (with `allOf`
/// composition, `$ref` resolution, and `x-gts-traits` applied), then validates
/// the metadata against the resolved schema using `jsonschema`.
///
/// Returns `Ok(())` when:
/// - `metadata` is `None` (nothing to validate)
/// - `type_code` has no registered schema in the types registry
/// - `metadata` validates against the resolved schema
///
/// # Errors
///
/// Returns [`DomainError`] when metadata violates the schema constraints
/// or the types registry is unavailable.
pub async fn validate_metadata_via_gts(
    metadata: Option<&serde_json::Value>,
    type_code: &str,
    types_registry: &dyn types_registry_sdk::TypesRegistryClient,
) -> Result<(), DomainError> {
    let Some(metadata) = metadata else {
        return Ok(());
    };

    // Fetch the GTS schema. Local client pre-links ancestors via Arc, so
    // `effective_properties()` returns the chain-resolved property map (own
    // overrides + inherited).
    let schema = match types_registry.get_type_schema(type_code).await {
        Ok(schema) => schema,
        // No registered schema for this type -- skip metadata validation.
        // The trait boundary is `CanonicalError` (ADR 0005); a missing schema
        // surfaces as `NotFound` regardless of entity kind.
        Err(toolkit_canonical_errors::CanonicalError::NotFound { .. }) => return Ok(()),
        Err(e) => {
            return Err(DomainError::validation(format!(
                "Failed to resolve GTS type '{type_code}' for metadata validation: {e}"
            )));
        }
    };

    // The chained RG type schema may declare `metadata` at any level of
    // the inheritance chain — `effective_properties` collects them all.
    let merged = schema.effective_properties();
    let metadata_schema = merged.get("metadata");

    let Some(metadata_schema) = metadata_schema else {
        // No metadata property in the schema — any metadata accepted.
        return Ok(());
    };

    let validator = jsonschema::validator_for(metadata_schema)
        .map_err(|e| DomainError::validation(format!("Type metadata_schema is invalid: {e}")))?;

    let errors: Vec<String> = validator
        .iter_errors(metadata)
        .map(|e| e.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(DomainError::validation(format!(
            "Metadata does not match type schema: {}",
            errors.join("; ")
        )));
    }
    Ok(())
}
