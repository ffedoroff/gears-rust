// Updated: 2026-10-06 by Constructor Tech
//! `DomainError` → [`CanonicalError`] boundary mapping for the credstore REST layer.

use toolkit_canonical_errors::{CanonicalError, Http, resource_error};

use crate::domain::error::DomainError;
use crate::domain::secret::typing::reasons;

// ---------------------------------------------------------------------------
// Resource marker
// ---------------------------------------------------------------------------

#[resource_error(gts_id!("cf.core.credstore.credential.v1~"))]
/// Resource marker that scopes canonical errors to the credstore credential resource.
pub(crate) struct CredentialResource;
