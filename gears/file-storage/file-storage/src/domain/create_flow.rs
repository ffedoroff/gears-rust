//! Shared `POST /files` orchestration for the REST handler and the SDK local client:
//! single-part vs. merged create+plan multipart path, and orphan-file compensation when a
//! multipart initiate fails.

use uuid::Uuid;

use file_storage_sdk::NewFile;
use toolkit_security::SecurityContext;

use crate::domain::error::DomainError;
use crate::domain::multipart::{MultipartPlan, compute_plan};
use crate::domain::multipart_service::MultipartService;
use crate::domain::service::{FileService, UploadTicket};

/// Multipart intent for the merged create+plan path (mirrors the SDK's `MultipartIntent`).
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct MultipartIntent {
    pub declared_size: u64,
    pub preferred_part_size: Option<u64>,
}

/// Result of [`create_file`]: the single-part ticket, or the new file's id plus the parts
/// plan when the computed plan has two or more parts.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub enum CreateFileOutcome {
    SinglePart(UploadTicket),
    Multipart { file_id: Uuid, plan: MultipartPlan },
}

/// `POST /files`: create a file and presign its first content upload.
///
/// * No `multipart` intent (or a plan of one part): single pending version,
///   [`CreateFileOutcome::SinglePart`].
/// * `multipart` intent with two or more parts: creates the bare file row (the initiate
///   registers its own version) and returns [`CreateFileOutcome::Multipart`]. A failed
///   initiate deletes the orphaned file row before the original error is returned.
///
/// `idempotency_key` is rejected with a `multipart` intent (the stored record only fits a
/// single-part ticket).
pub async fn create_file(
    file_svc: &FileService,
    multipart_svc: &MultipartService,
    ctx: &SecurityContext,
    new: NewFile,
    idempotency_key: Option<String>,
    auto_bind: bool,
    multipart: Option<MultipartIntent>,
) -> Result<CreateFileOutcome, DomainError> {
    if let Some(mp) = &multipart {
        if idempotency_key.is_some() {
            return Err(DomainError::validation(
                "idempotency_key",
                "not supported together with the multipart intent block",
            ));
        }
        // One-part plans fall through to the single-part path below.
        let (_, planned_parts) = compute_plan(mp.declared_size, mp.preferred_part_size, None)?;
        if planned_parts.len() >= 2 {
            let mime_type = new.mime_type.clone();
            let file_id = file_svc.create_file_bare(ctx, new).await?;
            let plan = match multipart_svc
                .initiate_multipart_upload(
                    ctx,
                    file_id,
                    &mime_type,
                    mp.declared_size,
                    mp.preferred_part_size,
                    auto_bind,
                )
                .await
            {
                Ok(plan) => plan,
                Err(e) => {
                    // Otherwise the bare file would stay a version-less orphan.
                    file_svc
                        .compensate_failed_multipart_initiate(ctx, file_id)
                        .await;
                    return Err(e);
                }
            };
            return Ok(CreateFileOutcome::Multipart { file_id, plan });
        }
    }

    let ticket = file_svc
        .create_file(ctx, new, idempotency_key, auto_bind)
        .await?;
    Ok(CreateFileOutcome::SinglePart(ticket))
}

#[cfg(test)]
#[path = "create_flow_tests.rs"]
mod create_flow_tests;
