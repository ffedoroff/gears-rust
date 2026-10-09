//! In-process adapter implementing the SDK client trait.
//!
//! Each method calls the same service method as the matching REST handler (same
//! `SecurityContext`, so identical authorization, audit and idempotency), then maps
//! the result into SDK models (`domain::sdk_convert`). Multi-step handler logic is
//! shared (`domain::create_flow`, `FileService::list_files_with_metadata`,
//! `FileService::list_versions_with_manifests`).

use std::sync::Arc;

use async_trait::async_trait;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use file_storage_sdk::{
    CreateFileOutcome, CustomMetadataPatch, EffectivePolicy, FileFetch, FileId, FileRecord,
    FileStorageClientV1, FileStorageError, MultipartCompleteOutcome, MultipartIntent,
    MultipartPlan, MultipartStatus, NewFile, OwnerFilter, OwnerKind, Page, Policy, PolicyBody,
    PolicyScope, RetentionRule, RetentionRuleBody, RetentionScope, Storage, UploadTicket,
    VersionId, VersionRecord,
};

use crate::domain::create_flow;
use crate::domain::etag;
use crate::domain::multipart_service::MultipartService;
use crate::domain::policy_service::PolicyService;
use crate::domain::sdk_convert;
use crate::domain::service::FileService;

/// Local (same-process) implementation of [`FileStorageClientV1`], resolved
/// from `ClientHub` by other gears. Shares its services with the REST routes.
#[allow(unknown_lints, de0309_must_have_domain_model)]
pub struct FileStorageLocalClient {
    service: Arc<FileService>,
    multipart_service: Arc<MultipartService>,
    policy_service: Arc<PolicyService>,
}

impl FileStorageLocalClient {
    #[must_use]
    pub fn new(
        service: Arc<FileService>,
        multipart_service: Arc<MultipartService>,
        policy_service: Arc<PolicyService>,
    ) -> Self {
        Self {
            service,
            multipart_service,
            policy_service,
        }
    }
}

fn upload_ticket(t: crate::domain::service::UploadTicket) -> UploadTicket {
    UploadTicket {
        file_id: t.file_id,
        version_id: t.version_id,
        upload_url: t.upload_url,
    }
}

fn download_ticket(t: crate::domain::service::DownloadTicket) -> file_storage_sdk::DownloadTicket {
    file_storage_sdk::DownloadTicket {
        download_url: t.download_url,
        etag: t.etag,
        version_id: t.version_id,
    }
}

#[async_trait]
impl FileStorageClientV1 for FileStorageLocalClient {
    async fn create_file(
        &self,
        ctx: &SecurityContext,
        new: NewFile,
        idempotency_key: Option<String>,
        auto_bind: bool,
        multipart: Option<MultipartIntent>,
    ) -> Result<CreateFileOutcome, FileStorageError> {
        let intent = multipart.map(|m| create_flow::MultipartIntent {
            declared_size: m.declared_size,
            preferred_part_size: m.preferred_part_size,
        });
        let outcome = create_flow::create_file(
            &self.service,
            &self.multipart_service,
            ctx,
            new,
            idempotency_key,
            auto_bind,
            intent,
        )
        .await?;
        Ok(match outcome {
            create_flow::CreateFileOutcome::SinglePart(t) => {
                CreateFileOutcome::SinglePart(upload_ticket(t))
            }
            create_flow::CreateFileOutcome::Multipart { file_id, plan } => {
                CreateFileOutcome::Multipart {
                    file_id,
                    plan: sdk_convert::multipart_plan(plan),
                }
            }
        })
    }

    async fn get_file(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        if_none_match: Option<&str>,
    ) -> Result<FileFetch, FileStorageError> {
        let (file, custom_metadata) = self.service.get_file_with_metadata(ctx, file_id).await?;
        let current_etag = etag::etag_for(&file);
        if etag::if_none_match_satisfied(if_none_match, current_etag.as_deref()) {
            return Ok(FileFetch::NotModified);
        }
        Ok(FileFetch::Modified {
            record: Box::new(FileRecord {
                file,
                custom_metadata,
            }),
            etag: current_etag,
        })
    }

    async fn list_files(
        &self,
        ctx: &SecurityContext,
        owner: OwnerFilter,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<Page<FileRecord>, FileStorageError> {
        let page = self
            .service
            .list_files_with_metadata(ctx, owner, limit, cursor)
            .await?;
        Ok(page.map_items(|(file, custom_metadata)| FileRecord {
            file,
            custom_metadata,
        }))
    }

    async fn update_metadata(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        patch: CustomMetadataPatch,
        if_match_metadata: Option<i64>,
    ) -> Result<FileRecord, FileStorageError> {
        self.service
            .update_metadata(ctx, file_id, patch, if_match_metadata)
            .await?;
        // Re-read: the mutation's return value carries no custom metadata.
        let (file, custom_metadata) = self.service.get_file_with_metadata(ctx, file_id).await?;
        Ok(FileRecord {
            file,
            custom_metadata,
        })
    }

    async fn delete_file(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        if_match: Option<&str>,
    ) -> Result<(), FileStorageError> {
        self.service.delete_file(ctx, file_id, if_match).await?;
        Ok(())
    }

    async fn download_url(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        version_id: Option<VersionId>,
    ) -> Result<file_storage_sdk::DownloadTicket, FileStorageError> {
        let ticket = self.service.download_url(ctx, file_id, version_id).await?;
        Ok(download_ticket(ticket))
    }

    async fn list_versions(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<Page<VersionRecord>, FileStorageError> {
        let page = self
            .service
            .list_versions_with_manifests(ctx, file_id, limit, cursor)
            .await?;
        Ok(page.map_items(|(version, manifest)| VersionRecord { version, manifest }))
    }

    async fn presign_version(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
    ) -> Result<UploadTicket, FileStorageError> {
        let ticket = self.service.presign_version(ctx, file_id).await?;
        Ok(upload_ticket(ticket))
    }

    async fn bind(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        version_id: VersionId,
        if_match: Option<&str>,
    ) -> Result<FileRecord, FileStorageError> {
        self.service
            .bind(ctx, file_id, version_id, if_match)
            .await?;
        // Re-read to attach custom metadata.
        let (file, custom_metadata) = self.service.get_file_with_metadata(ctx, file_id).await?;
        Ok(FileRecord {
            file,
            custom_metadata,
        })
    }

    async fn delete_version(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        version_id: VersionId,
    ) -> Result<(), FileStorageError> {
        self.service
            .delete_version(ctx, file_id, version_id)
            .await?;
        Ok(())
    }

    async fn initiate_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        declared_mime: &str,
        declared_size: u64,
        preferred_part_size: Option<u64>,
    ) -> Result<MultipartPlan, FileStorageError> {
        let plan = self
            .multipart_service
            .initiate_multipart_upload(
                ctx,
                file_id,
                declared_mime,
                declared_size,
                preferred_part_size,
                // Standalone initiate is manual-bind; `auto_bind` applies only via
                // `create_file`'s `multipart` intent.
                false,
            )
            .await?;
        Ok(sdk_convert::multipart_plan(plan))
    }

    async fn introspect_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        upload_id: Uuid,
    ) -> Result<MultipartStatus, FileStorageError> {
        let status = self
            .multipart_service
            .introspect_multipart_upload(ctx, file_id, upload_id)
            .await?;
        Ok(sdk_convert::multipart_status(status))
    }

    async fn complete_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        upload_id: Uuid,
        if_match: Option<&str>,
    ) -> Result<MultipartCompleteOutcome, FileStorageError> {
        let outcome = self
            .multipart_service
            .complete_multipart_upload(ctx, file_id, upload_id, if_match)
            .await?;
        Ok(sdk_convert::multipart_complete_outcome(outcome))
    }

    async fn abort_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        upload_id: Uuid,
    ) -> Result<(), FileStorageError> {
        self.multipart_service
            .abort_multipart_upload(ctx, file_id, upload_id)
            .await?;
        Ok(())
    }

    async fn transfer_ownership(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        new_owner_kind: OwnerKind,
        new_owner_id: Uuid,
    ) -> Result<FileRecord, FileStorageError> {
        let (file, custom_metadata) = self
            .service
            .transfer_ownership(ctx, file_id, new_owner_kind, new_owner_id)
            .await?;
        Ok(FileRecord {
            file,
            custom_metadata,
        })
    }

    async fn migrate_backend(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        target_backend_id: &str,
    ) -> Result<(), FileStorageError> {
        self.service
            .migrate_backend(ctx, file_id, target_backend_id)
            .await?;
        Ok(())
    }

    async fn list_storages(&self, ctx: &SecurityContext) -> Result<Vec<Storage>, FileStorageError> {
        // `list_backends` itself is authz-free.
        self.service.authorize_backends_read(ctx).await?;
        Ok(self
            .service
            .list_backends()
            .into_iter()
            .map(|(id, caps)| sdk_convert::storage(id, caps))
            .collect())
    }

    async fn get_storage(
        &self,
        ctx: &SecurityContext,
        storage_id: &str,
    ) -> Result<Storage, FileStorageError> {
        self.service.authorize_backends_read(ctx).await?;
        let (id, caps) = self.service.get_backend(storage_id)?;
        Ok(sdk_convert::storage(id, caps))
    }

    async fn get_policy(
        &self,
        ctx: &SecurityContext,
        scope: PolicyScope,
        scope_owner_id: Option<Uuid>,
    ) -> Result<Option<Policy>, FileStorageError> {
        let stored = self
            .policy_service
            .get_own_policy(
                ctx,
                sdk_convert::policy_scope_to_domain(scope),
                scope_owner_id,
            )
            .await?;
        Ok(stored.map(sdk_convert::stored_policy))
    }

    async fn get_effective_policy(
        &self,
        ctx: &SecurityContext,
        user_owner_id: Option<Uuid>,
    ) -> Result<EffectivePolicy, FileStorageError> {
        let ep = self
            .policy_service
            .get_effective_policy(ctx, user_owner_id)
            .await?;
        Ok(sdk_convert::effective_policy(ep))
    }

    async fn put_policy(
        &self,
        ctx: &SecurityContext,
        scope: PolicyScope,
        scope_owner_id: Option<Uuid>,
        body: PolicyBody,
    ) -> Result<Policy, FileStorageError> {
        let stored = self
            .policy_service
            .set_policy(
                ctx,
                sdk_convert::policy_scope_to_domain(scope),
                scope_owner_id,
                sdk_convert::policy_body_to_domain(body),
            )
            .await?;
        Ok(sdk_convert::stored_policy(stored))
    }

    async fn list_retention_rules(
        &self,
        ctx: &SecurityContext,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<Page<RetentionRule>, FileStorageError> {
        let page = self
            .policy_service
            .list_retention_rules(ctx, limit, cursor)
            .await?;
        Ok(page.map_items(sdk_convert::stored_retention_rule))
    }

    async fn create_retention_rule(
        &self,
        ctx: &SecurityContext,
        scope: RetentionScope,
        scope_target_id: Option<Uuid>,
        body: RetentionRuleBody,
    ) -> Result<RetentionRule, FileStorageError> {
        let rule = self
            .policy_service
            .create_retention_rule(
                ctx,
                sdk_convert::retention_scope_to_domain(scope),
                scope_target_id,
                sdk_convert::retention_rule_body_to_domain(body),
            )
            .await?;
        Ok(sdk_convert::stored_retention_rule(rule))
    }

    async fn delete_retention_rule(
        &self,
        ctx: &SecurityContext,
        rule_id: Uuid,
    ) -> Result<(), FileStorageError> {
        let removed = self
            .policy_service
            .delete_retention_rule(ctx, rule_id)
            .await?;
        if removed {
            Ok(())
        } else {
            Err(crate::domain::error::DomainError::retention_rule_not_found(rule_id).into())
        }
    }
}

#[cfg(test)]
#[path = "local_client_tests.rs"]
mod local_client_tests;
