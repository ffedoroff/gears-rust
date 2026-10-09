#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use sea_orm_migration::MigratorTrait;
use toolkit::api::canonical_prelude::CanonicalError;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use file_storage::domain::authz::{Authorizer, actions};
use file_storage::domain::error::DomainError;
use file_storage::domain::policy::{
    AgeRetention, MimeSizeOverride, PolicyBody, PolicyScope, RetentionRuleBody, RetentionScope,
    SizeLimits,
};
use file_storage::domain::policy_service::PolicyService;
use file_storage::domain::ports::PolicyStore;
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{BackendRegistry, InMemoryBackend, StorageBackend};
use file_storage::infra::signed_url::Issuer;
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::{NewFile, OwnerFilter, OwnerKind};

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

/// Grants `READ`/`WRITE`/`DELETE` unconditionally (subject to `deny_write_for`), but only grants
/// `ADMIN_POLICY` while `is_admin` is set.
#[derive(Default)]
pub struct ScopedTestAuthorizer {
    is_admin: AtomicBool,
    deny_write_for: Mutex<Option<Uuid>>,
}

impl ScopedTestAuthorizer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_admin(&self, admin: bool) {
        self.is_admin.store(admin, Ordering::SeqCst);
    }

    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn deny_write_for_file(&self, file_id: Uuid) {
        *self.deny_write_for.lock().expect("lock poisoned") = Some(file_id);
    }
}

#[async_trait]
impl Authorizer for ScopedTestAuthorizer {
    async fn authorize(
        &self,
        ctx: &SecurityContext,
        action: &str,
        _gts_file_type: &str,
        file_id: Option<Uuid>,
    ) -> Result<AccessScope, DomainError> {
        if action == actions::ADMIN_POLICY {
            return if self.is_admin.load(Ordering::SeqCst) {
                Ok(AccessScope::for_tenant(ctx.subject_tenant_id()))
            } else {
                Err(DomainError::Forbidden)
            };
        }

        if action == actions::WRITE
            && let Some(denied) = *self.deny_write_for.lock().expect("lock poisoned")
            && Some(denied) == file_id
        {
            return Err(DomainError::Forbidden);
        }

        Ok(AccessScope::for_tenant(ctx.subject_tenant_id()))
    }
}

async fn build_db() -> Arc<DBProvider<DbError>> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-policy-authz-test-{}.db",
        Uuid::now_v7().simple()
    ));
    let dsn = format!("sqlite://{}?mode=rwc", path.display());
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let db = connect_db(&dsn, opts).await.expect("connect sqlite");
    run_migrations_for_testing(&db, Migrator::migrations())
        .await
        .expect("migrations");
    Arc::new(DBProvider::new(db))
}

struct Harness {
    file_svc: Arc<FileService>,
    policy_svc: Arc<PolicyService>,
    policy_store: Arc<dyn PolicyStore>,
    authz: Arc<ScopedTestAuthorizer>,
}

async fn build_harness() -> Harness {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![backend], "mem").expect("registry");
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let authz = Arc::new(ScopedTestAuthorizer::new());
    let authorizer: Arc<dyn Authorizer> = Arc::clone(&authz) as Arc<dyn Authorizer>;
    let cfg = ServiceConfig {
        default_url_ttl_secs: 3600,
        sidecar_base_url: "http://sidecar.test".to_owned(),
        default_page_size: 50,
        max_page_size: 1000,
        idempotency_ttl_secs: 86400,
    };
    let default_page_size = cfg.default_page_size;
    let max_page_size = cfg.max_page_size;
    let store = Store::new(Arc::clone(&db));
    let policy_store: Arc<dyn PolicyStore> = Arc::new(store.clone());
    let file_svc = Arc::new(FileService::new(
        store,
        backends,
        issuer,
        Arc::clone(&authorizer),
        cfg,
        None,
        None,
    ));
    let policy_svc = Arc::new(PolicyService::new(
        Arc::clone(&policy_store),
        Arc::clone(&authorizer),
        default_page_size,
        max_page_size,
    ));
    Harness {
        file_svc,
        policy_svc,
        policy_store,
        authz,
    }
}

fn ctx(tenant: Uuid, subject: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(subject)
        .subject_tenant_id(tenant)
        .build()
        .expect("ctx")
}

fn valid_rule_body() -> RetentionRuleBody {
    RetentionRuleBody {
        age: Some(AgeRetention { max_age_days: 30 }),
        inactivity: None,
        metadata: None,
    }
}

fn new_file(owner_id: Uuid) -> NewFile {
    NewFile {
        owner_kind: OwnerKind::User,
        owner_id,
        name: "victim.bin".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: "application/octet-stream".to_owned(),
        custom_metadata: vec![],
    }
}

/// `PUT /policy?scope=user&scope_owner_id=<victim>` from a non-owner, non-admin caller must be
/// denied and must not write a row.
#[tokio::test]
async fn set_policy_foreign_owner_without_admin_scope_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);

    let result = h
        .policy_svc
        .set_policy(
            &ctx_a,
            PolicyScope::User,
            Some(user_b),
            PolicyBody::default(),
        )
        .await;

    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );

    let row = h
        .policy_store
        .get_policy(
            &AccessScope::allow_all(),
            tenant,
            &PolicyScope::User,
            Some(user_b),
        )
        .await
        .expect("get_policy");
    assert!(row.is_none(), "no policy row should exist for user_b");
}

/// Positive control: setting one's own user-scope policy is always allowed.
#[tokio::test]
async fn set_policy_self_owner_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);

    let stored = h
        .policy_svc
        .set_policy(
            &ctx_a,
            PolicyScope::User,
            Some(user_a),
            PolicyBody::default(),
        )
        .await
        .expect("set_policy should succeed for self");
    assert_eq!(stored.scope_owner_id, Some(user_a));

    let row = h
        .policy_store
        .get_policy(
            &AccessScope::allow_all(),
            tenant,
            &PolicyScope::User,
            Some(user_a),
        )
        .await
        .expect("get_policy")
        .expect("row must exist");
    assert_eq!(row.scope_owner_id, Some(user_a));
}

#[tokio::test]
async fn set_policy_tenant_admin_scope_allows_foreign_owner() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    h.authz.set_admin(true);

    let stored = h
        .policy_svc
        .set_policy(
            &ctx_admin,
            PolicyScope::User,
            Some(user_b),
            PolicyBody::default(),
        )
        .await
        .expect("admin should be able to set foreign owner's policy");
    assert_eq!(stored.scope_owner_id, Some(user_b));

    let row = h
        .policy_store
        .get_policy(
            &AccessScope::allow_all(),
            tenant,
            &PolicyScope::User,
            Some(user_b),
        )
        .await
        .expect("get_policy")
        .expect("row must exist for user_b");
    assert_eq!(row.scope_owner_id, Some(user_b));
}

#[tokio::test]
async fn get_own_policy_user_scope_without_owner_is_rejected() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let result = h
        .policy_svc
        .get_own_policy(&ctx_a, PolicyScope::User, None)
        .await;
    assert!(
        matches!(result, Err(DomainError::Validation { .. })),
        "expected Validation, got {result:?}"
    );
}

/// Positive control: `scope=tenant` with no `scope_owner_id` is the normal (and only valid) shape
/// for a tenant-scope read, and must not be rejected.
#[tokio::test]
async fn get_own_policy_tenant_scope_without_owner_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let result = h
        .policy_svc
        .get_own_policy(&ctx_a, PolicyScope::Tenant, None)
        .await;
    assert!(
        result.is_ok(),
        "tenant-scope read with no owner must be allowed, got {result:?}"
    );
}

#[tokio::test]
async fn get_own_policy_tenant_scope_with_owner_is_rejected() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let result = h
        .policy_svc
        .get_own_policy(&ctx_a, PolicyScope::Tenant, Some(owner))
        .await;
    assert!(
        matches!(result, Err(DomainError::Validation { .. })),
        "expected Validation, got {result:?}"
    );
}

/// A `scope=file` retention rule staged against a file the caller cannot `WRITE` must be denied,
/// and no row may be written.
#[tokio::test]
async fn create_retention_rule_file_scope_target_not_writable_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let ticket = h
        .file_svc
        .create_file(&ctx_a, new_file(owner), None, false)
        .await
        .expect("create victim file");
    h.authz.deny_write_for_file(ticket.file_id);

    let result = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::File,
            Some(ticket.file_id),
            valid_rule_body(),
        )
        .await;
    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant)
        .await
        .expect("list_retention_rules");
    assert_eq!(rules.len(), 0, "no retention rule row should be written");
}

/// Positive control: a `scope=file` rule against a real, writable file succeeds.
#[tokio::test]
async fn create_retention_rule_file_scope_target_writable_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let ticket = h
        .file_svc
        .create_file(&ctx_a, new_file(owner), None, false)
        .await
        .expect("create file");

    let rule = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::File,
            Some(ticket.file_id),
            valid_rule_body(),
        )
        .await
        .expect("create_retention_rule should succeed for a writable file");
    assert_eq!(rule.scope_target_id, Some(ticket.file_id));

    // B4: a nonexistent scope_target_id must 404, not silently pre-stage.
    let nonexistent = Uuid::now_v7();
    let result = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::File,
            Some(nonexistent),
            valid_rule_body(),
        )
        .await;
    assert!(
        matches!(result, Err(DomainError::FileNotFound { id }) if id == nonexistent),
        "expected FileNotFound, got {result:?}"
    );

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant)
        .await
        .expect("list_retention_rules");
    assert_eq!(rules.len(), 1, "only the writable-file rule should exist");
}

#[tokio::test]
async fn create_retention_rule_file_scope_target_foreign_tenant_is_not_found() {
    let h = build_harness().await;
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let owner_a = Uuid::now_v7();
    let owner_b = Uuid::now_v7();
    let ctx_a = ctx(tenant_a, owner_a);
    let ctx_b = ctx(tenant_b, owner_b);

    let ticket = h
        .file_svc
        .create_file(&ctx_a, new_file(owner_a), None, false)
        .await
        .expect("tenant A creates a file");

    let result = h
        .policy_svc
        .create_retention_rule(
            &ctx_b,
            RetentionScope::File,
            Some(ticket.file_id),
            valid_rule_body(),
        )
        .await;
    assert!(
        matches!(result, Err(DomainError::FileNotFound { id }) if id == ticket.file_id),
        "expected FileNotFound (foreign-tenant file must not resolve), got {result:?}"
    );

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant_b)
        .await
        .expect("list_retention_rules");
    assert_eq!(
        rules.len(),
        0,
        "no rule should be created under tenant B pointing at tenant A's file"
    );
}

/// A `User`-scope retention rule created by user A must not be deletable by user B (same tenant, no
/// `ADMIN_POLICY`).
#[tokio::test]
async fn delete_retention_rule_foreign_owner_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);
    let ctx_b = ctx(tenant, user_b);

    let rule = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::User,
            Some(user_a),
            valid_rule_body(),
        )
        .await
        .expect("user A creates own rule");

    let result = h
        .policy_svc
        .delete_retention_rule(&ctx_b, rule.rule_id)
        .await;
    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );

    let still_there = h
        .policy_store
        .get_retention_rule(&AccessScope::allow_all(), rule.rule_id)
        .await
        .expect("get_retention_rule")
        .expect("rule must still exist");
    assert_eq!(still_there.rule_id, rule.rule_id);
}

#[tokio::test]
async fn delete_file_cascade_removes_file_scope_retention_rule() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let ticket = h
        .file_svc
        .create_file(&ctx_a, new_file(owner), None, false)
        .await
        .expect("create file");

    let rule = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::File,
            Some(ticket.file_id),
            valid_rule_body(),
        )
        .await
        .expect("create file-scope rule");

    // Delete the target file (unconditional delete) -- the rule must go with it, in the same
    // delete, with no separate cleanup step.
    h.file_svc
        .delete_file(&ctx_a, ticket.file_id, Some("*"))
        .await
        .expect("delete target file");

    let gone = h
        .policy_store
        .get_retention_rule(&AccessScope::allow_all(), rule.rule_id)
        .await
        .expect("get_retention_rule");
    assert!(
        gone.is_none(),
        "the file-scope rule must be removed along with its target file"
    );

    let result = h
        .policy_svc
        .delete_retention_rule(&ctx_a, rule.rule_id)
        .await;
    assert!(
        matches!(
            result,
            Err(DomainError::RetentionRuleNotFound { rule_id }) if rule_id == rule.rule_id
        ),
        "expected RetentionRuleNotFound for an already-cascaded rule, got {result:?}"
    );
}

#[tokio::test]
async fn delete_retention_rule_after_file_cascade_is_not_found_for_any_tenant() {
    let h = build_harness().await;
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let owner_a = Uuid::now_v7();
    let owner_b = Uuid::now_v7();
    let ctx_a = ctx(tenant_a, owner_a);
    let ctx_b = ctx(tenant_b, owner_b);

    let ticket = h
        .file_svc
        .create_file(&ctx_a, new_file(owner_a), None, false)
        .await
        .expect("tenant A creates a file");

    let rule = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::File,
            Some(ticket.file_id),
            valid_rule_body(),
        )
        .await
        .expect("tenant A creates a file-scope rule");

    h.file_svc
        .delete_file(&ctx_a, ticket.file_id, Some("*"))
        .await
        .expect("tenant A deletes the target file");

    let still_there = h
        .policy_store
        .get_retention_rule(&AccessScope::allow_all(), rule.rule_id)
        .await
        .expect("get_retention_rule");
    assert!(
        still_there.is_none(),
        "the rule must have been cascaded away with tenant A's file"
    );

    let result = h
        .policy_svc
        .delete_retention_rule(&ctx_b, rule.rule_id)
        .await;
    assert!(
        matches!(
            result,
            Err(DomainError::RetentionRuleNotFound { rule_id }) if rule_id == rule.rule_id
        ),
        "tenant B must see RetentionRuleNotFound rather than Forbidden or a silent no-op; \
         got {result:?}"
    );
}

#[tokio::test]
async fn delete_retention_rule_foreign_tenant_gets_same_error_as_nonexistent_id() {
    let h = build_harness().await;
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let owner_a = Uuid::now_v7();
    let owner_b = Uuid::now_v7();
    let ctx_a = ctx(tenant_a, owner_a);
    let ctx_b = ctx(tenant_b, owner_b);

    h.authz.set_admin(true);
    let rule = h
        .policy_svc
        .create_retention_rule(&ctx_a, RetentionScope::Tenant, None, valid_rule_body())
        .await
        .expect("tenant A creates a tenant-scope rule");
    h.authz.set_admin(false);

    let foreign_result = h
        .policy_svc
        .delete_retention_rule(&ctx_b, rule.rule_id)
        .await;

    let missing_rule_id = Uuid::now_v7();
    let missing_result = h
        .policy_svc
        .delete_retention_rule(&ctx_b, missing_rule_id)
        .await;

    match (&foreign_result, &missing_result) {
        (
            Err(DomainError::RetentionRuleNotFound {
                rule_id: foreign_id,
            }),
            Err(DomainError::RetentionRuleNotFound {
                rule_id: missing_id,
            }),
        ) => {
            assert_eq!(*foreign_id, rule.rule_id);
            assert_eq!(*missing_id, missing_rule_id);
        }
        other => panic!(
            "both a foreign-tenant existing rule_id and a nonexistent rule_id must produce \
             RetentionRuleNotFound identically, got {other:?}"
        ),
    }

    // Sanity: the rule must genuinely still exist (owned by tenant A) — the 404 tenant B sees is a
    // scoping artifact, not an actual deletion.
    let still_there = h
        .policy_store
        .get_retention_rule(&AccessScope::allow_all(), rule.rule_id)
        .await
        .expect("get_retention_rule")
        .expect("rule must still exist, owned by tenant A");
    assert_eq!(still_there.tenant_id, tenant_a);
}

#[tokio::test]
async fn delete_missing_retention_rule_returns_retention_not_found() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user = Uuid::now_v7();
    let missing_rule_id = Uuid::now_v7();

    let result = h
        .policy_svc
        .delete_retention_rule(&ctx(tenant, user), missing_rule_id)
        .await;
    assert!(
        matches!(
            result,
            Err(DomainError::RetentionRuleNotFound { rule_id }) if rule_id == missing_rule_id
        ),
        "expected RetentionRuleNotFound({missing_rule_id}), got {result:?}"
    );

    let err = result.expect_err("must be an error");
    let canonical: CanonicalError = err.into();
    assert_eq!(canonical.status_code(), 404);
    assert!(
        canonical
            .resource_type()
            .is_some_and(|t| t.contains("retention_rule")),
        "resource type must name a retention rule, got {:?}",
        canonical.resource_type()
    );
    assert!(
        canonical.detail().contains("Retention rule"),
        "detail must name a retention rule, not a file, got {:?}",
        canonical.detail()
    );
    assert!(
        !canonical.detail().to_lowercase().starts_with("file "),
        "detail must not mislabel the resource as a file, got {:?}",
        canonical.detail()
    );
}

#[tokio::test]
async fn create_retention_rule_zero_max_age_is_rejected() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let result = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::User,
            Some(owner),
            RetentionRuleBody {
                age: Some(AgeRetention { max_age_days: 0 }),
                inactivity: None,
                metadata: None,
            },
        )
        .await;
    assert!(
        matches!(result, Err(DomainError::Validation { .. })),
        "expected Validation, got {result:?}"
    );

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant)
        .await
        .expect("list_retention_rules");
    assert_eq!(rules.len(), 0, "no retention rule row should be written");
}

#[tokio::test]
async fn create_retention_rule_all_criteria_none_is_rejected() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let result = h
        .policy_svc
        .create_retention_rule(
            &ctx_a,
            RetentionScope::User,
            Some(owner),
            RetentionRuleBody::default(),
        )
        .await;
    assert!(
        matches!(result, Err(DomainError::Validation { .. })),
        "expected Validation, got {result:?}"
    );

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant)
        .await
        .expect("list_retention_rules");
    assert_eq!(rules.len(), 0, "no retention rule row should be written");
}

/// A `User`-scope retention rule with `scope_target_id = None` is a dead rule (it can never resolve
/// to a target user).
#[tokio::test]
async fn create_retention_rule_user_scope_without_target_is_rejected() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    h.authz.set_admin(true);

    let result = h
        .policy_svc
        .create_retention_rule(&ctx_admin, RetentionScope::User, None, valid_rule_body())
        .await;
    assert!(
        matches!(result, Err(DomainError::Validation { .. })),
        "expected Validation, got {result:?}"
    );

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant)
        .await
        .expect("list_retention_rules");
    assert_eq!(rules.len(), 0, "no retention rule row should be written");
}

#[tokio::test]
async fn set_policy_user_scope_without_owner_is_rejected() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let result = h
        .policy_svc
        .set_policy(&ctx_a, PolicyScope::User, None, PolicyBody::default())
        .await;
    assert!(
        matches!(result, Err(DomainError::Validation { .. })),
        "expected Validation, got {result:?}"
    );
}

#[tokio::test]
async fn set_policy_tenant_scope_with_owner_is_rejected() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let result = h
        .policy_svc
        .set_policy(
            &ctx_a,
            PolicyScope::Tenant,
            Some(owner),
            PolicyBody::default(),
        )
        .await;
    assert!(
        matches!(result, Err(DomainError::Validation { .. })),
        "expected Validation, got {result:?}"
    );
}

#[tokio::test]
async fn set_policy_star_slash_star_mime_is_rejected_or_defined() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let ctx_a = ctx(tenant, owner);

    let allowed_result = h
        .policy_svc
        .set_policy(
            &ctx_a,
            PolicyScope::User,
            Some(owner),
            PolicyBody {
                allowed_mime_types: vec!["*/*".to_owned()],
                ..PolicyBody::default()
            },
        )
        .await;
    assert!(
        matches!(allowed_result, Err(DomainError::Validation { .. })),
        "expected '*/*' in allowed_mime_types to be rejected, got {allowed_result:?}"
    );

    let per_mime_result = h
        .policy_svc
        .set_policy(
            &ctx_a,
            PolicyScope::User,
            Some(owner),
            PolicyBody {
                size_limits: SizeLimits {
                    max_bytes: None,
                    per_mime: vec![MimeSizeOverride {
                        mime: "*/*".to_owned(),
                        max_bytes: 1024,
                    }],
                },
                ..PolicyBody::default()
            },
        )
        .await;
    assert!(
        matches!(per_mime_result, Err(DomainError::Validation { .. })),
        "expected '*/*' in size_limits.per_mime to be rejected, got {per_mime_result:?}"
    );

    let row = h
        .policy_store
        .get_policy(
            &AccessScope::allow_all(),
            tenant,
            &PolicyScope::User,
            Some(owner),
        )
        .await
        .expect("get_policy");
    assert!(row.is_none(), "no policy row should be written");
}

/// `PUT /policy?scope=tenant` (no `scope_owner_id`) applies to every subject in the tenant.
#[tokio::test]
async fn set_policy_tenant_scope_without_admin_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user = Uuid::now_v7();
    let ctx_a = ctx(tenant, user);

    let result = h
        .policy_svc
        .set_policy(&ctx_a, PolicyScope::Tenant, None, PolicyBody::default())
        .await;
    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );

    let row = h
        .policy_store
        .get_policy(
            &AccessScope::allow_all(),
            tenant,
            &PolicyScope::Tenant,
            None,
        )
        .await
        .expect("get_policy");
    assert!(row.is_none(), "no tenant policy row should exist");
}

/// Positive control: an `ADMIN_POLICY`-authorized caller may set the tenant-scope policy.
#[tokio::test]
async fn set_policy_tenant_scope_with_admin_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    h.authz.set_admin(true);

    let stored = h
        .policy_svc
        .set_policy(&ctx_admin, PolicyScope::Tenant, None, PolicyBody::default())
        .await
        .expect("admin should be able to set the tenant-scope policy");
    assert_eq!(stored.scope, PolicyScope::Tenant);
    assert_eq!(stored.scope_owner_id, None);

    let row = h
        .policy_store
        .get_policy(
            &AccessScope::allow_all(),
            tenant,
            &PolicyScope::Tenant,
            None,
        )
        .await
        .expect("get_policy")
        .expect("tenant policy row must exist");
    assert_eq!(row.scope, PolicyScope::Tenant);
}

/// A `scope=tenant` retention rule is a standing instruction for the cleanup job to
/// permanently delete every matching file in the tenant, with no owner filter.
#[tokio::test]
async fn create_retention_rule_tenant_scope_without_admin_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user = Uuid::now_v7();
    let ctx_a = ctx(tenant, user);

    let result = h
        .policy_svc
        .create_retention_rule(&ctx_a, RetentionScope::Tenant, None, valid_rule_body())
        .await;
    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant)
        .await
        .expect("list_retention_rules");
    assert_eq!(
        rules.len(),
        0,
        "no tenant-scope retention rule should be written"
    );
}

/// Positive control: an `ADMIN_POLICY`-authorized caller may create a `scope=tenant` retention
/// rule.
#[tokio::test]
async fn create_retention_rule_tenant_scope_with_admin_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    h.authz.set_admin(true);

    let rule = h
        .policy_svc
        .create_retention_rule(&ctx_admin, RetentionScope::Tenant, None, valid_rule_body())
        .await
        .expect("admin should be able to create a tenant-scope retention rule");
    assert_eq!(rule.scope, RetentionScope::Tenant);
    assert_eq!(rule.scope_target_id, None);

    let rules = h
        .policy_store
        .list_retention_rules(&AccessScope::allow_all(), tenant)
        .await
        .expect("list_retention_rules");
    assert_eq!(rules.len(), 1, "the tenant-scope rule should be stored");
    assert_eq!(rules[0].rule_id, rule.rule_id);
}

#[tokio::test]
async fn delete_retention_rule_tenant_scope_without_admin_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let user = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    let ctx_user = ctx(tenant, user);

    h.authz.set_admin(true);
    let rule = h
        .policy_svc
        .create_retention_rule(&ctx_admin, RetentionScope::Tenant, None, valid_rule_body())
        .await
        .expect("admin creates the tenant-scope rule");
    h.authz.set_admin(false);

    let result = h
        .policy_svc
        .delete_retention_rule(&ctx_user, rule.rule_id)
        .await;
    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );

    let still_there = h
        .policy_store
        .get_retention_rule(&AccessScope::allow_all(), rule.rule_id)
        .await
        .expect("get_retention_rule")
        .expect("rule must still exist");
    assert_eq!(still_there.rule_id, rule.rule_id);
}

#[tokio::test]
async fn get_effective_policy_foreign_owner_without_admin_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);

    let result = h
        .policy_svc
        .get_effective_policy(&ctx_a, Some(user_b))
        .await;
    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );
}

/// Positive control: a caller reading their own effective policy (`user_owner_id ==
/// ctx.subject_id()`) is always allowed.
#[tokio::test]
async fn get_effective_policy_self_owner_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);

    let result = h
        .policy_svc
        .get_effective_policy(&ctx_a, Some(user_a))
        .await;
    assert!(
        result.is_ok(),
        "reading one's own effective policy must be allowed, got {result:?}"
    );
}

/// Positive control: `user_owner_id = None` (tenant-level effective policy only) is always allowed
/// -- there is no victim's user-level policy being disclosed.
#[tokio::test]
async fn get_effective_policy_no_owner_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);

    let result = h.policy_svc.get_effective_policy(&ctx_a, None).await;
    assert!(
        result.is_ok(),
        "no user_owner_id must be allowed, got {result:?}"
    );
}

#[tokio::test]
async fn get_effective_policy_foreign_owner_with_admin_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    h.authz.set_admin(true);

    h.policy_svc
        .set_policy(
            &ctx_admin,
            PolicyScope::User,
            Some(user_b),
            PolicyBody {
                allowed_mime_types: vec!["image/png".to_owned()],
                ..PolicyBody::default()
            },
        )
        .await
        .expect("admin sets user_b's policy");

    let effective = h
        .policy_svc
        .get_effective_policy(&ctx_admin, Some(user_b))
        .await
        .expect("admin should be able to read a foreign owner's effective policy");
    assert_eq!(
        effective.allowed_mime_types,
        Some(vec!["image/png".to_owned()]),
        "effective policy must reflect user_b's own policy, not an empty default"
    );
}

/// A non-admin caller must see tenant-scope rules (nothing owner-specific to hide) and their own
/// user-scope rules, but not another user's user-scope rule.
#[tokio::test]
async fn list_retention_rules_filters_by_scope_for_non_admin() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let subject = Uuid::now_v7();
    let other_user = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    let ctx_subject = ctx(tenant, subject);

    h.authz.set_admin(true);
    let tenant_rule = h
        .policy_svc
        .create_retention_rule(&ctx_admin, RetentionScope::Tenant, None, valid_rule_body())
        .await
        .expect("admin creates the tenant-scope rule");
    let subject_rule = h
        .policy_svc
        .create_retention_rule(
            &ctx_admin,
            RetentionScope::User,
            Some(subject),
            valid_rule_body(),
        )
        .await
        .expect("admin creates the subject's user-scope rule");
    let other_rule = h
        .policy_svc
        .create_retention_rule(
            &ctx_admin,
            RetentionScope::User,
            Some(other_user),
            valid_rule_body(),
        )
        .await
        .expect("admin creates the other user's user-scope rule");
    h.authz.set_admin(false);

    let visible = h
        .policy_svc
        .list_retention_rules(&ctx_subject, None, None)
        .await
        .expect("list_retention_rules should succeed for a non-admin")
        .items;
    let visible_ids: std::collections::HashSet<Uuid> = visible.iter().map(|r| r.rule_id).collect();
    let expected_visible: std::collections::HashSet<Uuid> =
        [tenant_rule.rule_id, subject_rule.rule_id]
            .into_iter()
            .collect();
    assert_eq!(
        visible_ids, expected_visible,
        "non-admin must see exactly the tenant-scope rule and their own user-scope rule"
    );
    assert!(
        !visible_ids.contains(&other_rule.rule_id),
        "non-admin must not see another user's user-scope rule"
    );

    h.authz.set_admin(true);
    let all = h
        .policy_svc
        .list_retention_rules(&ctx_admin, None, None)
        .await
        .expect("list_retention_rules should succeed for admin")
        .items;
    let all_ids: std::collections::HashSet<Uuid> = all.iter().map(|r| r.rule_id).collect();
    let expected_all: std::collections::HashSet<Uuid> = [
        tenant_rule.rule_id,
        subject_rule.rule_id,
        other_rule.rule_id,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        all_ids, expected_all,
        "admin must see every rule in the tenant"
    );
}

/// `POST /files` with `owner_id` different from `ctx.subject_id()` must be denied for a non-admin
/// caller, and must not create a file row.
#[tokio::test]
async fn create_file_foreign_owner_without_admin_is_denied() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);

    let result = h
        .file_svc
        .create_file(&ctx_a, new_file(user_b), None, false)
        .await;
    assert!(
        matches!(result, Err(DomainError::Forbidden)),
        "expected Forbidden, got {result:?}"
    );

    h.authz.set_admin(true);
    let listed = h
        .file_svc
        .list_files(
            &ctx_a,
            OwnerFilter {
                owner_kind: OwnerKind::User,
                owner_id: user_b,
            },
            None,
            None,
        )
        .await
        .expect("list_files as admin-scope check");
    assert!(
        listed.items.is_empty(),
        "denied create_file must not have written a file row for user_b"
    );
}

/// Positive control: creating a file under one's own `owner_id` is always allowed.
#[tokio::test]
async fn create_file_self_owner_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let user_a = Uuid::now_v7();
    let ctx_a = ctx(tenant, user_a);

    let ticket = h
        .file_svc
        .create_file(&ctx_a, new_file(user_a), None, false)
        .await
        .expect("create_file should succeed for self owner");

    let file = h
        .file_svc
        .get_file(&ctx_a, ticket.file_id)
        .await
        .expect("created file must be readable");
    assert_eq!(file.owner_id, user_a);
}

#[tokio::test]
async fn create_file_foreign_owner_with_admin_is_allowed() {
    let h = build_harness().await;
    let tenant = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let user_b = Uuid::now_v7();
    let ctx_admin = ctx(tenant, admin);
    h.authz.set_admin(true);

    let ticket = h
        .file_svc
        .create_file(&ctx_admin, new_file(user_b), None, false)
        .await
        .expect("admin should be able to create a file under a foreign owner");

    let file = h
        .file_svc
        .get_file(&ctx_admin, ticket.file_id)
        .await
        .expect("created file must be readable");
    assert_eq!(file.owner_id, user_b);
}
