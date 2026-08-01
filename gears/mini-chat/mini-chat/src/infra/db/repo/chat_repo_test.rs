use std::sync::Arc;

use toolkit_db::DBProvider;
use toolkit_db::odata::LimitCfg;
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::repos::ChatRepository as _;
use crate::domain::service::test_helpers::{inmem_db, mock_db_provider};

use super::ChatRepository;

type Db = Arc<DBProvider<toolkit_db::DbError>>;

fn limit_cfg() -> LimitCfg {
    LimitCfg::new(20, 100)
}

async fn test_db() -> Db {
    mock_db_provider(inmem_db().await)
}

// ════════════════════════════════════════════════════════════════════
// ML-5130: list_page must classify client-caused OData errors as
// DomainError::Validation (-> HTTP 400), not DomainError::Database
// (-> HTTP 500). An unknown $orderby field never reaches SQL: it fails
// inside paginate_odata's field-resolution loop with
// toolkit_odata::Error::InvalidOrderByField, before any row is read, so
// no fixture rows are needed to exercise the classifier.
// ════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn list_page_unknown_orderby_field_returns_validation_not_database() {
    let db = test_db().await;
    let tenant_id = Uuid::new_v4();

    let repo = ChatRepository::new(limit_cfg());
    let conn = db.conn().unwrap();
    let scope = AccessScope::for_tenant(tenant_id);

    let query = toolkit_odata::ODataQuery::new().with_order(toolkit_odata::ODataOrderBy(vec![
        toolkit_odata::OrderKey {
            field: "not_a_real_field".to_owned(),
            dir: toolkit_odata::SortDir::Asc,
        },
    ]));

    let err = repo
        .list_page(&conn, &scope, &query)
        .await
        .expect_err("unknown $orderby field must be rejected");

    assert!(
        matches!(err, crate::domain::error::DomainError::Validation { .. }),
        "client-caused $orderby error must classify as Validation (400), got {err:?}"
    );
}
