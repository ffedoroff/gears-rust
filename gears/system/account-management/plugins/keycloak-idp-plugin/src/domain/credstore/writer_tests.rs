// Updated: 2026-10-06 by Constructor Tech
use super::*;
use crate::domain::system_actor::build_system_ctx;
use crate::domain::test_support::{
    cs_already_exists, cs_not_found, cs_precondition_failed, cs_unavailable,
};
use async_trait::async_trait;
use credstore_sdk::{
    Credential, CredentialListItem, CredentialPatch, PutOutcome, Secret, Validator,
};
use parking_lot::Mutex;
use toolkit_canonical_errors::CanonicalError;
use toolkit_odata::{ODataQuery, Page};
use uuid::Uuid;

/// One recorded `put` invocation — `(key_str, value_bytes, sharing)`.
type PutCall = (String, Vec<u8>, SharingMode);

/// Stub unified client capturing `put` calls and serving one canned
/// `delete` response.
#[domain_model]
#[derive(Default)]
struct StubMutator {
    /// All recorded `put` invocations.
    put_calls: Mutex<Vec<PutCall>>,
    /// One-shot response for the next `delete` call; defaults to `Ok(())`.
    delete_response: Mutex<Option<Result<(), CanonicalError>>>,
    /// Scripted `put` responses, consumed in call order; empty → `Ok`.
    put_responses: Mutex<std::collections::VecDeque<Result<(), CanonicalError>>>,
    /// The precondition of every `put`, in call order.
    put_preconditions: Mutex<Vec<PutPrecondition>>,
}

#[async_trait]
impl CredStoreClientV2 for StubMutator {
    async fn get_record(
        &self,
        _ctx: &SecurityContext,
        _key: &SecretRef,
    ) -> Result<Option<Credential>, CanonicalError> {
        Ok(None)
    }

    async fn get_secret(
        &self,
        _ctx: &SecurityContext,
        _key: &SecretRef,
    ) -> Result<Option<Secret>, CanonicalError> {
        Ok(None)
    }

    async fn put(
        &self,
        _ctx: &SecurityContext,
        key: &SecretRef,
        write: CredentialWrite,
        precondition: PutPrecondition,
    ) -> Result<PutOutcome, CanonicalError> {
        self.put_preconditions.lock().push(precondition);
        self.put_calls.lock().push((
            key.as_ref().to_owned(),
            match &write.secret {
                credstore_sdk::SecretWrite::Set(v) => v.as_bytes().to_vec(),
                credstore_sdk::SecretWrite::Null => Vec::new(),
            },
            write.sharing,
        ));
        self.put_responses.lock().pop_front().unwrap_or(Ok(()))?;
        Ok(PutOutcome {
            created: true,
            validator: Validator {
                id: Uuid::nil(),
                version: 1,
            },
        })
    }

    async fn patch(
        &self,
        _ctx: &SecurityContext,
        _key: &SecretRef,
        _patch: CredentialPatch,
        _precondition: WritePrecondition,
    ) -> Result<Validator, CanonicalError> {
        Ok(Validator {
            id: Uuid::nil(),
            version: 1,
        })
    }

    async fn delete(
        &self,
        _ctx: &SecurityContext,
        _key: &SecretRef,
        _precondition: WritePrecondition,
    ) -> Result<(), CanonicalError> {
        self.delete_response.lock().take().unwrap_or(Ok(()))
    }

    async fn list(
        &self,
        _ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<CredentialListItem>, CanonicalError> {
        Ok(Page::empty(query.limit.unwrap_or(0)))
    }
}

#[tokio::test]
async fn put_forwards_with_system_ctx() {
    let stub = Arc::new(StubMutator::default());
    let ctx = build_system_ctx(Uuid::nil());
    let writer = CredStoreWriter::new(stub.clone(), ctx);
    let key = SecretRef::new("k").expect("valid SecretRef");
    let val = SecretValue::from("v");
    writer
        .put(&key, val, SharingMode::Tenant)
        .await
        .expect("put ok");
    let calls = stub.put_calls.lock();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "k");
    assert_eq!(calls[0].1, b"v");
    assert_eq!(calls[0].2, SharingMode::Tenant);
}

#[tokio::test]
async fn delete_maps_not_found_to_ok() {
    let stub = Arc::new(StubMutator::default());
    *stub.delete_response.lock() = Some(Err(cs_not_found()));
    let ctx = build_system_ctx(Uuid::nil());
    let writer = CredStoreWriter::new(stub, ctx);
    let key = SecretRef::new("k").expect("valid SecretRef");
    writer
        .delete(&key)
        .await
        .expect("NotFound MUST be mapped to Ok");
}

#[tokio::test]
async fn delete_passes_other_errors_through() {
    let stub = Arc::new(StubMutator::default());
    *stub.delete_response.lock() = Some(Err(cs_unavailable("nope")));
    let ctx = build_system_ctx(Uuid::nil());
    let writer = CredStoreWriter::new(stub, ctx);
    let key = SecretRef::new("k").expect("valid SecretRef");
    let err = writer
        .delete(&key)
        .await
        .expect_err("non-NotFound MUST surface");
    assert!(matches!(err, CredStoreError::Unavailable { .. }));
}

#[tokio::test]
async fn delete_ok_stays_ok() {
    let stub = Arc::new(StubMutator::default());
    let ctx = build_system_ctx(Uuid::nil());
    let writer = CredStoreWriter::new(stub, ctx);
    let key = SecretRef::new("k").expect("valid SecretRef");
    writer.delete(&key).await.expect("Ok MUST stay Ok");
}

#[tokio::test]
async fn put_on_a_fresh_reference_is_one_create_only_call() {
    let stub = Arc::new(StubMutator::default());
    let writer = CredStoreWriter::new(stub.clone(), build_system_ctx(Uuid::nil()));
    let key = SecretRef::new("k").expect("valid SecretRef");
    writer
        .put(&key, SecretValue::from("v"), SharingMode::Tenant)
        .await
        .expect("put ok");
    assert_eq!(
        *stub.put_preconditions.lock(),
        [PutPrecondition::CreateOnly]
    );
}

#[tokio::test]
async fn put_over_an_existing_reference_falls_back_to_an_exists_overwrite() {
    let stub = Arc::new(StubMutator::default());
    stub.put_responses
        .lock()
        .push_back(Err(cs_already_exists()));
    let writer = CredStoreWriter::new(stub.clone(), build_system_ctx(Uuid::nil()));
    let key = SecretRef::new("k").expect("valid SecretRef");
    writer
        .put(&key, SecretValue::from("v"), SharingMode::Tenant)
        .await
        .expect("overwrite ok");
    assert_eq!(
        *stub.put_preconditions.lock(),
        [PutPrecondition::CreateOnly, PutPrecondition::Exists]
    );
    let calls = stub.put_calls.lock();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].1, b"v", "the overwrite carries the same value");
}

#[tokio::test]
async fn put_propagates_a_precondition_failure_when_the_record_vanishes_between_the_steps() {
    let stub = Arc::new(StubMutator::default());
    stub.put_responses
        .lock()
        .push_back(Err(cs_already_exists()));
    stub.put_responses
        .lock()
        .push_back(Err(cs_precondition_failed()));
    let writer = CredStoreWriter::new(stub.clone(), build_system_ctx(Uuid::nil()));
    let key = SecretRef::new("k").expect("valid SecretRef");
    let err = writer
        .put(&key, SecretValue::from("v"), SharingMode::Tenant)
        .await
        .expect_err("no retry loop");
    assert!(matches!(err, CredStoreError::PreconditionFailed));
    assert_eq!(stub.put_preconditions.lock().len(), 2, "no third attempt");
}

#[tokio::test]
async fn put_propagates_other_create_errors_without_an_overwrite() {
    let stub = Arc::new(StubMutator::default());
    stub.put_responses
        .lock()
        .push_back(Err(cs_unavailable("down")));
    let writer = CredStoreWriter::new(stub.clone(), build_system_ctx(Uuid::nil()));
    let key = SecretRef::new("k").expect("valid SecretRef");
    let err = writer
        .put(&key, SecretValue::from("v"), SharingMode::Tenant)
        .await
        .expect_err("surfaces");
    assert!(matches!(err, CredStoreError::Unavailable { .. }));
    assert_eq!(stub.put_preconditions.lock().len(), 1);
}
