use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use futures::StreamExt;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use toolkit_utils::SecretString;
use tower::ServiceExt;
use uuid::Uuid;

use file_storage::domain::error::DomainError;
use file_storage::infra::backend::{
    BackendCapabilities, BackendRegistry, InMemoryBackend, LocalFsBackend, StorageBackend,
};
use file_storage::infra::metrics::NoopMetrics;
use file_storage::infra::signed_url::{Claims, Issuer, MultipartClaims, Op, UploadConstraints};

use super::{
    DEFAULT_MAX_BODY_BYTES, MAX_PREVIOUS_SIGNING_PUBLIC_KEYS, SidecarState, TokenQuery,
    build_config, build_router, dedupe_public_keys, extract_token, finalize_with_control_plane,
    idle_timeout_stream, interpret_finalize_response, parse_optional, parse_public_key_list,
    report_part_with_control_plane, write_multipart_part_native,
    write_multipart_part_offset_object,
};

async fn write_all(backend: &dyn StorageBackend, path: &str, bytes: Bytes) {
    let len = bytes.len() as u64;
    let stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>> =
        Box::pin(futures::stream::once(async move { Ok(bytes) }));
    backend
        .put_stream(path, stream, Some(len))
        .await
        .expect("put_stream");
}

async fn read_all(backend: &dyn StorageBackend, path: &str) -> Bytes {
    let expected_len = backend
        .stat(path)
        .await
        .expect("stat")
        .expect("blob must exist");
    let mut stream = backend
        .get_stream(path, expected_len)
        .await
        .expect("get_stream");
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        buf.extend_from_slice(&chunk.expect("chunk"));
    }
    Bytes::from(buf)
}

fn test_state() -> SidecarState {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backends = BackendRegistry::new(
        vec![Arc::new(InMemoryBackend::new("test")) as Arc<dyn StorageBackend>],
        "test",
    )
    .expect("build test backend registry");
    SidecarState {
        verifier: std::sync::Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    }
}

fn token_query(token: Option<&str>) -> TokenQuery {
    TokenQuery {
        fs_token: token.map(SecretString::new),
    }
}

fn header_map_with_token(token: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(token) = token {
        headers.insert(
            "x-fs-token",
            HeaderValue::from_str(token).expect("valid header value"),
        );
    }
    headers
}

#[test]
fn extract_token_missing_both_is_unauthorized() {
    let err = extract_token(&token_query(None), &header_map_with_token(None))
        .expect_err("must reject when neither transport carries a token");
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
}

/// Only the query param carries a token: used as-is.
#[test]
fn extract_token_query_only_is_used() {
    let token = extract_token(
        &token_query(Some("query-token")),
        &header_map_with_token(None),
    )
    .expect("a lone query token must be accepted");
    assert_eq!(token, "query-token");
}

/// Only the header carries a token: used as-is.
#[test]
fn extract_token_header_only_is_used() {
    let token = extract_token(
        &token_query(None),
        &header_map_with_token(Some("header-token")),
    )
    .expect("a lone header token must be accepted");
    assert_eq!(token, "header-token");
}

#[test]
fn extract_token_both_present_and_matching_is_accepted() {
    let token = extract_token(
        &token_query(Some("same-token")),
        &header_map_with_token(Some("same-token")),
    )
    .expect("matching query and header tokens must be accepted");
    assert_eq!(token, "same-token");
}

/// Both transports present but *disagree*: rejected with `400`, not silently
/// resolved by query-wins-header-loses precedence.
#[test]
fn extract_token_both_present_and_conflicting_is_bad_request() {
    let err = extract_token(
        &token_query(Some("query-token")),
        &header_map_with_token(Some("header-token")),
    )
    .expect_err("conflicting query/header tokens must be rejected");
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn download_rejects_conflicting_query_and_header_tokens() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backends = BackendRegistry::new(
        vec![Arc::new(InMemoryBackend::new("test")) as Arc<dyn StorageBackend>],
        "test",
    )
    .expect("build test backend registry");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());
    state.backends = backends;

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let base_claims = Claims {
        op: Op::Get,
        file_id,
        version_id,
        backend_id: "test".to_owned(),
        backend_path: format!("/{file_id}/{version_id}"),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let query_token = issuer
        .issue(base_claims.clone(), OffsetDateTime::now_utc())
        .expect("issue query token");
    let header_token = issuer
        .issue(
            Claims {
                request_id: "other-request-id".to_owned(),
                ..base_claims
            },
            OffsetDateTime::now_utc(),
        )
        .expect("issue header token");
    assert_ne!(
        query_token, header_token,
        "test premise: the two tokens must actually differ"
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={query_token}"
            ))
            .header("x-fs-token", header_token)
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sidecar_healthz_returns_200() {
    let router = build_router(test_state(), DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get("/healthz")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn sidecar_readyz_returns_200_when_backends_ready() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(LocalFsBackend::new("local-fs", dir.path()));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "local-fs",
    )
    .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], b"ready");
}

#[tokio::test]
async fn sidecar_readyz_returns_503_when_backend_root_missing() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let missing_root = dir.path().join("does-not-exist");
    // `dir` itself is dropped here too, so `missing_root`'s parent is gone as
    // well — belt-and-braces against the root ever accidentally existing.
    drop(dir);

    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(LocalFsBackend::new("local-fs", &missing_root));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "local-fs",
    )
    .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body_text = String::from_utf8(body.to_vec()).expect("valid utf8 body");
    assert!(
        body_text.contains("local-fs"),
        "body must name the failing backend id, got {body_text:?}"
    );
    assert!(
        !body_text.to_lowercase().contains("no such file")
            && !body_text.contains(missing_root.to_string_lossy().as_ref()),
        "body must not leak the underlying OS error or filesystem path, got {body_text:?}"
    );
}

#[tokio::test]
async fn sidecar_body_limit_allows_bodies_over_2mib() {
    let router = build_router(test_state(), DEFAULT_MAX_BODY_BYTES);
    let body = vec![0u8; 3 * 1024 * 1024]; // 3 MiB, over axum's 2 MiB default.
    let response = router
        .oneshot(
            Request::put(
                "/api/file-storage-data/v1/upload/\
                 00000000-0000-0000-0000-000000000000/\
                 00000000-0000-0000-0000-000000000000",
            )
            .body(Body::from(body))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn finalize_callback_times_out_within_configured_bound() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock listener");
    let addr = listener.local_addr().expect("local addr");

    // Accept connections but never write a response, so the client's
    // read times out rather than erroring immediately.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(150))
        .connect_timeout(Duration::from_millis(150))
        .build()
        .expect("client build");
    let mut state = test_state();
    state.http = http;
    state.control_base_url = format!("http://{addr}");

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        finalize_with_control_plane(
            &state,
            "dummy-token",
            "test-request-id",
            Uuid::nil(),
            Uuid::nil(),
            0,
            "deadbeef",
        ),
    )
    .await
    .expect(
        "finalize_with_control_plane must return within the test's own timeout budget \
         (production timeout regressed if this fires)",
    );

    assert!(
        outcome.is_err(),
        "finalize must fail when the control plane never responds"
    );
}

#[tokio::test]
async fn finalize_callback_retries_on_connection_refused_then_succeeds() {
    // Reserve a free port, then release it immediately: connecting to it
    // while nothing is listening reliably yields ECONNREFUSED on loopback.
    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let addr = probe.local_addr().expect("local addr");
    drop(probe);

    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let listener = TcpListener::bind(addr)
            .await
            .expect("bind mock control plane");
        if let Ok((mut stream, _)) = listener.accept().await {
            accepted_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            }
        }
    });

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .expect("client build");
    let mut state = test_state();
    state.http = http;
    state.control_base_url = format!("http://{addr}");

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        finalize_with_control_plane(
            &state,
            "dummy-token",
            "test-request-id",
            Uuid::nil(),
            Uuid::nil(),
            0,
            "deadbeef",
        ),
    )
    .await
    .expect("finalize_with_control_plane must return within the test's own timeout budget");

    assert!(
        outcome.is_ok(),
        "finalize must succeed once it retries past the connection-refused attempt"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "exactly one connection should reach the mock control plane (the retry)"
    );
}

fn test_download_state() -> (SidecarState, Issuer, Arc<InMemoryBackend>) {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(InMemoryBackend::new("test"));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "test",
    )
    .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };
    (state, issuer, backend)
}

/// Mint a signed `op = get` download token for `(file_id, version_id, backend_path)`,
/// carrying no `content_type`/`etag` claims (old-token compat).
fn download_token(issuer: &Issuer, file_id: Uuid, version_id: Uuid, backend_path: &str) -> String {
    download_token_with_meta(issuer, file_id, version_id, backend_path, "", "")
}

fn download_token_with_meta(
    issuer: &Issuer,
    file_id: Uuid,
    version_id: Uuid,
    backend_path: &str,
    content_type: &str,
    etag: &str,
) -> String {
    let claims = Claims {
        op: Op::Get,
        file_id,
        version_id,
        backend_id: "test".to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: content_type.to_owned(),
        etag: etag.to_owned(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue download token")
}

/// Which error [`FaultyReadBackend`]'s `get_stream`/`get_range_stream`
/// return instead of delegating to the real inner backend.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadFault {
    /// The race `download_range`/`download_whole` must map to `503` +
    /// `Retry-After`.
    Conflict,
    /// Any other backend error -- must still map to `500`.
    Other,
    Unavailable,
}

// `stat` succeeds but the read fails: simulates the stat/read race without real timing.
struct FaultyReadBackend {
    inner: InMemoryBackend,
    fault: ReadFault,
}

impl FaultyReadBackend {
    fn fault_error(&self) -> DomainError {
        match self.fault {
            ReadFault::Conflict => DomainError::conflict(
                "object changed size before it could be read (test fault)".to_owned(),
            ),
            ReadFault::Other => {
                DomainError::backend(self.inner.id(), "simulated I/O fault (test fault)")
            }
            ReadFault::Unavailable => DomainError::backend_unavailable(
                self.inner.id(),
                "simulated transient backend fault (test fault)",
            ),
        }
    }
}

#[async_trait]
impl StorageBackend for FaultyReadBackend {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    async fn put_stream(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError> {
        self.inner.put_stream(path, stream, max_size).await
    }

    async fn publish_exclusive(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<file_storage::infra::backend::PublishOutcome, DomainError> {
        self.inner.publish_exclusive(path, stream, max_size).await
    }

    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError> {
        self.inner.read_prefix(path, max_bytes).await
    }

    async fn size(&self, path: &str) -> Result<u64, DomainError> {
        self.inner.size(path).await
    }

    async fn delete(&self, path: &str) -> Result<(), DomainError> {
        self.inner.delete(path).await
    }

    async fn exists(&self, path: &str) -> Result<bool, DomainError> {
        self.inner.exists(path).await
    }

    async fn stat(&self, path: &str) -> Result<Option<u64>, DomainError> {
        self.inner.stat(path).await
    }

    async fn get_stream(
        &self,
        _path: &str,
        _expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        Err(self.fault_error())
    }

    async fn get_range_stream(
        &self,
        _path: &str,
        _range: file_storage_sdk::ByteRange,
        _expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        Err(self.fault_error())
    }
}

async fn test_faulty_download_state(
    path: &str,
    body: &'static [u8],
    fault: ReadFault,
) -> (SidecarState, Issuer) {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let inner = InMemoryBackend::new("test");
    write_all(&inner, path, Bytes::from_static(body)).await;
    let backend: Arc<dyn StorageBackend> = Arc::new(FaultyReadBackend { inner, fault });
    let backends =
        BackendRegistry::new(vec![backend], "test").expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };
    (state, issuer)
}

// Fails after the first chunks, so the response head is already on the wire when the fault lands.
struct MidStreamFaultBackend {
    inner: InMemoryBackend,
}

impl MidStreamFaultBackend {
    fn fault_stream() -> futures::stream::BoxStream<'static, std::io::Result<Bytes>> {
        Box::pin(futures::stream::unfold(0u8, |step| async move {
            match step {
                0 => Some((Ok(Bytes::from_static(b"first-chunk-")), 1)),
                1 => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some((Ok(Bytes::from_static(b"second-chunk-")), 2))
                }
                2 => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some((Err(std::io::Error::other("simulated mid-stream fault")), 3))
                }
                _ => None,
            }
        }))
    }
}

#[async_trait]
impl StorageBackend for MidStreamFaultBackend {
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    async fn put_stream(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError> {
        self.inner.put_stream(path, stream, max_size).await
    }

    async fn publish_exclusive(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<file_storage::infra::backend::PublishOutcome, DomainError> {
        self.inner.publish_exclusive(path, stream, max_size).await
    }

    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError> {
        self.inner.read_prefix(path, max_bytes).await
    }

    async fn size(&self, path: &str) -> Result<u64, DomainError> {
        self.inner.size(path).await
    }

    async fn delete(&self, path: &str) -> Result<(), DomainError> {
        self.inner.delete(path).await
    }

    async fn exists(&self, path: &str) -> Result<bool, DomainError> {
        self.inner.exists(path).await
    }

    async fn stat(&self, path: &str) -> Result<Option<u64>, DomainError> {
        self.inner.stat(path).await
    }

    async fn get_stream(
        &self,
        _path: &str,
        _expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        Ok(Self::fault_stream())
    }

    async fn get_range_stream(
        &self,
        _path: &str,
        _range: file_storage_sdk::ByteRange,
        _expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        Ok(Self::fault_stream())
    }
}

async fn test_mid_stream_fault_download_state(
    path: &str,
    body: &'static [u8],
) -> (SidecarState, Issuer) {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let inner = InMemoryBackend::new("test");
    write_all(&inner, path, Bytes::from_static(body)).await;
    let backend: Arc<dyn StorageBackend> = Arc::new(MidStreamFaultBackend { inner });
    let backends =
        BackendRegistry::new(vec![backend], "test").expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };
    (state, issuer)
}

#[tokio::test]
async fn download_whole_mid_stream_backend_error_aborts_response() {
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let full_content =
        b"this object is much longer than the two short chunks the fault stream ever yields";
    let (state, issuer) = test_mid_stream_fault_download_state(&path, full_content).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });

    let response = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
        ))
        .send()
        .await
        .expect("real HTTP request reaches the sidecar and gets a response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("Content-Length header present on 200")
            .to_str()
            .expect("valid header value"),
        full_content.len().to_string(),
        "the header was already committed to the full object size before the fault stream ran"
    );

    let body_result = response.bytes().await;
    assert!(
        body_result.is_err(),
        "a mid-stream backend fault after a 200 with a committed Content-Length must surface to \
         the client as a body-read error, not as a successful short read; got: {body_result:?}"
    );
}

#[tokio::test]
async fn download_range_mid_stream_backend_error_aborts_response() {
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let full_content =
        b"this object is much longer than the two short chunks the fault stream ever yields";
    let (state, issuer) = test_mid_stream_fault_download_state(&path, full_content).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });

    let response = reqwest::Client::new()
        .get(format!(
            "http://{addr}/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
        ))
        .header(header::RANGE, "bytes=0-")
        .send()
        .await
        .expect("real HTTP request reaches the sidecar and gets a response");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("Content-Length header present on 206")
            .to_str()
            .expect("valid header value"),
        full_content.len().to_string(),
        "the header was already committed to the full range span before the fault stream ran"
    );

    let body_result = response.bytes().await;
    assert!(
        body_result.is_err(),
        "a mid-stream backend fault after a 206 with a committed Content-Length must surface to \
         the client as a body-read error, not as a successful short read; got: {body_result:?}"
    );
}

#[tokio::test]
async fn download_whole_conflict_from_backend_returns_503_with_retry_after() {
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let (state, issuer) =
        test_faulty_download_state(&path, b"hello world", ReadFault::Conflict).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header present on 503")
            .to_str()
            .expect("valid header value"),
        "1"
    );
}

/// The range-request counterpart: a `Conflict` from `get_range_stream` must
/// also map to `503` + `Retry-After`.
#[tokio::test]
async fn download_range_conflict_from_backend_returns_503_with_retry_after() {
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let (state, issuer) =
        test_faulty_download_state(&path, b"hello world", ReadFault::Conflict).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header present on 503")
            .to_str()
            .expect("valid header value"),
        "1"
    );
}

#[tokio::test]
async fn download_other_backend_error_still_returns_500() {
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let (state, issuer) = test_faulty_download_state(&path, b"hello world", ReadFault::Other).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        response.headers().get(header::RETRY_AFTER).is_none(),
        "a genuine backend error must not carry a Retry-After hint"
    );
}

#[tokio::test]
async fn download_whole_backend_unavailable_returns_503_with_retry_after_5() {
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let (state, issuer) =
        test_faulty_download_state(&path, b"hello world", ReadFault::Unavailable).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header present on 503")
            .to_str()
            .expect("valid header value"),
        file_storage::domain::error::BACKEND_RETRY_AFTER_SECS.to_string()
    );
}

#[tokio::test]
async fn download_range_response_includes_content_range() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        bytes::Bytes::from_static(b"hello world"),
    )
    .await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let content_range = response
        .headers()
        .get(header::CONTENT_RANGE)
        .expect("Content-Range header present on 206")
        .to_str()
        .expect("valid header value");
    assert_eq!(content_range, "bytes 0-4/11");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], b"hello");
}

#[tokio::test]
async fn download_whole_content_length_matches_actual_body_length() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let content = b"whole-object download body used to check Content-Length";
    write_all(backend.as_ref(), &path, bytes::Bytes::from_static(content)).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let content_length: usize = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .expect("Content-Length header present on 200")
        .to_str()
        .expect("valid header value")
        .parse()
        .expect("Content-Length is a valid integer");
    assert_eq!(content_length, content.len());

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(
        body.len(),
        content_length,
        "actual body length must equal the already-sent Content-Length"
    );
    assert_eq!(&body[..], content);
}

#[tokio::test]
async fn download_missing_blob_returns_404_not_416() {
    let (state, issuer, _backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}"); // never written
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a missing blob must be 404, not 416"
    );
}

#[tokio::test]
async fn download_unsatisfiable_range_returns_416_with_content_range() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        bytes::Bytes::from_static(b"hello world"),
    )
    .await; // 11 bytes
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=100-200")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    let content_range = response
        .headers()
        .get(header::CONTENT_RANGE)
        .expect("Content-Range header present on 416")
        .to_str()
        .expect("valid header value");
    assert_eq!(content_range, "bytes */11");
    // api.md: "every download response includes Accept-Ranges" — 416 is not
    // an exception.
    let accept_ranges = response
        .headers()
        .get(header::ACCEPT_RANGES)
        .expect("Accept-Ranges header present on 416")
        .to_str()
        .expect("valid header value");
    assert_eq!(accept_ranges, "bytes");
}

#[tokio::test]
async fn download_inverted_range_is_ignored_and_returns_full_body() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        bytes::Bytes::from_static(b"hello world"),
    )
    .await; // 11 bytes
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=5-2")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], b"hello world");
}

#[tokio::test]
async fn download_sets_content_type_and_etag_from_claims() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        bytes::Bytes::from_static(b"hello world"),
    )
    .await;
    let token = download_token_with_meta(
        &issuer,
        file_id,
        version_id,
        &path,
        "image/png",
        "\"abc123\"",
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header present")
            .to_str()
            .expect("valid header value"),
        "image/png"
    );
    assert_eq!(
        response
            .headers()
            .get(header::ETAG)
            .expect("ETag header present")
            .to_str()
            .expect("valid header value"),
        "\"abc123\""
    );
}

#[tokio::test]
async fn download_range_sets_content_type_and_etag_from_claims() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        bytes::Bytes::from_static(b"hello world"),
    )
    .await;
    let token = download_token_with_meta(
        &issuer,
        file_id,
        version_id,
        &path,
        "text/plain",
        "\"deadbeef\"",
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header present")
            .to_str()
            .expect("valid header value"),
        "text/plain"
    );
    assert_eq!(
        response
            .headers()
            .get(header::ETAG)
            .expect("ETag header present")
            .to_str()
            .expect("valid header value"),
        "\"deadbeef\""
    );
}

#[tokio::test]
async fn download_without_meta_claims_falls_back_to_octet_stream_and_no_etag() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        bytes::Bytes::from_static(b"hello world"),
    )
    .await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header present")
            .to_str()
            .expect("valid header value"),
        "application/octet-stream"
    );
    assert!(
        response.headers().get(header::ETAG).is_none(),
        "old token carries no etag claim; ETag header must be absent, not empty"
    );
}

#[tokio::test]
async fn finalize_failure_does_not_leak_control_plane_url() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                let body = "internal-upstream-secret-detail";
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.ok();
            }
        }
    });

    let mut state = test_state();
    state.control_base_url = format!("http://{addr}");

    let outcome = finalize_with_control_plane(
        &state,
        "dummy-token",
        "test-request-id",
        Uuid::nil(),
        Uuid::nil(),
        0,
        "deadbeef",
    )
    .await;

    let Err(response) = outcome else {
        panic!("finalize must fail when the control plane returns an error status");
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    let body_text = String::from_utf8_lossy(&body_bytes).to_lowercase();

    assert!(
        !body_text.contains("internal-upstream-secret-detail"),
        "client-facing body must not leak the upstream error body: {body_text}"
    );
    assert!(
        !body_text.contains(&addr.to_string()),
        "client-facing body must not leak the control-plane address: {body_text}"
    );
    assert!(
        !body_text.contains("500"),
        "client-facing body must not leak the raw upstream HTTP status: {body_text}"
    );
}

#[tokio::test]
async fn finalize_callback_sends_internal_token_header() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request_text = String::from_utf8_lossy(&buf[..n]).into_owned();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .await
                .ok();
            tx.send(request_text).ok();
        }
    });

    let mut state = test_state();
    state.control_base_url = format!("http://{addr}");
    state.internal_token = SecretString::new("interim-shared-secret");

    let outcome = finalize_with_control_plane(
        &state,
        "dummy-token",
        "test-request-id",
        Uuid::nil(),
        Uuid::nil(),
        0,
        "deadbeef",
    )
    .await;
    assert!(
        outcome.is_ok(),
        "finalize must succeed against the mock 200 OK response"
    );

    let request_text = rx.await.expect("mock control plane must receive a request");
    assert!(
        request_text
            .to_lowercase()
            .contains("x-fs-internal-token: interim-shared-secret"),
        "finalize callback must carry the configured x-fs-internal-token header: {request_text}"
    );
}

#[tokio::test]
async fn finalize_callback_total_time_bounded_by_retry_budget() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            std::mem::forget(stream);
        }
    });

    let mut state = test_state();
    state.control_base_url = format!("http://{addr}");
    let budget = Duration::from_millis(300);
    state.callback_retry_budget = budget;

    let start = std::time::Instant::now();
    let outcome = finalize_with_control_plane(
        &state,
        "dummy-token",
        "test-request-id",
        Uuid::nil(),
        Uuid::nil(),
        0,
        "deadbeef",
    )
    .await;
    let elapsed = start.elapsed();

    let Err(response) = outcome else {
        panic!(
            "finalize must fail once the retry budget is exhausted against a hung control plane"
        );
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        elapsed < budget * 3,
        "total retry time must stay close to the configured budget ({budget:?}), not blow up to \
         several times it by giving every attempt its own full window; took {elapsed:?}"
    );
}

async fn call_report_part(state: &SidecarState) -> Result<(), Response> {
    report_part_with_control_plane(
        state,
        "dummy-token",
        "test-request-id",
        Uuid::nil(),
        Uuid::nil(),
        Uuid::nil(),
        1,
        "\"backend-etag\"",
        "deadbeef",
        0,
    )
    .await
}

#[tokio::test]
async fn report_part_callback_retries_bounded_on_transport_failure_then_bad_gateway() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accepted_clone.fetch_add(1, Ordering::SeqCst);
            std::mem::forget(stream);
        }
    });

    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .connect_timeout(Duration::from_millis(50))
        .build()
        .expect("client build");
    let mut state = test_state();
    state.http = http;
    state.control_base_url = format!("http://{addr}");
    state.callback_retry_budget = Duration::from_secs(5);

    let outcome = tokio::time::timeout(Duration::from_secs(3), call_report_part(&state))
        .await
        .expect("report-part must return within the test's own timeout budget");

    let Err(response) = outcome else {
        panic!("report-part must fail once every attempt times out against a hung control plane");
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        3,
        "exactly CALLBACK_MAX_ATTEMPTS connections should reach the mock control plane -- \
         bounded, not unbounded, retries on a transport failure"
    );
}

#[tokio::test]
async fn report_part_callback_4xx_is_not_retried() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            accepted_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            }
        }
    });

    let mut state = test_state();
    state.control_base_url = format!("http://{addr}");

    let outcome = tokio::time::timeout(Duration::from_secs(3), call_report_part(&state))
        .await
        .expect("report-part must return within the test's own timeout budget");

    let Err(response) = outcome else {
        panic!("report-part must fail when the control plane returns a 4xx status");
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "a real 4xx status must not be retried -- exactly one attempt"
    );
}

#[tokio::test]
async fn report_part_callback_5xx_is_not_retried() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_clone = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            accepted_clone.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                stream
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            }
        }
    });

    let mut state = test_state();
    state.control_base_url = format!("http://{addr}");

    let outcome = tokio::time::timeout(Duration::from_secs(3), call_report_part(&state))
        .await
        .expect("report-part must return within the test's own timeout budget");

    let Err(response) = outcome else {
        panic!("report-part must fail when the control plane returns a 5xx status");
    };
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "a real 5xx status must not be retried either -- exactly one attempt, same as a 4xx"
    );
}

async fn mock_http_response(raw_response: &'static [u8]) -> reqwest::Response {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _n = stream.read(&mut buf).await;
            stream.write_all(raw_response).await.ok();
        }
    });

    reqwest::Client::new()
        .get(format!("http://{addr}"))
        .send()
        .await
        .expect("mock server responds")
}

/// Won auto-bind CAS: `x-fs-bound: true` + `etag` must both be echoed onto
/// the returned [`FinalizeEcho`], with `current_etag` left `None`.
#[tokio::test]
async fn interpret_finalize_response_bound_forwards_bound_and_etag() {
    let resp = mock_http_response(
        b"HTTP/1.1 204 No Content\r\nx-fs-bound: true\r\netag: \"abc123\"\r\ncontent-length: 0\r\n\r\n",
    )
    .await;

    let echo = interpret_finalize_response(resp, Uuid::nil(), Uuid::nil())
        .await
        .expect("a success status must be interpreted as Ok");
    assert_eq!(echo.bound.as_deref(), Some("true"));
    assert_eq!(echo.etag.as_deref(), Some("\"abc123\""));
    assert_eq!(
        echo.current_etag, None,
        "a won bind carries no current_etag"
    );
}

/// Lost auto-bind CAS: `x-fs-bound: conflict` + `x-fs-current-etag` must
/// both be echoed, with `etag` left `None` (no new content was bound).
#[tokio::test]
async fn interpret_finalize_response_conflict_forwards_current_etag() {
    let resp = mock_http_response(
        b"HTTP/1.1 204 No Content\r\nx-fs-bound: conflict\r\nx-fs-current-etag: \"xyz789\"\r\n\
          content-length: 0\r\n\r\n",
    )
    .await;

    let echo = interpret_finalize_response(resp, Uuid::nil(), Uuid::nil())
        .await
        .expect("a success status must be interpreted as Ok");
    assert_eq!(echo.bound.as_deref(), Some("conflict"));
    assert_eq!(echo.current_etag.as_deref(), Some("\"xyz789\""));
    assert_eq!(echo.etag, None, "a lost CAS carries no new etag");
}

#[tokio::test]
async fn interpret_finalize_response_manual_mode_has_no_bind_headers() {
    let resp = mock_http_response(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await;

    let echo = interpret_finalize_response(resp, Uuid::nil(), Uuid::nil())
        .await
        .expect("a success status must be interpreted as Ok");
    assert_eq!(echo.bound, None);
    assert_eq!(echo.etag, None);
    assert_eq!(echo.current_etag, None);
}

#[tokio::test]
async fn interpret_finalize_response_error_status_maps_to_bad_gateway() {
    let resp =
        mock_http_response(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 5\r\n\r\noops!")
            .await;

    let err = interpret_finalize_response(resp, Uuid::nil(), Uuid::nil())
        .await
        .expect_err("a non-success status must be interpreted as Err");
    assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn interpret_finalize_response_non_utf8_header_value_is_treated_as_absent() {
    let mut raw = b"HTTP/1.1 204 No Content\r\nx-fs-bound: ".to_vec();
    raw.extend_from_slice(&[0xFF, 0xFE]); // not valid UTF-8
    raw.extend_from_slice(b"\r\ncontent-length: 0\r\n\r\n");

    let resp = mock_http_response(Box::leak(raw.into_boxed_slice())).await;

    let echo = interpret_finalize_response(resp, Uuid::nil(), Uuid::nil())
        .await
        .expect("a success status must be interpreted as Ok");
    assert_eq!(
        echo.bound, None,
        "a header value that fails to_str() must read as absent, not propagate garbage"
    );
}

#[tokio::test]
async fn upload_forwards_bind_conflict_headers_from_finalize_callback() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _n = stream.read(&mut buf).await;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nx-fs-bound: conflict\r\n\
                      x-fs-current-etag: \"current-etag-value\"\r\ncontent-length: 0\r\n\r\n",
                )
                .await
                .ok();
        }
    });

    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());
    state.control_base_url = format!("http://{addr}");

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let backend_path = format!("/{file_id}/{version_id}");
    let token = upload_token(&issuer, file_id, version_id, "test", &backend_path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::from(b"hello world".to_vec()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the upload itself succeeds even when the auto-bind CAS is lost -- only the bind, \
         not the upload, conflicted"
    );
    assert_eq!(
        response
            .headers()
            .get("x-fs-bound")
            .expect("X-FS-Bound header present")
            .to_str()
            .expect("valid header value"),
        "conflict"
    );
    assert_eq!(
        response
            .headers()
            .get("x-fs-current-etag")
            .expect("X-FS-Current-ETag header present")
            .to_str()
            .expect("valid header value"),
        "\"current-etag-value\""
    );
    assert!(
        response.headers().get(header::ETAG).is_none(),
        "a lost CAS carries no new ETag -- only X-FS-Current-ETag"
    );
}

fn upload_token(
    issuer: &Issuer,
    file_id: Uuid,
    version_id: Uuid,
    backend_id: &str,
    backend_path: &str,
) -> String {
    let claims = Claims {
        op: Op::Put,
        file_id,
        version_id,
        backend_id: backend_id.to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue upload token")
}

#[allow(clippy::too_many_arguments)]
fn multipart_part_token(
    issuer: &Issuer,
    file_id: Uuid,
    version_id: Uuid,
    backend_id: &str,
    backend_path: &str,
    upload_id: Uuid,
    part_number: u32,
    offset: u64,
    size: u64,
    backend_handle: &str,
) -> String {
    let claims = Claims {
        op: Op::MultipartPart,
        file_id,
        version_id,
        backend_id: backend_id.to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id,
            part_number,
            offset,
            size,
            backend_handle: backend_handle.to_owned(),
        },
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue multipart part token")
}

#[tokio::test]
async fn sidecar_multipart_native_backend_dispatches_to_upload_part() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(InMemoryBackend::new("mem"));
    let backends =
        BackendRegistry::new(vec![Arc::clone(&backend) as Arc<dyn StorageBackend>], "mem")
            .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let backend_path = format!("/{file_id}/{version_id}");
    let upload_id = Uuid::now_v7();

    let backend_handle = backend
        .initiate_multipart(&backend_path)
        .await
        .expect("initiate native multipart session");

    let part1 = b"first-part-bytes".to_vec();
    let part2 = b"second-part-payload".to_vec();

    let token1 = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "mem",
        &backend_path,
        upload_id,
        1,
        0,
        part1.len() as u64,
        &backend_handle,
    );
    let token2 = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "mem",
        &backend_path,
        upload_id,
        2,
        part1.len() as u64,
        part2.len() as u64,
        &backend_handle,
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);

    let resp1 = router
        .clone()
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/1?fs-token={token1}"
            ))
            .body(Body::from(part1.clone()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(resp1.status(), StatusCode::OK, "part 1 PUT must succeed");
    let resp1_body = axum::body::to_bytes(resp1.into_body(), usize::MAX)
        .await
        .expect("read part 1 response body");
    let resp1_json: serde_json::Value =
        serde_json::from_slice(&resp1_body).expect("part 1 response is JSON");
    let etag1 = resp1_json["etag"]
        .as_str()
        .expect("part 1 response has an etag")
        .to_owned();

    let resp2 = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/2?fs-token={token2}"
            ))
            .body(Body::from(part2.clone()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(resp2.status(), StatusCode::OK, "part 2 PUT must succeed");
    let resp2_body = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .expect("read part 2 response body");
    let resp2_json: serde_json::Value =
        serde_json::from_slice(&resp2_body).expect("part 2 response is JSON");
    let etag2 = resp2_json["etag"]
        .as_str()
        .expect("part 2 response has an etag")
        .to_owned();

    let hash1 = file_storage::infra::content::hash::digest_to_array(
        file_storage::infra::content::hash::sha256(&part1),
    );
    let hash2 = file_storage::infra::content::hash::digest_to_array(
        file_storage::infra::content::hash::sha256(&part2),
    );
    let (manifest, root) = backend
        .complete_multipart(
            &backend_path,
            &backend_handle,
            &[(1, 0, hash1, etag1), (2, part1.len() as u64, hash2, etag2)],
        )
        .await
        .expect("complete native multipart session - both parts must be real");

    let assembled = read_all(backend.as_ref(), &backend_path).await;
    let mut expected = part1.clone();
    expected.extend_from_slice(&part2);
    assert_eq!(
        &assembled[..],
        &expected[..],
        "assembled object must be the exact concatenation of the two parts"
    );

    let expected_manifest = file_storage::infra::content::hash_mode::Manifest::new(vec![
        file_storage::infra::content::hash_mode::ManifestEntry {
            offset: 0,
            digest: hash1,
        },
        file_storage::infra::content::hash_mode::ManifestEntry {
            offset: part1.len() as u64,
            digest: hash2,
        },
    ])
    .unwrap();
    assert_eq!(
        manifest.to_wire_string(),
        expected_manifest.to_wire_string()
    );
    assert_eq!(
        root,
        expected_manifest.root(),
        "complete_multipart's returned root must be sha256(manifest)"
    );
}

#[tokio::test]
async fn write_multipart_part_native_undersized_returns_400() {
    let backend = InMemoryBackend::new("mem");
    let backend_path = "/undersized-native";
    let backend_handle = backend
        .initiate_multipart(backend_path)
        .await
        .expect("initiate native multipart session");
    let claims = Claims {
        op: Op::MultipartPart,
        file_id: Uuid::now_v7(),
        version_id: Uuid::now_v7(),
        backend_id: "mem".to_owned(),
        backend_path: backend_path.to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id: Uuid::now_v7(),
            part_number: 1,
            offset: 0,
            size: 10,
            backend_handle,
        },
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };

    let err =
        write_multipart_part_native(&backend, &claims, 1, Body::from(b"short".to_vec()), None)
            .await
            .expect_err("undersized part must be rejected");
    assert_eq!(
        err.status(),
        StatusCode::BAD_REQUEST,
        "undersized part is a client size mismatch, not an over-limit body"
    );
}

#[tokio::test]
async fn write_multipart_part_offset_object_undersized_returns_400() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let backend = LocalFsBackend::new("local-fs", dir.path());
    let claims = Claims {
        op: Op::MultipartPart,
        file_id: Uuid::now_v7(),
        version_id: Uuid::now_v7(),
        backend_id: "local-fs".to_owned(),
        backend_path: "/undersized-offset".to_owned(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id: Uuid::now_v7(),
            part_number: 1,
            offset: 0,
            size: 10,
            backend_handle: String::new(),
        },
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };

    let err = write_multipart_part_offset_object(
        &backend,
        &claims,
        1,
        Body::from(b"short".to_vec()),
        None,
    )
    .await
    .expect_err("undersized part must be rejected");
    assert_eq!(
        err.status(),
        StatusCode::BAD_REQUEST,
        "undersized part is a client size mismatch, not an over-limit body"
    );
}

#[tokio::test]
async fn upload_replay_after_publish_is_rejected_with_409() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(InMemoryBackend::new("test"));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "test",
    )
    .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let token = upload_token(&issuer, file_id, version_id, "test", &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);

    let first = router
        .clone()
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::from(b"original-bytes".to_vec()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "first PUT to a fresh backend path must publish successfully"
    );

    let second = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::from(b"replayed-different-bytes".to_vec()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(
        second.status(),
        StatusCode::CONFLICT,
        "a replayed PUT against an already-published path must be rejected with 409, \
         never overwrite it"
    );

    // The backend must still hold the FIRST attempt's bytes, untouched.
    let stored = read_all(backend.as_ref(), &path).await;
    assert_eq!(
        &stored[..],
        b"original-bytes",
        "a replayed PUT must never overwrite the already-published content"
    );
}

#[tokio::test]
async fn sidecar_resolves_backend_by_claims_backend_id() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend_a = Arc::new(InMemoryBackend::new("local-fs"));
    let backend_b = Arc::new(InMemoryBackend::new("other"));
    let backends = BackendRegistry::new(
        vec![
            Arc::clone(&backend_a) as Arc<dyn StorageBackend>,
            Arc::clone(&backend_b) as Arc<dyn StorageBackend>,
        ],
        "local-fs",
    )
    .expect("build two-backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };

    let file_id_a = Uuid::now_v7();
    let version_id_a = Uuid::now_v7();
    let path_a = format!("/{file_id_a}/{version_id_a}");
    let token_a = upload_token(&issuer, file_id_a, version_id_a, "local-fs", &path_a);

    let file_id_b = Uuid::now_v7();
    let version_id_b = Uuid::now_v7();
    let path_b = format!("/{file_id_b}/{version_id_b}");
    let token_b = upload_token(&issuer, file_id_b, version_id_b, "other", &path_b);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);

    let response_a = router
        .clone()
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id_a}/{version_id_a}?fs-token={token_a}"
            ))
            .body(Body::from(b"bytes-for-local-fs".to_vec()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response_a.status(), StatusCode::OK);

    let response_b = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id_b}/{version_id_b}?fs-token={token_b}"
            ))
            .body(Body::from(b"bytes-for-other".to_vec()))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response_b.status(), StatusCode::OK);

    // Assert the bytes landed in the backend the TOKEN named, not always
    // the same one — via each backend's own `list_paths()`/`get()`.
    let a_paths = backend_a.list_paths().await.expect("list local-fs paths");
    assert!(
        a_paths.contains(&path_a),
        "expected {path_a} in local-fs backend, got {a_paths:?}"
    );
    assert!(
        !a_paths.contains(&path_b),
        "path_b must not land in local-fs backend, got {a_paths:?}"
    );
    let got_a = read_all(backend_a.as_ref(), &path_a).await;
    assert_eq!(&got_a[..], b"bytes-for-local-fs");

    let b_paths = backend_b.list_paths().await.expect("list other paths");
    assert!(
        b_paths.contains(&path_b),
        "expected {path_b} in other backend, got {b_paths:?}"
    );
    assert!(
        !b_paths.contains(&path_a),
        "path_a must not land in other backend, got {b_paths:?}"
    );
    let got_b = read_all(backend_b.as_ref(), &path_b).await;
    assert_eq!(&got_b[..], b"bytes-for-other");
}

/// Unset (`raw = None`) must fall back to the default without error.
#[test]
fn parse_optional_unset_uses_default() {
    let value: u64 = parse_optional("FS_SIDECAR_TEST_VAR", None, 10).expect("unset uses default");
    assert_eq!(value, 10);
}

/// A well-formed value overrides the default.
#[test]
fn parse_optional_valid_value_overrides_default() {
    let value: u64 = parse_optional("FS_SIDECAR_TEST_VAR", Some("42".to_owned()), 10)
        .expect("valid value parses");
    assert_eq!(value, 42);
}

#[test]
fn parse_optional_invalid_value_errors() {
    let err = parse_optional::<u64>("FS_SIDECAR_MAX_BODY_BYTES", Some("5GB".to_owned()), 10)
        .expect_err("malformed value must fail fast, not fall back to the default");
    let msg = err.to_string();
    assert!(
        msg.contains("FS_SIDECAR_MAX_BODY_BYTES"),
        "error should name the offending variable: {msg}"
    );
    assert!(
        msg.contains("5GB"),
        "error should include the offending value: {msg}"
    );
}

/// An empty string is also not a valid `u64` and must error, not silently
/// become the default.
#[test]
fn parse_optional_empty_string_errors() {
    parse_optional::<u64>("FS_SIDECAR_TEST_VAR", Some(String::new()), 10)
        .expect_err("empty string is not a valid u64");
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_stream_times_out_when_the_stream_goes_quiet() {
    let chunk = bytes::Bytes::from_static(b"hello");
    let stream = futures::stream::once(async move { Ok::<_, std::io::Error>(chunk) })
        .chain(futures::stream::pending::<std::io::Result<bytes::Bytes>>());
    let timed_out = Arc::new(AtomicBool::new(false));
    let mut wrapped = idle_timeout_stream(
        stream,
        Some(Duration::from_millis(50)),
        Arc::clone(&timed_out),
    );

    let first = wrapped
        .next()
        .await
        .expect("stream has a first item")
        .expect("first item is Ok");
    assert_eq!(first, bytes::Bytes::from_static(b"hello"));
    assert!(
        !timed_out.load(Ordering::SeqCst),
        "flag must not be set before the idle deadline"
    );

    let second = wrapped
        .next()
        .await
        .expect("wrapper yields the timeout error instead of hanging forever");
    let err = second.expect_err("must be an idle-timeout error, not a chunk");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        timed_out.load(Ordering::SeqCst),
        "flag must be set once the idle timeout fires"
    );

    assert!(wrapped.next().await.is_none());
}

#[tokio::test]
async fn idle_timeout_stream_disabled_passes_stream_through_unchanged() {
    let items: Vec<std::io::Result<bytes::Bytes>> = vec![
        Ok(bytes::Bytes::from_static(b"a")),
        Ok(bytes::Bytes::from_static(b"b")),
    ];
    let timed_out = Arc::new(AtomicBool::new(false));
    let mut wrapped =
        idle_timeout_stream(futures::stream::iter(items), None, Arc::clone(&timed_out));

    assert_eq!(
        wrapped.next().await.unwrap().unwrap(),
        bytes::Bytes::from_static(b"a")
    );
    assert_eq!(
        wrapped.next().await.unwrap().unwrap(),
        bytes::Bytes::from_static(b"b")
    );
    assert!(wrapped.next().await.is_none());
    assert!(!timed_out.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_stream_tolerates_pauses_under_the_limit() {
    let stream = futures::stream::unfold(0u8, |i| async move {
        if i >= 3 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        Some((Ok::<_, std::io::Error>(bytes::Bytes::from(vec![i])), i + 1))
    });
    let timed_out = Arc::new(AtomicBool::new(false));
    let mut wrapped = idle_timeout_stream(
        stream,
        Some(Duration::from_millis(200)),
        Arc::clone(&timed_out),
    );

    let mut collected = Vec::new();
    while let Some(item) = wrapped.next().await {
        collected.push(item.expect("no idle timeout expected -- pauses stay under the limit"));
    }
    assert_eq!(
        collected,
        vec![
            bytes::Bytes::from(vec![0u8]),
            bytes::Bytes::from(vec![1u8]),
            bytes::Bytes::from(vec![2u8]),
        ]
    );
    assert!(!timed_out.load(Ordering::SeqCst));
}

#[test]
fn parse_public_key_list_empty_string_is_empty_vec() {
    assert_eq!(parse_public_key_list("").unwrap(), Vec::<Vec<u8>>::new());
}

#[test]
fn parse_public_key_list_trims_and_skips_empty_elements() {
    let a = URL_SAFE_NO_PAD.encode([1, 2, 3]);
    let b = URL_SAFE_NO_PAD.encode([4, 5, 6]);
    let c = URL_SAFE_NO_PAD.encode([7, 8, 9]);
    let raw = format!("{a}, {b},,{c}");

    let parsed = parse_public_key_list(&raw).expect("valid entries parse");
    assert_eq!(parsed, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]]);
}

#[test]
fn parse_public_key_list_invalid_element_names_its_position() {
    let a = URL_SAFE_NO_PAD.encode([1, 2, 3]);
    let raw = format!("{a}, not-valid-base64!!!");

    let err = parse_public_key_list(&raw).expect_err("second entry is not valid base64url");
    let msg = err.to_string();
    assert!(
        msg.contains("entry #1"),
        "error should name the 0-based position of the bad entry: {msg}"
    );
}

/// No duplicates anywhere: nothing is dropped and order is preserved
/// (primary first, then `previous` in order).
#[test]
fn dedupe_public_keys_no_duplicates_drops_nothing() {
    let primary = vec![1, 2, 3];
    let previous = vec![vec![4, 5, 6], vec![7, 8, 9]];

    let (keys, dropped) = dedupe_public_keys(primary.clone(), previous.clone());
    assert_eq!(
        keys,
        vec![primary, previous[0].clone(), previous[1].clone()]
    );
    assert_eq!(dropped, 0);
}

#[test]
fn dedupe_public_keys_drops_primary_repeated_in_previous() {
    let primary = vec![1, 2, 3];
    let previous = vec![vec![4, 5, 6], primary.clone()];

    let (keys, dropped) = dedupe_public_keys(primary.clone(), previous);
    assert_eq!(keys, vec![primary, vec![4, 5, 6]]);
    assert_eq!(dropped, 1);
}

/// A key repeated within `previous` itself (not just against the primary)
/// is also de-duplicated -- only the first occurrence survives.
#[test]
fn dedupe_public_keys_drops_duplicate_within_previous() {
    let primary = vec![1, 2, 3];
    let b = vec![4, 5, 6];
    let previous = vec![b.clone(), b.clone()];

    let (keys, dropped) = dedupe_public_keys(primary.clone(), previous);
    assert_eq!(keys, vec![primary, b]);
    assert_eq!(dropped, 1);
}

#[test]
fn dedupe_public_keys_combined_primary_and_previous_repeats() {
    let a = vec![1, 2, 3];
    let b = vec![4, 5, 6];
    let previous = vec![b.clone(), a.clone(), b.clone()];

    let (keys, dropped) = dedupe_public_keys(a.clone(), previous);
    assert_eq!(keys, vec![a, b]);
    assert_eq!(dropped, 2);
}

fn base_config_env() -> (HashMap<&'static str, String>, Issuer) {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut env = HashMap::new();
    env.insert(
        "FS_SIDECAR_PUBLIC_KEY",
        URL_SAFE_NO_PAD.encode(issuer.public_key()),
    );
    env.insert(
        "FS_SIDECAR_INTERNAL_TOKEN",
        "test-internal-token".to_owned(),
    );
    (env, issuer)
}

fn lookup_fn(env: HashMap<&'static str, String>) -> impl Fn(&str) -> Option<String> {
    move |name| env.get(name).cloned()
}

/// `FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS=0` must disable the guard (`None`),
/// not become a real (zero-length) timeout that fires on every request.
#[test]
fn build_config_zero_idle_timeout_disables_guard() {
    let (mut env, _issuer) = base_config_env();
    env.insert("FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS", "0".to_owned());

    let config = build_config(lookup_fn(env)).expect("valid config");
    assert!(
        config.body_idle_timeout.is_none(),
        "0 must disable the idle-timeout guard entirely"
    );
}

/// A nonzero `FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS` becomes exactly that
/// duration, not silently rounded or ignored.
#[test]
fn build_config_nonzero_idle_timeout_is_some_duration() {
    let (mut env, _issuer) = base_config_env();
    env.insert("FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS", "5".to_owned());

    let config = build_config(lookup_fn(env)).expect("valid config");
    assert_eq!(config.body_idle_timeout, Some(Duration::from_secs(5)));
}

#[test]
fn build_config_malformed_length_previous_key_is_rejected() {
    let (mut env, _issuer) = base_config_env();
    env.insert(
        "FS_SIDECAR_PREVIOUS_PUBLIC_KEYS",
        URL_SAFE_NO_PAD.encode([1, 2, 3, 4, 5, 6, 7, 8]),
    );

    let err = build_config(lookup_fn(env))
        .expect_err("a previous key of the wrong length must fail startup");
    let msg = err.to_string();
    assert!(
        msg.contains("length") && msg.contains('8'),
        "error should name the length mismatch, got: {msg}"
    );
}

#[test]
fn build_config_duplicate_previous_key_is_deduped_not_rejected() {
    let (mut env, issuer) = base_config_env();
    let primary_b64 = URL_SAFE_NO_PAD.encode(issuer.public_key());
    env.insert(
        "FS_SIDECAR_PREVIOUS_PUBLIC_KEYS",
        format!("{primary_b64},{primary_b64}"),
    );

    let config =
        build_config(lookup_fn(env)).expect("duplicate keys must be deduped, not rejected");
    assert_eq!(
        config.accepted_key_count, 1,
        "the primary and its duplicate collapse to a single accepted key"
    );
    assert_eq!(config.dropped_duplicate_keys, 2);
}

#[test]
fn build_config_rotation_accepts_old_key_while_listed_then_rejects_once_removed() {
    let (new_env, _new_issuer) = base_config_env();
    let old_issuer = Issuer::generate(60).expect("issuer generation");
    let old_key_b64 = URL_SAFE_NO_PAD.encode(old_issuer.public_key());

    let token = old_issuer
        .issue(
            Claims {
                op: Op::Get,
                file_id: Uuid::now_v7(),
                version_id: Uuid::now_v7(),
                backend_id: "test".to_owned(),
                backend_path: "/irrelevant".to_owned(),
                exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
                upload: UploadConstraints::default(),
                multipart: MultipartClaims::default(),
                request_id: "test-request-id".to_owned(),
                content_type: String::new(),
                etag: String::new(),
                bind_on_finalize: false,
                content_sha256: String::new(),
            },
            OffsetDateTime::now_utc(),
        )
        .expect("issue token with old key");

    let mut env_during_rotation = new_env.clone();
    env_during_rotation.insert("FS_SIDECAR_PREVIOUS_PUBLIC_KEYS", old_key_b64);
    let config_during_rotation =
        build_config(lookup_fn(env_during_rotation)).expect("valid config");
    config_during_rotation
        .verifier
        .verify(&token, OffsetDateTime::now_utc())
        .expect("a token signed by the old key must verify while it is still listed");

    let config_after_rotation = build_config(lookup_fn(new_env)).expect("valid config");
    config_after_rotation
        .verifier
        .verify(&token, OffsetDateTime::now_utc())
        .expect_err("a token signed by the old key must be rejected once it is no longer listed");
}

fn synthetic_previous_keys_csv(n: usize) -> String {
    (0..n)
        .map(|i| {
            let b = u8::try_from(i).expect("test count stays well within u8 range");
            URL_SAFE_NO_PAD.encode([b; 32])
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Exactly `MAX_PREVIOUS_SIGNING_PUBLIC_KEYS` entries in
/// `FS_SIDECAR_PREVIOUS_PUBLIC_KEYS` must be accepted.
#[test]
fn build_config_previous_keys_at_max_is_accepted() {
    let (mut env, _issuer) = base_config_env();
    env.insert(
        "FS_SIDECAR_PREVIOUS_PUBLIC_KEYS",
        synthetic_previous_keys_csv(MAX_PREVIOUS_SIGNING_PUBLIC_KEYS),
    );

    let config = build_config(lookup_fn(env))
        .expect("exactly MAX_PREVIOUS_SIGNING_PUBLIC_KEYS entries must be accepted");
    assert_eq!(
        config.accepted_key_count,
        MAX_PREVIOUS_SIGNING_PUBLIC_KEYS + 1,
        "primary + every previous key, none of these are duplicates"
    );
}

#[test]
fn build_config_previous_keys_above_max_is_rejected() {
    let (mut env, _issuer) = base_config_env();
    env.insert(
        "FS_SIDECAR_PREVIOUS_PUBLIC_KEYS",
        synthetic_previous_keys_csv(MAX_PREVIOUS_SIGNING_PUBLIC_KEYS + 1),
    );

    let err = build_config(lookup_fn(env))
        .expect_err("one entry over MAX_PREVIOUS_SIGNING_PUBLIC_KEYS must fail startup");
    assert!(
        err.to_string().contains("MAX_PREVIOUS_SIGNING_PUBLIC_KEYS"),
        "error should name the exceeded ceiling: {err}"
    );
}

#[test]
fn build_config_requires_internal_token() {
    for value in [None, Some("")] {
        let (mut env, _issuer) = base_config_env();
        env.remove("FS_SIDECAR_INTERNAL_TOKEN");
        if let Some(v) = value {
            env.insert("FS_SIDECAR_INTERNAL_TOKEN", v.to_owned());
        }
        let err = build_config(lookup_fn(env)).expect_err("missing token must fail");
        assert!(
            err.to_string().contains("FS_SIDECAR_INTERNAL_TOKEN"),
            "error should name the variable: {err}"
        );
    }
}

#[test]
fn build_config_debug_redacts_internal_token() {
    let (mut env, _issuer) = base_config_env();
    env.insert(
        "FS_SIDECAR_INTERNAL_TOKEN",
        "super-secret-value-123".to_owned(),
    );

    let config = build_config(lookup_fn(env)).expect("valid config");
    let debug_output = format!("{config:?}");
    assert!(
        !debug_output.contains("super-secret-value-123"),
        "Debug must not print the raw internal token: {debug_output}"
    );
    assert!(
        debug_output.contains("internal_token"),
        "Debug should still name the field, just not its value: {debug_output}"
    );
}

#[tokio::test]
async fn download_head_existing_object_returns_200_with_empty_body() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        bytes::Bytes::from_static(b"hello world"),
    )
    .await; // 11 bytes
    let token = download_token_with_meta(
        &issuer,
        file_id,
        version_id,
        &path,
        "text/plain",
        "\"etag123\"",
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri(format!(
                    "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
                ))
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("Content-Length header present")
            .to_str()
            .expect("valid header value"),
        "11"
    );
    assert_eq!(
        response
            .headers()
            .get(header::ACCEPT_RANGES)
            .expect("Accept-Ranges header present")
            .to_str()
            .expect("valid header value"),
        "bytes"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("Content-Type header present")
            .to_str()
            .expect("valid header value"),
        "text/plain"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert!(
        body.is_empty(),
        "HEAD response body must be empty, got {} byte(s)",
        body.len()
    );
}

/// `HEAD` on a missing object must be `404`, same as `GET`.
#[tokio::test]
async fn download_head_missing_object_returns_404() {
    let (state, issuer, _backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}"); // never written
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri(format!(
                    "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
                ))
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn upload_exact_size_mismatch_returns_400_and_deletes_created_object() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let backend = Arc::new(InMemoryBackend::new("test"));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "test",
    )
    .expect("build test backend registry");
    let state = SidecarState {
        verifier: Arc::new(issuer.verifier()),
        backends,
        control_base_url: String::new(),
        internal_token: SecretString::new("test-internal-token"),
        http: reqwest::Client::new(),
        metrics: Arc::new(NoopMetrics),
        body_idle_timeout: None,
        callback_retry_budget: Duration::from_secs(10),
    };

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let claims = Claims {
        op: Op::Put,
        file_id,
        version_id,
        backend_id: "test".to_owned(),
        backend_path: path.clone(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        upload: UploadConstraints {
            exact_size: Some(999), // deliberately wrong: the body below is 11 bytes
            ..UploadConstraints::default()
        },
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue upload token");

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::from(b"hello world".to_vec())) // 11 bytes, not the claimed 999
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let exists = backend
        .exists(&path)
        .await
        .expect("backend exists check succeeds");
    assert!(
        !exists,
        "the object this request itself created must be cleaned up after a \
         post-validation failure, not left poisoning the immutable path"
    );
}

// Real (short) sleeps: the idle timer is tokio time, so the stall must be real wall-clock.
#[tokio::test(start_paused = true)]
async fn upload_body_idle_timeout_returns_408_and_publishes_nothing() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());
    state.body_idle_timeout = Some(Duration::from_millis(50));
    let backend = state.backends.get("test").expect("test backend registered");

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let token = upload_token(&issuer, file_id, version_id, "test", &path);

    let body_stream = futures::stream::unfold(0u8, |i| async move {
        match i {
            0 => Some((
                Ok::<_, std::io::Error>(Bytes::from_static(b"first-chunk")),
                1,
            )),
            1 => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Some((Ok(Bytes::from_static(b"never-sent")), 2))
            }
            _ => None,
        }
    });

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::from_stream(body_stream))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

    let stat = backend.stat(&path).await.expect("stat succeeds");
    assert!(
        stat.is_none(),
        "a partial upload aborted by the idle timeout must never become visible to stat"
    );
}

#[tokio::test]
async fn upload_succeeds_when_token_expires_after_verification_while_body_still_streaming() {
    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let claims = Claims {
        op: Op::Put,
        file_id,
        version_id,
        backend_id: "test".to_owned(),
        backend_path: path.clone(),
        exp: OffsetDateTime::now_utc().unix_timestamp() + 2,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, OffsetDateTime::now_utc())
        .expect("issue upload token");

    let body_stream = futures::stream::unfold(0u8, |i| async move {
        if i >= 3 {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
        Some((
            Ok::<_, std::io::Error>(Bytes::from_static(b"slow-chunk")),
            i + 1,
        ))
    });

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/upload/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::from_stream(body_stream))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "exp is checked only once, at the start of the request -- an upload already \
         admitted and mid-flight when exp passes must still complete"
    );
}

#[tokio::test]
async fn upload_multipart_part_offset_object_oversized_returns_413_and_leaves_no_part_file() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let backend = Arc::new(LocalFsBackend::new("local-fs", dir.path()));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "local-fs",
    )
    .expect("build test backend registry");
    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());
    state.backends = backends;

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let upload_id = Uuid::now_v7();
    let backend_path = format!("/{file_id}/{version_id}");
    let token = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "local-fs",
        &backend_path,
        upload_id,
        1,
        0,
        10,
        "",
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/1?fs-token={token}"
            ))
            .body(Body::from(Bytes::from_static(
                b"this part body is far longer than the declared size claim",
            )))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let part_path = format!("{backend_path}.part.1");
    let stat = backend.stat(&part_path).await.expect("stat succeeds");
    assert!(
        stat.is_none(),
        "an oversized part rejected with 413 must never leave a visible .part.N object"
    );
}

#[tokio::test]
async fn upload_multipart_part_native_oversized_returns_413() {
    let backend = Arc::new(InMemoryBackend::new("mem"));
    let backends =
        BackendRegistry::new(vec![Arc::clone(&backend) as Arc<dyn StorageBackend>], "mem")
            .expect("build test backend registry");
    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());
    state.backends = backends;

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let upload_id = Uuid::now_v7();
    let backend_path = format!("/{file_id}/{version_id}");
    let backend_handle = backend
        .initiate_multipart(&backend_path)
        .await
        .expect("initiate native multipart session");
    let token = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "mem",
        &backend_path,
        upload_id,
        1,
        0,
        10,
        &backend_handle,
    );

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/1?fs-token={token}"
            ))
            .body(Body::from(Bytes::from_static(
                b"this part body is far longer than the declared size claim",
            )))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(start_paused = true)]
async fn upload_multipart_part_native_idle_timeout_returns_408() {
    let backend = Arc::new(InMemoryBackend::new("mem"));
    let backends =
        BackendRegistry::new(vec![Arc::clone(&backend) as Arc<dyn StorageBackend>], "mem")
            .expect("build test backend registry");
    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());
    state.backends = backends;
    state.body_idle_timeout = Some(Duration::from_millis(50));

    // Mock control plane: only its accepted-connection count matters here --
    // the report-part callback must never even try to dial it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let control_plane_addr = listener.local_addr().expect("local addr");
    let report_part_calls = Arc::new(AtomicUsize::new(0));
    let report_part_calls_srv = Arc::clone(&report_part_calls);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            report_part_calls_srv.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            }
        }
    });
    state.control_base_url = format!("http://{control_plane_addr}");

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let upload_id = Uuid::now_v7();
    let backend_path = format!("/{file_id}/{version_id}");
    let backend_handle = backend
        .initiate_multipart(&backend_path)
        .await
        .expect("initiate native multipart session");
    // Declared size is larger than what the stream ever delivers -- the idle
    // timeout must fire well before an undersized-part rejection would.
    let token = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "mem",
        &backend_path,
        upload_id,
        1,
        0,
        1024,
        &backend_handle,
    );

    let body_stream = futures::stream::unfold(0u8, |i| async move {
        match i {
            0 => Some((
                Ok::<_, std::io::Error>(Bytes::from_static(b"first-chunk")),
                1,
            )),
            1 => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Some((Ok(Bytes::from_static(b"never-sent")), 2))
            }
            _ => None,
        }
    });

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/1?fs-token={token}"
            ))
            .body(Body::from_stream(body_stream))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

    assert_eq!(
        report_part_calls.load(Ordering::SeqCst),
        0,
        "the report-part callback must never be dialed for a part the idle timeout aborted"
    );

    let (_manifest, _root) = backend
        .complete_multipart(
            &backend_path,
            &backend_handle,
            &[(1, 0, [0u8; 32], "unused-etag".to_owned())],
        )
        .await
        .expect("force-completing the still-open handle must succeed");
    let assembled_len = backend
        .stat(&backend_path)
        .await
        .expect("stat succeeds")
        .expect("complete_multipart always publishes the assembled object");
    assert_eq!(
        assembled_len, 0,
        "the idle-timed-out part must never have landed in the backend's part map"
    );
}

#[tokio::test(start_paused = true)]
async fn upload_multipart_part_offset_object_idle_timeout_returns_408() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let backend = Arc::new(LocalFsBackend::new("local-fs", dir.path()));
    let backends = BackendRegistry::new(
        vec![Arc::clone(&backend) as Arc<dyn StorageBackend>],
        "local-fs",
    )
    .expect("build test backend registry");
    let issuer = Issuer::generate(60).expect("issuer generation");
    let mut state = test_state();
    state.verifier = Arc::new(issuer.verifier());
    state.backends = backends;
    state.body_idle_timeout = Some(Duration::from_millis(50));

    // Mock control plane: only its accepted-connection count matters here --
    // the report-part callback must never even try to dial it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock control plane");
    let control_plane_addr = listener.local_addr().expect("local addr");
    let report_part_calls = Arc::new(AtomicUsize::new(0));
    let report_part_calls_srv = Arc::clone(&report_part_calls);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            report_part_calls_srv.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            if stream.read(&mut buf).await.is_ok() {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            }
        }
    });
    state.control_base_url = format!("http://{control_plane_addr}");

    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let upload_id = Uuid::now_v7();
    let backend_path = format!("/{file_id}/{version_id}");
    // Declared size is larger than what the stream ever delivers -- the idle
    // timeout must fire well before an undersized-part rejection would.
    let token = multipart_part_token(
        &issuer,
        file_id,
        version_id,
        "local-fs",
        &backend_path,
        upload_id,
        1,
        0,
        1024,
        "",
    );

    let body_stream = futures::stream::unfold(0u8, |i| async move {
        match i {
            0 => Some((
                Ok::<_, std::io::Error>(Bytes::from_static(b"first-chunk")),
                1,
            )),
            1 => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Some((Ok(Bytes::from_static(b"never-sent")), 2))
            }
            _ => None,
        }
    });

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::put(format!(
                "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/1?fs-token={token}"
            ))
            .body(Body::from_stream(body_stream))
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

    let part_path = format!("{backend_path}.part.1");
    let stat = backend.stat(&part_path).await.expect("stat succeeds");
    assert!(
        stat.is_none(),
        "an idle-timed-out part must never leave a visible .part.N object"
    );

    assert_eq!(
        report_part_calls.load(Ordering::SeqCst),
        0,
        "the report-part callback must never be dialed for a part the idle timeout aborted"
    );
}

#[derive(Default)]
struct RecordingMetrics {
    egress_bytes: std::sync::Mutex<f64>,
    ingress_bytes: std::sync::Mutex<f64>,
}

impl RecordingMetrics {
    fn egress_total(&self) -> f64 {
        *self.egress_bytes.lock().expect("lock poisoned")
    }
}

impl file_storage::domain::ports::FileStorageMetricsPort for RecordingMetrics {
    fn record_operation(&self, _op: &str, _result: &str) {}
    fn record_backend_error(&self, _backend_id: &str, _op: &str) {}
    fn record_quota_denied(&self, _op: &str) {}
    fn record_sweep_result(
        &self,
        _abandoned_pending_deleted: u64,
        _abandoned_files_deleted: u64,
        _expired_multipart_aborted: u64,
        _retention_expired_deleted: u64,
        _idempotency_keys_deleted: u64,
    ) {
    }
    fn record_ingress_bytes(&self, bytes: f64) {
        *self.ingress_bytes.lock().expect("lock poisoned") += bytes;
    }
    fn record_egress_bytes(&self, bytes: f64) {
        *self.egress_bytes.lock().expect("lock poisoned") += bytes;
    }
    fn record_request(&self, _route: &str, _method: &str, _status: u16, _latency_ms: f64) {}
}

fn test_download_state_with_metrics(
    metrics: Arc<dyn file_storage::domain::ports::FileStorageMetricsPort>,
) -> (SidecarState, Issuer, Arc<InMemoryBackend>) {
    let (mut state, issuer, backend) = test_download_state();
    state.metrics = metrics;
    (state, issuer, backend)
}

#[tokio::test]
async fn download_range_content_length_matches_actual_body_length() {
    let (state, issuer, backend) = test_download_state();
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let content = b"range download body used to check Content-Length exactly";
    write_all(backend.as_ref(), &path, Bytes::from_static(content)).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=2-9")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let content_length: usize = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .expect("Content-Length header present on 206")
        .to_str()
        .expect("valid header value")
        .parse()
        .expect("Content-Length is a valid integer");
    assert_eq!(content_length, 8, "bytes=2-9 spans exactly 8 bytes");

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(
        body.len(),
        content_length,
        "actual body length must equal the already-sent Content-Length"
    );
    assert_eq!(&body[..], &content[2..10]);
}

#[tokio::test]
async fn download_whole_get_records_egress_bytes_equal_to_body_length() {
    let metrics = Arc::new(RecordingMetrics::default());
    let (state, issuer, backend) = test_download_state_with_metrics(metrics.clone());
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let content = b"whole-object body used to check the egress metric";
    write_all(backend.as_ref(), &path, Bytes::from_static(content)).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], content);

    #[allow(
        clippy::float_cmp,
        clippy::float_cmp_const,
        clippy::cast_precision_loss
    )]
    {
        assert_eq!(
            metrics.egress_total(),
            content.len() as f64,
            "egress must equal exactly the bytes actually streamed"
        );
    }
}

#[tokio::test]
async fn download_range_get_records_egress_bytes_equal_to_range_length() {
    let metrics = Arc::new(RecordingMetrics::default());
    let (state, issuer, backend) = test_download_state_with_metrics(metrics.clone());
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    let content = b"range body used to check the egress metric records only the span";
    write_all(backend.as_ref(), &path, Bytes::from_static(content)).await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::get(format!(
                "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
            ))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .expect("valid request"),
        )
        .await
        .expect("router call succeeds");
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(body.len(), 5, "bytes=0-4 spans exactly 5 bytes");

    #[allow(clippy::float_cmp, clippy::float_cmp_const)]
    {
        assert_eq!(
            metrics.egress_total(),
            5.0,
            "egress must equal exactly the range span actually streamed, not the whole object"
        );
    }
}

#[tokio::test]
async fn download_head_records_zero_egress_bytes() {
    let metrics = Arc::new(RecordingMetrics::default());
    let (state, issuer, backend) = test_download_state_with_metrics(metrics.clone());
    let file_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let path = format!("/{file_id}/{version_id}");
    write_all(
        backend.as_ref(),
        &path,
        Bytes::from_static(b"content that HEAD must never account as egress"),
    )
    .await;
    let token = download_token(&issuer, file_id, version_id, &path);

    let router = build_router(state, DEFAULT_MAX_BODY_BYTES);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri(format!(
                    "/api/file-storage-data/v1/download/{file_id}/{version_id}?fs-token={token}"
                ))
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("router call succeeds");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().contains_key(header::CONTENT_LENGTH),
        "HEAD must still report Content-Length even though it records no egress"
    );

    #[allow(clippy::float_cmp, clippy::float_cmp_const)]
    {
        assert_eq!(
            metrics.egress_total(),
            0.0,
            "HEAD has no body to stream, so egress must stay at 0"
        );
    }
}
