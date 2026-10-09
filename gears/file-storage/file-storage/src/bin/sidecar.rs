//! `FileStorage` data-plane sidecar: the only component that moves user bytes.
//!
//! It verifies the control-minted Ed25519 signed-URL token, enforces the token's upload
//! constraints (size / hash) and streams content to/from a storage backend. Clients never
//! address a backend directly.
//!
//! Configuration (env):
//!   - `FS_SIDECAR_ADDR` - bind address (default `0.0.0.0:8087`)
//!   - `FS_SIDECAR_PUBLIC_KEY` - base64url Ed25519 **primary** public key (from control)
//!   - `FS_SIDECAR_PREVIOUS_PUBLIC_KEYS` - optional comma-separated base64url public keys tried
//!     after the primary, so a `signing_key_seed` rotation neither causes an outage nor
//!     invalidates issued URLs (no `kid` claim: the set is small, so each key is tried in
//!     turn; see `docs/operations.md`, "Rotation")
//!   - `FS_SIDECAR_BACKEND_ROOT` - local-fs backend root (default `./.file-storage-data`)
//!   - `FS_SIDECAR_CONTROL_URL` - control-plane base URL for the finalize/report-part
//!     callbacks (default `http://localhost:8080`); empty disables them (dev/test only)
//!   - `FS_SIDECAR_MAX_BODY_BYTES` - transport-level body ceiling replacing axum's 2 MiB
//!     default (default 5 GiB); the real limit is the token's `upload.max_size`/`exact_size`
//!   - `FS_SIDECAR_FINALIZE_TIMEOUT_SECS` - total wall-clock budget (default `10`) of a
//!     control-plane callback including all retries and delays
//!   - `FS_SIDECAR_FINALIZE_CONNECT_TIMEOUT_SECS` - connect timeout of those callbacks
//!     (default `5`); together they bound how long a hung control plane can hold an upload open
//!   - `FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS` - max pause between two request-body chunks (and
//!     before the first) on `upload`/`upload_multipart_part` (default `60`; `0` disables).
//!     It bounds only the pause, never the total duration. The token's `exp` is checked once
//!     before any body byte is read and `FS_SIDECAR_MAX_BODY_BYTES` bounds bytes not time, so
//!     a stalled client could otherwise hold the request open forever (CWE-400); it gets
//!     `408 Request Timeout` (see `idle_timeout_stream`).
//!   - `FS_SIDECAR_INTERNAL_TOKEN` - **required**: shared secret sent as
//!     `x-fs-internal-token` on the finalize and report-part callbacks. The sidecar refuses
//!     to start without it. Must equal the control plane's
//!     `FileStorageConfig::finalize_internal_secret`; the control plane trusts the size and
//!     SHA-256 reported on these callbacks (see ADR-0003).
//!   - `FS_SIDECAR_S3_BACKENDS` - optional JSON array of
//!     `file_storage::config::S3BackendConfig` entries (credentials included; prefer sourcing
//!     it from a secrets manager or mounted file). Entries are validated at startup and
//!     registered next to the always-present `local-fs` backend; each request resolves its
//!     backend from the verified token's `claims.backend_id`.
//!
//! `upload_multipart_part` on a `multipart_native` backend (e.g. `S3Backend`) streams the part
//! straight to the backend (`write_multipart_part_native`) without buffering a whole part.
//!
//! ## Upload lifecycle
//!
//! After a successful single-part `PUT` the sidecar:
//! 1. Publishes the blob **create-exclusive** (`StorageBackend::publish_exclusive`): a second
//!    `PUT` to an already-published path never overwrites it. This closes a token-replay
//!    integrity gap: the signature does not cover the body and stays valid until `exp`.
//! 2. Posts a finalize callback to
//!    `POST {control_url}/api/file-storage/v1/files/{file_id}/versions/{version_id}/finalize`
//!    with the signed token and the measured size and SHA-256.
//! 3. Returns `200 OK` only if the callback succeeds; otherwise `502 Bad Gateway` and the
//!    client retries (safe: step 1 never overwrites; see `upload` for the retry/replay table).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, MatchedPath, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures::StreamExt;
use serde::Deserialize;
use time::OffsetDateTime;
use toolkit_utils::SecretString;
use uuid::Uuid;

use file_storage::domain::error::{BACKEND_RETRY_AFTER_SECS, DomainError};
use file_storage::domain::ports::FileStorageMetricsPort;
use file_storage::infra::backend::{BackendRegistry, LocalFsBackend, S3Backend, StorageBackend};
use file_storage::infra::content::stream_verify::verify_whole_object_download_stream;
use file_storage::infra::content::{hash, range};
use file_storage::infra::metrics::FileStorageMetricsMeter;
use file_storage::infra::signed_url::{
    Claims, MAX_PREVIOUS_SIGNING_PUBLIC_KEYS, Op, Verifier, dedupe_public_keys,
    parse_public_key_list,
};

/// Id of the local-fs backend, also the `BackendRegistry` default id (required to construct it;
/// dispatch never consults it since every request names its backend via `claims.backend_id`).
const LOCAL_FS_ID: &str = "local-fs";

#[derive(Clone)]
/// Shared per-process state of the sidecar HTTP handlers: token verifier, backends, control-plane callback settings and metrics.
struct SidecarState {
    verifier: Arc<Verifier>,
    /// Backends keyed by id; resolved per request from the verified token's `claims.backend_id`.
    backends: BackendRegistry,
    /// Control-plane base URL, e.g. `http://localhost:8080`; empty disables the finalize
    /// callback (dev mode).
    control_base_url: String,
    /// Gear-local shared secret (`FS_SIDECAR_INTERNAL_TOKEN`) sent as
    /// `x-fs-internal-token` on the finalize/report-part callbacks.
    /// Mandatory: startup fails when it is unset/empty.
    internal_token: SecretString,
    http: reqwest::Client,
    /// Request/byte/latency metrics for the sidecar's own routes (never proxied by the
    /// api-gateway, so it owns its `OTel` `Meter`).
    metrics: Arc<dyn FileStorageMetricsPort>,
    /// Max pause between body chunks (and before the first) on the upload routes, from
    /// `FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS`; `None` disables. See [`idle_timeout_stream`].
    body_idle_timeout: Option<Duration>,
    /// Overall wall-clock budget of a finalize/report-part callback **including all retries
    /// and delays** (`FS_SIDECAR_FINALIZE_TIMEOUT_SECS`); `post_with_retry` wraps its whole
    /// loop in one `tokio::time::timeout` of this size.
    callback_retry_budget: Duration,
}

#[derive(Debug, Deserialize)]
/// Query string of the data-plane routes; carries the signed token when it is not sent in a header.
struct TokenQuery {
    #[serde(rename = "fs-token")]
    fs_token: Option<SecretString>,
}

/// Default for `FS_SIDECAR_MAX_BODY_BYTES` (5 GiB), above any policy-permitted single-part
/// upload; only a transport ceiling, the real limit is the token's `upload.max_size`.
const DEFAULT_MAX_BODY_BYTES: usize = 5_368_709_120;

/// Parse an optional env value as `T`, using `default` when unset but failing fast when a
/// value was supplied and does not parse (a typo like `5GB` must not silently fall back).
fn parse_optional<T>(name: &str, raw: Option<String>, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match raw {
        Some(raw) => raw
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("invalid {name}={raw:?}: {e}")),
        None => Ok(default),
    }
}

/// Parsed, validated sidecar configuration: the deterministic part of startup (env parsing,
/// key dedup + `Verifier`, zero-value checks) with no I/O beyond the `lookup` closure.
/// Built by [`build_config`]. `Debug` is manual: `Verifier` has no `Debug` and `internal_token`
/// is a secret.
struct SidecarConfig {
    addr: SocketAddr,
    root: String,
    /// Primary key plus any still-valid previous keys ([`dedupe_public_keys`]).
    verifier: Arc<Verifier>,
    /// Number of keys `verifier` accepts, for the startup log.
    accepted_key_count: usize,
    /// Previous keys dropped as duplicates, for the startup log.
    dropped_duplicate_keys: usize,
    control_base_url: String,
    max_body_bytes: usize,
    finalize_timeout_secs: u64,
    finalize_connect_timeout_secs: u64,
    body_idle_timeout: Option<Duration>,
    internal_token: SecretString,
}

impl std::fmt::Debug for SidecarConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarConfig")
            .field("addr", &self.addr)
            .field("root", &self.root)
            .field("verifier", &"Verifier { .. }")
            .field("accepted_key_count", &self.accepted_key_count)
            .field("dropped_duplicate_keys", &self.dropped_duplicate_keys)
            .field("control_base_url", &self.control_base_url)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("finalize_timeout_secs", &self.finalize_timeout_secs)
            .field(
                "finalize_connect_timeout_secs",
                &self.finalize_connect_timeout_secs,
            )
            .field("body_idle_timeout", &self.body_idle_timeout)
            // Print only whether a secret is configured.
            .field("internal_token", &"<redacted>")
            .finish()
    }
}

/// Assemble [`SidecarConfig`] from env lookups made through `lookup` (not `std::env::var`),
/// so it is unit-testable. Fails fast on a missing `FS_SIDECAR_PUBLIC_KEY`, a malformed key
/// (bad base64 or wrong length) or any other unparseable value.
fn build_config(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<SidecarConfig> {
    let addr: SocketAddr = lookup("FS_SIDECAR_ADDR")
        .unwrap_or_else(|| "0.0.0.0:8087".to_owned())
        .parse()?;
    let root =
        lookup("FS_SIDECAR_BACKEND_ROOT").unwrap_or_else(|| "./.file-storage-data".to_owned());
    let public_key_b64 = lookup("FS_SIDECAR_PUBLIC_KEY")
        .ok_or_else(|| anyhow::anyhow!("FS_SIDECAR_PUBLIC_KEY is required"))?;
    let public_key = URL_SAFE_NO_PAD
        .decode(public_key_b64.trim())
        .map_err(|e| anyhow::anyhow!("invalid FS_SIDECAR_PUBLIC_KEY: {e}"))?;

    // Keys retained from an earlier `signing_key_seed`, tried after the primary during rotation.
    let previous_public_keys: Vec<Vec<u8>> = match lookup("FS_SIDECAR_PREVIOUS_PUBLIC_KEYS") {
        Some(raw) if !raw.trim().is_empty() => parse_public_key_list(&raw)
            .map_err(|e| anyhow::anyhow!("invalid FS_SIDECAR_PREVIOUS_PUBLIC_KEYS: {e}"))?,
        _ => Vec::new(),
    };
    // Capped before dedup (as `FileStorageConfig::validate` does): `Verifier` tries every key
    // per request, so an unbounded list is an unbounded per-request cost.
    if previous_public_keys.len() > MAX_PREVIOUS_SIGNING_PUBLIC_KEYS {
        anyhow::bail!(
            "invalid FS_SIDECAR_PREVIOUS_PUBLIC_KEYS: {} entries, exceeding \
             MAX_PREVIOUS_SIGNING_PUBLIC_KEYS ({})",
            previous_public_keys.len(),
            MAX_PREVIOUS_SIGNING_PUBLIC_KEYS
        );
    }
    // Primary leads the set (`Verifier::verify` tries keys in order); duplicates are dropped
    // rather than rejected so operators need not scrub the list when a rotation completes.
    let (verifier_keys, dropped_duplicate_keys) =
        dedupe_public_keys(public_key, previous_public_keys);
    let accepted_key_count = verifier_keys.len();
    let verifier = Arc::new(Verifier::from_public_keys(verifier_keys).map_err(|e| {
        anyhow::anyhow!("invalid FS_SIDECAR_PUBLIC_KEY/FS_SIDECAR_PREVIOUS_PUBLIC_KEYS: {e}")
    })?);

    // Empty `FS_SIDECAR_CONTROL_URL` disables the callback (local dev / standalone tests).
    let control_base_url =
        lookup("FS_SIDECAR_CONTROL_URL").unwrap_or_else(|| "http://localhost:8080".to_owned());

    // Replaces axum's 2 MiB body floor; the token's size claims remain the real limit.
    let max_body_bytes: usize = parse_optional(
        "FS_SIDECAR_MAX_BODY_BYTES",
        lookup("FS_SIDECAR_MAX_BODY_BYTES"),
        DEFAULT_MAX_BODY_BYTES,
    )?;

    // Bound the control-plane callbacks so a hung control plane cannot block uploads forever;
    // `finalize_timeout_secs` is the overall budget of the retry loop, not per attempt.
    let finalize_timeout_secs: u64 = parse_optional(
        "FS_SIDECAR_FINALIZE_TIMEOUT_SECS",
        lookup("FS_SIDECAR_FINALIZE_TIMEOUT_SECS"),
        10,
    )?;
    let finalize_connect_timeout_secs: u64 = parse_optional(
        "FS_SIDECAR_FINALIZE_CONNECT_TIMEOUT_SECS",
        lookup("FS_SIDECAR_FINALIZE_CONNECT_TIMEOUT_SECS"),
        5,
    )?;

    // `0` disables the idle guard (`None`); it is a per-chunk bound, never a total deadline.
    let body_idle_timeout_secs: u64 = parse_optional(
        "FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS",
        lookup("FS_SIDECAR_BODY_IDLE_TIMEOUT_SECS"),
        60,
    )?;
    let body_idle_timeout = if body_idle_timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(body_idle_timeout_secs))
    };

    // Mandatory (sent as `x-fs-internal-token`): fail fast so every finalize is not rejected.
    let internal_token = lookup("FS_SIDECAR_INTERNAL_TOKEN")
        .filter(|s| !s.is_empty())
        .map(SecretString::new)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "FS_SIDECAR_INTERNAL_TOKEN is required (must equal the control plane's \
                 finalize_internal_secret)"
            )
        })?;

    Ok(SidecarConfig {
        addr,
        root,
        verifier,
        accepted_key_count,
        dropped_duplicate_keys,
        control_base_url,
        max_body_bytes,
        finalize_timeout_secs,
        finalize_connect_timeout_secs,
        body_idle_timeout,
        internal_token,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = build_config(|name| std::env::var(name).ok())?;

    if config.dropped_duplicate_keys > 0 {
        // Log only the key count, never key material.
        tracing::warn!(
            dropped_duplicates = config.dropped_duplicate_keys,
            "FS_SIDECAR_PREVIOUS_PUBLIC_KEYS contains keys already in the accepted set; \
             dropped \u{2014} a completed rotation usually means the list should be cleared"
        );
    }
    tracing::info!(
        accepted_key_count = config.accepted_key_count,
        "sidecar signed-URL verifier configured"
    );

    if config.control_base_url.is_empty() {
        tracing::warn!(
            "FS_SIDECAR_CONTROL_URL is empty \u{2014} finalize callback disabled. \
             Uploaded versions will remain in 'pending' status."
        );
    } else {
        tracing::info!(
            control_base_url = %config.control_base_url,
            "sidecar finalize callback enabled"
        );
    }

    // Backstop only: `post_with_retry` bounds the whole retry loop with the same budget, which
    // fires first once an attempt has consumed part of it; this covers direct requests.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.finalize_timeout_secs))
        .connect_timeout(Duration::from_secs(config.finalize_connect_timeout_secs))
        .build()
        .map_err(|e| anyhow::anyhow!("reqwest client: {e}"))?;

    // `S3BackendConfig` entries are constructed eagerly so a bad endpoint or missing credentials
    // fails startup; they join the `BackendRegistry` next to `local-fs`.
    let s3_backends: Vec<Arc<dyn StorageBackend>> = match std::env::var("FS_SIDECAR_S3_BACKENDS") {
        Ok(json) if !json.trim().is_empty() => {
            let entries: Vec<file_storage::config::S3BackendConfig> =
                serde_json::from_str(&json)
                    .map_err(|e| anyhow::anyhow!("invalid FS_SIDECAR_S3_BACKENDS: {e}"))?;
            entries
                .iter()
                .map(|entry| {
                    S3Backend::from_config(entry)
                        .map(|backend| Arc::new(backend) as Arc<dyn StorageBackend>)
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("FS_SIDECAR_S3_BACKENDS: {e}"))?
        }
        _ => Vec::new(),
    };
    if !s3_backends.is_empty() {
        tracing::info!(
            count = s3_backends.len(),
            "sidecar parsed FS_SIDECAR_S3_BACKENDS \u{2014} registered for claims.backend_id dispatch"
        );
    }

    let mut backend_list: Vec<Arc<dyn StorageBackend>> =
        vec![Arc::new(LocalFsBackend::new(LOCAL_FS_ID, config.root))];
    backend_list.extend(s3_backends);
    let backends = BackendRegistry::new(backend_list, LOCAL_FS_ID)
        .map_err(|e| anyhow::anyhow!("failed to build sidecar backend registry: {e}"))?;

    // The sidecar is its own process, so it owns its `Meter` (as `gear.rs` does for control).
    let metrics_scope =
        opentelemetry::InstrumentationScope::builder("file-storage-sidecar".to_owned()).build();
    let metrics: Arc<dyn FileStorageMetricsPort> = Arc::new(FileStorageMetricsMeter::new(
        &opentelemetry::global::meter_with_scope(metrics_scope),
        "file_storage",
    ));

    let state = SidecarState {
        verifier: config.verifier,
        backends,
        control_base_url: config.control_base_url,
        internal_token: config.internal_token,
        http,
        metrics,
        body_idle_timeout: config.body_idle_timeout,
        callback_retry_budget: Duration::from_secs(config.finalize_timeout_secs),
    };

    let app = build_router(state, config.max_body_bytes);

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(addr = %config.addr, "file-storage sidecar listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the sidecar `Router` without binding a socket (so tests can drive it via `oneshot`).
/// `max_body_bytes` replaces axum's 2 MiB body floor; the token's size claims stay the real
/// limit.
fn build_router(state: SidecarState, max_body_bytes: usize) -> Router {
    Router::new()
        .route(
            "/api/file-storage-data/v1/upload/{file_id}/{version_id}",
            put(upload),
        )
        // Explicit `.head(..)`: axum's GET-derived HEAD would stream the whole object.
        .route(
            "/api/file-storage-data/v1/download/{file_id}/{version_id}",
            get(download).head(download_head),
        )
        // Per-part upload: the control plane mints a `multipart_part` token with an exact `size`.
        .route(
            "/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/{part_number}",
            put(upload_multipart_part),
        )
        // Liveness: always 200, no dependency check (see `readyz`).
        .route("/healthz", get(healthz))
        // Readiness: reflects real backend availability.
        .route("/readyz", get(readyz))
        // Route-level latency/status; wraps every route above.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            record_request_metrics,
        ))
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body_bytes))
}

/// Records one `file_storage_sidecar_request_duration_ms` observation per request (route from
/// [`MatchedPath`] or `"unmatched"` to bound cardinality, method, status, latency).
async fn record_request_metrics(
    State(state): State<SidecarState>,
    matched_path: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_owned();
    let route = matched_path
        .as_ref()
        .map_or("unmatched", MatchedPath::as_str)
        .to_owned();
    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    state
        .metrics
        .record_request(&route, &method, response.status().as_u16(), elapsed_ms);
    response
}

/// Liveness probe: `200 OK` once serving; deliberately no backend check (see `readyz`).
async fn healthz() -> &'static str {
    "ok"
}

/// Time budget for one backend's readiness probe, so a hung backend (e.g. stalled S3) cannot
/// delay `/readyz` past a typical k8s probe period (~10s).
const READYZ_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Readiness probe: polls every backend's [`StorageBackend::is_ready`] concurrently, each
/// bounded by `READYZ_PROBE_TIMEOUT`. `200 "ready"` only if all answer `Ok`; otherwise `503`
/// naming just the failing backend ids (never the error text, so no backend internals leak).
async fn readyz(State(state): State<SidecarState>) -> Response {
    let checks = state.backends.iter().map(|(id, backend)| {
        let id = id.to_owned();
        let backend = Arc::clone(backend);
        async move {
            match tokio::time::timeout(READYZ_PROBE_TIMEOUT, backend.is_ready()).await {
                Ok(Ok(())) => None,
                Ok(Err(_)) | Err(_) => Some(id),
            }
        }
    });

    let failing: Vec<String> = futures::future::join_all(checks)
        .await
        .into_iter()
        .flatten()
        .collect();

    if failing.is_empty() {
        (StatusCode::OK, "ready").into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("not ready: {}", failing.join(", ")),
        )
            .into_response()
    }
}

/// Extract the token from the `fs-token` query param and/or the `X-FS-Token` header.
///
/// Either alone is accepted; if both are present they must agree, otherwise the request is
/// rejected with `400` before the verifier sees either. `Err` carries the ready response:
/// `400` for conflicting tokens, `401` for none.
#[allow(clippy::result_large_err)]
fn extract_token(q: &TokenQuery, headers: &HeaderMap) -> Result<String, Response> {
    let query_token = q.fs_token.as_ref().map(|s| s.expose().to_owned());
    let header_token = headers
        .get("x-fs-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    match (query_token, header_token) {
        (Some(q), Some(h)) if q == h => Ok(q),
        (Some(_), Some(_)) => Err((
            StatusCode::BAD_REQUEST,
            "conflicting fs-token in query and header",
        )
            .into_response()),
        (Some(t), None) | (None, Some(t)) => Ok(t),
        (None, None) => Err((StatusCode::UNAUTHORIZED, "missing fs-token").into_response()),
    }
}

/// Response text for the upload routes when [`idle_timeout_stream`] fires.
const BODY_IDLE_TIMEOUT_MESSAGE: &str = "request body idle timeout";

/// Wrap a body stream so a pause longer than `idle` between chunks (or before the first)
/// ends it with an `Err(ErrorKind::TimedOut)` and sets `timed_out` (CWE-400: `exp` is checked
/// only once up front and `FS_SIDECAR_MAX_BODY_BYTES` bounds bytes, not time).
///
/// This is a per-chunk idle bound, never a total deadline. `idle == None` returns the stream
/// unwrapped and never touches `timed_out`.
///
/// After firing, the stream yields that one `Err` and ends; callers use `timed_out` to answer
/// `408 Request Timeout` instead of the generic error. Backends already clean up partial
/// objects on any stream error, so no special-casing is needed.
fn idle_timeout_stream<S>(
    stream: S,
    idle: Option<Duration>,
    timed_out: Arc<AtomicBool>,
) -> futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>>
where
    S: futures::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static,
{
    let Some(idle) = idle else {
        return Box::pin(stream);
    };
    Box::pin(futures::stream::unfold(
        (Box::pin(stream), false),
        move |(mut stream, done)| {
            let timed_out = Arc::clone(&timed_out);
            async move {
                if done {
                    return None;
                }
                match tokio::time::timeout(idle, stream.next()).await {
                    Ok(Some(item)) => Some((item, (stream, false))),
                    Ok(None) => None,
                    Err(_elapsed) => {
                        timed_out.store(true, Ordering::SeqCst);
                        Some((
                            Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                BODY_IDLE_TIMEOUT_MESSAGE,
                            )),
                            (stream, true),
                        ))
                    }
                }
            }
        },
    ))
}

/// If `timed_out` was set by [`idle_timeout_stream`], logs one `warn!` naming `context`
/// (and `bytes_received` when cheaply known) and returns the `408 Request Timeout` response;
/// `None` otherwise so the caller continues its own error handling. Shared by [`upload`],
/// `write_multipart_part_native` and `write_multipart_part_offset_object`.
fn idle_timeout_response(
    timed_out: &AtomicBool,
    context: &str,
    bytes_received: Option<u64>,
) -> Option<Response> {
    if !timed_out.load(Ordering::SeqCst) {
        return None;
    }
    if let Some(bytes_received) = bytes_received {
        tracing::warn!(
            context,
            bytes_received,
            "request body idle timeout \u{2014} answering 408"
        );
    } else {
        tracing::warn!(context, "request body idle timeout \u{2014} answering 408");
    }
    Some((StatusCode::REQUEST_TIMEOUT, BODY_IDLE_TIMEOUT_MESSAGE).into_response())
}

/// `PUT` upload: verify token (op=PUT), stream bytes straight to the backend.
///
/// The body is never buffered whole: it goes to `StorageBackend::publish_exclusive`, which
/// aborts mid-stream once `claims.upload.max_size` is exceeded. `exact_size`/`expected_hash`
/// are only final after the stream is drained, so they are checked after it returns.
///
/// `publish_exclusive` reports `created: false` instead of overwriting an existing blob at
/// `claims.backend_path`. Then:
/// * finalize succeeds (an earlier publish landed but finalize never ran, and the bytes
///   match) -> `200`, a benign retry converged;
/// * anything else (version already `available` = genuine replay, finalize transport failure,
///   or no control plane) -> `409 Conflict`: this `PUT` took no effect, and a `502` would
///   wrongly suggest the bytes might have been stored.
async fn upload(
    State(state): State<SidecarState>,
    Path((file_id, version_id)): Path<(Uuid, Uuid)>,
    Query(q): Query<TokenQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let token = match extract_token(&q, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let claims = match state.verifier.verify(&token, OffsetDateTime::now_utc()) {
        Ok(c) => c,
        Err(e) => return (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    };
    if claims.op != Op::Put || claims.file_id != file_id || claims.version_id != version_id {
        return (
            StatusCode::FORBIDDEN,
            "token does not authorize this operation",
        )
            .into_response();
    }

    let backend = match state.backends.get(&claims.backend_id) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("unknown backend '{}': {e}", claims.backend_id),
            )
                .into_response();
        }
    };

    let timed_out = Arc::new(AtomicBool::new(false));
    let byte_stream = idle_timeout_stream(
        body.into_data_stream()
            .map(|r| r.map_err(std::io::Error::other)),
        state.body_idle_timeout,
        Arc::clone(&timed_out),
    );
    let outcome = match backend
        .publish_exclusive(&claims.backend_path, byte_stream, claims.upload.max_size)
        .await
    {
        Ok(v) => v,
        // The only `Validation` error is the mid-stream `max_size` guard.
        Err(DomainError::Validation { .. }) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "exceeds max_size").into_response();
        }
        Err(e) => {
            if let Some(resp) = idle_timeout_response(&timed_out, &claims.backend_path, None) {
                return resp;
            }
            return backend_error_response(&e, "publish_exclusive");
        }
    };
    let (bytes_written, digest, created) = (outcome.bytes_written, outcome.digest, outcome.created);

    // Remaining constraints are checkable now that the length/hash are final.
    if claims
        .upload
        .exact_size
        .is_some_and(|exact| bytes_written != exact)
    {
        return reject_upload_bad_content(
            backend.as_ref(),
            &claims,
            created,
            "size does not match exact_size",
        )
        .await;
    }
    if let Some(expected) = &claims.upload.expected_hash {
        let got = format!("{}:{}", hash::ALGORITHM, hex::encode(digest));
        if !expected.eq_ignore_ascii_case(&got) {
            return reject_upload_bad_content(
                backend.as_ref(),
                &claims,
                created,
                "content hash mismatch",
            )
            .await;
        }
    }

    let size = i64::try_from(bytes_written).unwrap_or(i64::MAX);
    let hash_hex = hex::encode(digest);

    // The sidecar is the only component that sees content bytes: record ingress here.
    #[allow(clippy::cast_precision_loss)]
    state.metrics.record_ingress_bytes(bytes_written as f64);

    // Finalize callback: tell the control plane the bytes landed so it can mark the version
    // `available`. `claims.request_id` is echoed as `x-request-id` to correlate both planes' logs.
    let finalize_result = finalize_with_control_plane(
        &state,
        &token,
        &claims.request_id,
        file_id,
        version_id,
        size,
        &hash_hex,
    )
    .await;

    if !created {
        // Immutability guard: `publish_exclusive` did not write (an earlier PUT landed, or a
        // token replay after finalize); the live object is untouched. Finalize was still called
        // with this attempt's size/hash: once the version is `available` it rejects a differing
        // pair, so a replay with other bytes cannot alter metadata. Outcomes: see `upload`.
        return match finalize_result {
            Err(_) => (
                StatusCode::CONFLICT,
                "content already published for this version",
            )
                .into_response(),
            Ok(_) if state.control_base_url.is_empty() => (
                StatusCode::CONFLICT,
                "content already published for this version",
            )
                .into_response(),
            Ok(echo) => uploaded_response(&echo),
        };
    }

    match finalize_result {
        Err(resp) => resp,
        Ok(echo) => uploaded_response(&echo),
    }
}

/// Reject an upload whose streamed bytes failed the post-publish `exact_size`/`expected_hash`
/// check with `400`, first deleting the object `publish_exclusive` just wrote **iff this
/// request created it** (`created == true`).
///
/// `publish_exclusive` never overwrites, so a leftover invalid object would block a corrected
/// retry (it would get `created: false`) until the orphan cleanup reclaims the path. Deletion
/// is best-effort (`warn!` on failure). With `created == false` another request owns the live
/// object and this request's bytes were never stored, so nothing is deleted.
async fn reject_upload_bad_content(
    backend: &dyn StorageBackend,
    claims: &Claims,
    created: bool,
    reason: &'static str,
) -> Response {
    if created && let Err(e) = backend.delete(&claims.backend_path).await {
        tracing::warn!(
            error = %e,
            backend_path = %claims.backend_path,
            "failed to clean up freshly-published object after post-validation failure; \
             path will stay poisoned until orphan reconciliation reclaims it"
        );
    }
    (StatusCode::BAD_REQUEST, reason).into_response()
}

/// Build the `200 uploaded` response, echoing the auto-bind outcome (`X-FS-Bound` / `ETag`).
fn uploaded_response(echo: &FinalizeEcho) -> Response {
    let mut resp = (StatusCode::OK, "uploaded").into_response();
    if let Some(bound) = &echo.bound
        && let Ok(v) = HeaderValue::from_str(bound)
    {
        resp.headers_mut().insert("x-fs-bound", v);
    }
    if let Some(etag) = &echo.etag
        && let Ok(v) = HeaderValue::from_str(etag)
    {
        resp.headers_mut().insert(header::ETAG, v);
    }
    if let Some(cur) = &echo.current_etag
        && let Ok(v) = HeaderValue::from_str(cur)
    {
        resp.headers_mut().insert("x-fs-current-etag", v);
    }
    resp
}

/// Build the finalize request body (JSON `{size, hash_hex}`); the error response is boxed.
#[allow(clippy::result_large_err)]
fn finalize_body(size: i64, hash_hex: &str) -> Result<Vec<u8>, Response> {
    let body = serde_json::json!({ "size": size, "hash_hex": hash_hex });
    serde_json::to_vec(&body).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize finalize request body");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    })
}

/// Auto-bind outcome from the finalize response (`x-fs-bound` / `etag`, set when the token
/// carried `bind_on_finalize`), copied onto the sidecar's `200` as `X-FS-Bound` / `ETag`;
/// both `None` for manual-bind tokens.
#[derive(Debug, Default, Clone)]
struct FinalizeEcho {
    bound: Option<String>,
    etag: Option<String>,
    current_etag: Option<String>,
}

/// Interpret the HTTP response from the control-plane finalize call.
async fn interpret_finalize_response(
    resp: reqwest::Response,
    file_id: Uuid,
    version_id: Uuid,
) -> Result<FinalizeEcho, Response> {
    if resp.status().is_success() {
        tracing::debug!(%file_id, %version_id, "finalize callback succeeded");
        let hdr = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        return Ok(FinalizeEcho {
            bound: hdr("x-fs-bound"),
            etag: hdr("etag"),
            current_etag: hdr("x-fs-current-etag"),
        });
    }
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    tracing::error!(
        %file_id, %version_id,
        http_status = %status,
        body = %body_text,
        "control-plane finalize callback returned error"
    );
    // The detailed status/body stay in the server-side log above — forwarding
    // them to the client would leak the control plane's raw error body
    // (which can carry internal details) to an uploading client.
    Err((StatusCode::BAD_GATEWAY, "finalize failed").into_response())
}

/// Maximum number of attempts (including the first) for a sidecar→control-plane
/// callback POST (finalize or report-part). Only transport-level failures
/// (`reqwest::Error::is_connect()` / `is_timeout()`) are retried; a
/// successful-but-error HTTP status is a real 4xx/5xx from the control plane
/// and is returned immediately by the caller's response interpretation.
const CALLBACK_MAX_ATTEMPTS: u32 = 3;

/// Fixed delay between callback retry attempts. Short enough that even the
/// maximum number of attempts adds well under a second to the test suite's
/// wall-clock budget.
const CALLBACK_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Error from [`post_with_retry`]: a transport failure from an attempt that ran, or the retry
/// budget (`retry_budget`) running out first. Callers treat both alike (log, answer `502`);
/// the split just gives the budget case an honest message.
#[derive(Debug)]
enum CallbackError {
    Transport(reqwest::Error),
    BudgetExceeded(Duration),
}

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::BudgetExceeded(budget) => write!(
                f,
                "control-plane callback retry budget ({:.3}s) exceeded before any attempt \
                 completed",
                budget.as_secs_f64()
            ),
        }
    }
}

impl std::error::Error for CallbackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            Self::BudgetExceeded(_) => None,
        }
    }
}

/// POST `body_bytes` to `url` with the callback retry policy: up to `CALLBACK_MAX_ATTEMPTS`
/// attempts, retrying only transport connect/timeout failures, `CALLBACK_RETRY_DELAY` apart.
/// Shared by `finalize_with_control_plane` and `report_part_with_control_plane`.
///
/// The whole loop (attempts plus delays) is wrapped in one `tokio::time::timeout(retry_budget,
/// ..)` (normally `FS_SIDECAR_FINALIZE_TIMEOUT_SECS`), so total time is bounded regardless of
/// `CALLBACK_MAX_ATTEMPTS`; an in-flight attempt is cancelled when the budget runs out.
/// `internal_token` is always attached as `x-fs-internal-token`.
async fn post_with_retry(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    request_id: &str,
    internal_token: &str,
    body_bytes: &[u8],
    retry_budget: Duration,
) -> Result<reqwest::Response, CallbackError> {
    use tokio_retry::RetryIf;
    use tokio_retry::strategy::FixedInterval;

    let mut attempt: u32 = 0;
    let action = || {
        attempt += 1;
        let this_attempt = attempt;
        let mut req = http
            .post(url)
            .header("content-type", "application/json")
            .header("x-fs-token", token);
        // Propagate the correlation id so both planes' logs for this upload can be joined.
        if !request_id.is_empty() {
            req = req.header("x-request-id", request_id);
        }
        req = req.header("x-fs-internal-token", internal_token);
        let fut = req.body(body_bytes.to_vec()).send();
        async move {
            let result = fut.await;
            if let Err(ref e) = result
                && this_attempt < CALLBACK_MAX_ATTEMPTS
                && (e.is_connect() || e.is_timeout())
            {
                tracing::warn!(
                    attempt = this_attempt,
                    error = %e,
                    "control-plane callback transport error, retrying"
                );
            }
            result
        }
    };
    // Retry only transport connect/timeout failures; an HTTP status is returned unchanged.
    // `CALLBACK_MAX_ATTEMPTS` includes the first attempt, so there is one fewer delay.
    let retryable = |e: &reqwest::Error| e.is_connect() || e.is_timeout();
    let strategy =
        FixedInterval::new(CALLBACK_RETRY_DELAY).take((CALLBACK_MAX_ATTEMPTS - 1) as usize);
    // The whole loop is inside this timeout; cancelling an in-flight `send()` is safe (small
    // already-materialized body, `reqwest` closes the connection on drop).
    match tokio::time::timeout(retry_budget, RetryIf::start(strategy, action, retryable)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => Err(CallbackError::Transport(e)),
        Err(_elapsed) => Err(CallbackError::BudgetExceeded(retry_budget)),
    }
}

/// Call the control-plane finalize endpoint after a successful PUT. `Err(Response)` is a `502`
/// for the client; an empty `control_base_url` skips the callback (dev mode).
async fn finalize_with_control_plane(
    state: &SidecarState,
    token: &str,
    request_id: &str,
    file_id: Uuid,
    version_id: Uuid,
    size: i64,
    hash_hex: &str,
) -> Result<FinalizeEcho, Response> {
    if state.control_base_url.is_empty() {
        return Ok(FinalizeEcho::default());
    }

    let url = format!(
        "{}/api/file-storage/v1/files/{}/versions/{}/finalize",
        state.control_base_url.trim_end_matches('/'),
        file_id,
        version_id,
    );

    let body_bytes = finalize_body(size, hash_hex)?;

    match post_with_retry(
        &state.http,
        &url,
        token,
        request_id,
        state.internal_token.expose(),
        &body_bytes,
        state.callback_retry_budget,
    )
    .await
    {
        Ok(resp) => interpret_finalize_response(resp, file_id, version_id).await,
        Err(e) => {
            tracing::error!(
                %file_id, %version_id, error = %e,
                "control-plane finalize callback failed"
            );
            // `e` embeds the internal `FS_SIDECAR_CONTROL_URL`: never forward it to the client
            // (it is already logged above).
            Err((StatusCode::BAD_GATEWAY, "finalize failed").into_response())
        }
    }
}

/// Build the report-part request body (JSON `{backend_etag, hash_hex, size}`); the error
/// response is boxed.
#[allow(clippy::result_large_err)]
fn report_part_body(backend_etag: &str, hash_hex: &str, size: i64) -> Result<Vec<u8>, Response> {
    let body = serde_json::json!({
        "backend_etag": backend_etag,
        "hash_hex": hash_hex,
        "size": size,
    });
    serde_json::to_vec(&body).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize report-part request body");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    })
}

/// Interpret the HTTP response from the control-plane report-part call.
async fn interpret_report_part_response(
    resp: reqwest::Response,
    upload_id: Uuid,
    part_number: u32,
) -> Result<(), Response> {
    if resp.status().is_success() {
        tracing::debug!(%upload_id, part_number, "report-part callback succeeded");
        return Ok(());
    }
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    tracing::error!(
        %upload_id, part_number,
        http_status = %status,
        body = %body_text,
        "control-plane report-part callback returned error"
    );
    // Same no-leak principle as `interpret_finalize_response`: status/body stay server-side.
    Err((StatusCode::BAD_GATEWAY, "report failed").into_response())
}

/// Call the control-plane report-part endpoint after a successful part write; same contract as
/// `finalize_with_control_plane` (`502` on failure, skipped when `control_base_url` is empty).
/// The part write and this report are both idempotent per `(upload_id, part_number)`, so the
/// client may retry.
#[allow(clippy::too_many_arguments)]
async fn report_part_with_control_plane(
    state: &SidecarState,
    token: &str,
    request_id: &str,
    file_id: Uuid,
    version_id: Uuid,
    upload_id: Uuid,
    part_number: u32,
    backend_etag: &str,
    hash_hex: &str,
    size: i64,
) -> Result<(), Response> {
    if state.control_base_url.is_empty() {
        return Ok(());
    }

    let url = format!(
        "{}/api/file-storage/v1/files/{}/versions/{}/multipart/{}/parts/{}/report",
        state.control_base_url.trim_end_matches('/'),
        file_id,
        version_id,
        upload_id,
        part_number,
    );

    let body_bytes = report_part_body(backend_etag, hash_hex, size)?;

    match post_with_retry(
        &state.http,
        &url,
        token,
        request_id,
        state.internal_token.expose(),
        &body_bytes,
        state.callback_retry_budget,
    )
    .await
    {
        Ok(resp) => interpret_report_part_response(resp, upload_id, part_number).await,
        Err(e) => {
            tracing::error!(
                %file_id, %version_id, %upload_id, part_number, error = %e,
                "control-plane report-part callback failed"
            );
            // Same no-leak principle: `e` embeds the internal control-plane URL.
            Err((StatusCode::BAD_GATEWAY, "report failed").into_response())
        }
    }
}

/// Writes one multipart part to `backend`, returning `(body_len, backend_etag, hash_hex)` or an
/// early terminal `Response` on a client/backend error. Neither path buffers a whole part.
/// * `multipart_native` (e.g. `S3Backend`): stream into `upload_part_stream` against the native
///   session (`claims.multipart.backend_handle`); see `write_multipart_part_native`.
/// * otherwise (e.g. `LocalFsBackend`): write the part as its own object at
///   `{backend_path}.part.{n}` via `put_stream`; `complete_multipart_upload` assembles them.
async fn write_multipart_part(
    backend: &dyn StorageBackend,
    claims: &Claims,
    part_number: u32,
    body: Body,
    idle: Option<Duration>,
) -> Result<(u64, String, String), Response> {
    if backend.capabilities().multipart_native {
        write_multipart_part_native(backend, claims, part_number, body, idle).await
    } else {
        write_multipart_part_offset_object(backend, claims, part_number, body, idle).await
    }
}

/// Wraps `stream` (already through [`idle_timeout_stream`]) so it never forwards more than
/// `max_size` bytes: the chunk that would exceed it sets `oversized` and is replaced by one
/// `Err(ErrorKind::InvalidData)`. Needed because a native backend's `upload_part_stream` takes
/// an exact length, not a ceiling like `put_stream`.
///
/// It also publishes the exact byte count seen into `observed_len` when the stream ends, so
/// `write_multipart_part_native` can tell an undersized part from a backend fault.
fn part_size_guard(
    stream: futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>>,
    max_size: u64,
    oversized: Arc<AtomicBool>,
    observed_len: Arc<Mutex<Option<u64>>>,
) -> futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>> {
    Box::pin(futures::stream::unfold(
        (stream, 0u64, false),
        move |(mut stream, seen, done)| {
            let oversized = Arc::clone(&oversized);
            let observed_len = Arc::clone(&observed_len);
            async move {
                if done {
                    return None;
                }
                match stream.next().await {
                    None => {
                        if let Ok(mut slot) = observed_len.lock() {
                            *slot = Some(seen);
                        }
                        None
                    }
                    Some(Err(e)) => Some((Err(e), (stream, seen, true))),
                    Some(Ok(chunk)) => {
                        let new_seen = seen + chunk.len() as u64;
                        if new_seen > max_size {
                            if let Ok(mut slot) = observed_len.lock() {
                                *slot = Some(new_seen);
                            }
                            oversized.store(true, Ordering::SeqCst);
                            let e = std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("part body length exceeds token size claim {max_size}"),
                            );
                            Some((Err(e), (stream, new_seen, true)))
                        } else {
                            Some((Ok(chunk), (stream, new_seen, false)))
                        }
                    }
                }
            }
        },
    ))
}

/// `multipart_native` write path; see `write_multipart_part`.
///
/// The part streams into `backend.upload_part_stream` with `claims.multipart.size` (the
/// server-authoritative part length) as the exact `len` a native backend needs.
/// [`part_size_guard`] rejects an oversized part before the backend's exact-length check and
/// publishes the observed count so an undersized part can be told from a backend fault.
async fn write_multipart_part_native(
    backend: &dyn StorageBackend,
    claims: &Claims,
    part_number: u32,
    body: Body,
    idle: Option<Duration>,
) -> Result<(u64, String, String), Response> {
    let max_size = claims.multipart.size;
    let timed_out = Arc::new(AtomicBool::new(false));
    let byte_stream = idle_timeout_stream(
        body.into_data_stream()
            .map(|r| r.map_err(std::io::Error::other)),
        idle,
        Arc::clone(&timed_out),
    );

    let oversized = Arc::new(AtomicBool::new(false));
    let observed_len: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let guarded_stream = part_size_guard(
        byte_stream,
        max_size,
        Arc::clone(&oversized),
        Arc::clone(&observed_len),
    );

    let upload_result = backend
        .upload_part_stream(
            &claims.backend_path,
            &claims.multipart.backend_handle,
            part_number,
            // ADR-0006: the part's byte offset in the assembled object, minted into the token.
            claims.multipart.offset,
            guarded_stream,
            max_size,
        )
        .await;

    match upload_result {
        // The backend reports success only after `guarded_stream` yielded exactly `max_size`
        // bytes (the `upload_part_stream` contract), so `body_len` is always `max_size`.
        Ok((etag, hash)) => Ok((max_size, etag, hex::encode(hash))),
        Err(e) => {
            if oversized.load(Ordering::SeqCst) {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("part body length exceeds token size claim {max_size}"),
                )
                    .into_response());
            }
            let observed = observed_len.lock().ok().and_then(|g| *g);
            if let Some(resp) = idle_timeout_response(
                &timed_out,
                &format!("{} (part {part_number})", claims.backend_path),
                observed,
            ) {
                return Err(resp);
            }
            // Neither oversize nor idle timeout: a count short of `max_size` means an undersized
            // part (a client error, `400` rather than `413`/`500`); anything else is a backend
            // fault.
            if let Some(observed) = observed
                && observed != max_size
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "part body length {observed} does not match token size claim {max_size}"
                    ),
                )
                    .into_response());
            }
            Err(backend_error_response(
                &e,
                &format!("upload_part_stream (part {part_number})"),
            ))
        }
    }
}

/// Non-native (offset-object) write path; see `write_multipart_part`.
async fn write_multipart_part_offset_object(
    backend: &dyn StorageBackend,
    claims: &Claims,
    part_number: u32,
    body: Body,
    idle: Option<Duration>,
) -> Result<(u64, String, String), Response> {
    let part_path = format!("{}.part.{}", claims.backend_path, part_number);
    let timed_out = Arc::new(AtomicBool::new(false));
    let byte_stream = idle_timeout_stream(
        body.into_data_stream()
            .map(|r| r.map_err(std::io::Error::other)),
        idle,
        Arc::clone(&timed_out),
    );
    let (body_len, part_hash) = match backend
        .put_stream(&part_path, byte_stream, Some(claims.multipart.size))
        .await
    {
        Ok(v) => v,
        Err(DomainError::Validation { .. }) => {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "part body length exceeds token size claim {}",
                    claims.multipart.size
                ),
            )
                .into_response());
        }
        Err(e) => {
            if let Some(resp) = idle_timeout_response(&timed_out, &part_path, None) {
                return Err(resp);
            }
            return Err(backend_error_response(
                &e,
                &format!("put_stream (part {part_number})"),
            ));
        }
    };

    // Exact-length check: the `max_size` guard only rejects an oversized part mid-stream
    // (`413`), so a mismatch here means undersized: `400`. The part is removed so a rejected
    // part never lingers as an orphaned backend object.
    if body_len != claims.multipart.size {
        drop(backend.delete(&part_path).await);
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "part body length {} does not match token size claim {}",
                body_len, claims.multipart.size
            ),
        )
            .into_response());
    }

    let part_etag = hex::encode(part_hash);
    Ok((body_len, part_etag.clone(), part_etag))
}

/// `PUT` multipart part: verify the `op=multipart_part` token, stream the part to the backend,
/// enforce the exact `size` claim and return the part hash. The control plane is the sole
/// token minter (ADR-0004); the sidecar only verifies.
///
/// Oversized parts abort mid-stream; undersized ones are only detectable once the stream is
/// drained (see `write_multipart_part_native` and the offset-object path).
///
/// Idempotent per `(upload_id, part_number)`: a re-PUT with the same token overwrites the
/// earlier part (safe for resume, ADR-0004).
async fn upload_multipart_part(
    State(state): State<SidecarState>,
    Path((file_id, version_id, part_number)): Path<(Uuid, Uuid, u32)>,
    Query(q): Query<TokenQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let token = match extract_token(&q, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    // Verify the signed token (asymmetric Ed25519; the sidecar cannot mint tokens, ADR-0004).
    let claims = match state
        .verifier
        .verify(&token, time::OffsetDateTime::now_utc())
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    };

    // Verify op and path bindings.
    if claims.op != Op::MultipartPart
        || claims.file_id != file_id
        || claims.version_id != version_id
    {
        return (
            StatusCode::FORBIDDEN,
            "token does not authorize this operation",
        )
            .into_response();
    }

    // Verify part-number binding (prevents replaying another part's token here).
    if claims.multipart.part_number != part_number {
        return (
            StatusCode::FORBIDDEN,
            "token part_number does not match path",
        )
            .into_response();
    }

    let backend = match state.backends.get(&claims.backend_id) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("unknown backend '{}': {e}", claims.backend_id),
            )
                .into_response();
        }
    };

    // Write the part (see `write_multipart_part` for the two models).
    let (body_len, backend_etag, hash_hex) = match write_multipart_part(
        backend.as_ref(),
        &claims,
        part_number,
        body,
        state.body_idle_timeout,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    #[allow(clippy::cast_precision_loss)]
    state.metrics.record_ingress_bytes(body_len as f64);

    // Report-part callback: tell the control plane the part landed so it records the part row
    // `complete_multipart_upload` assembles from; `claims.request_id` is echoed as `x-request-id`.
    if let Err(resp) = report_part_with_control_plane(
        &state,
        &token,
        &claims.request_id,
        file_id,
        version_id,
        claims.multipart.upload_id,
        part_number,
        &backend_etag,
        &hash_hex,
        i64::try_from(body_len).unwrap_or(i64::MAX),
    )
    .await
    {
        return resp;
    }

    // Return the part hash and ETag for per-part integrity tracking.
    let body = serde_json::json!({
        "part_number": part_number,
        "etag": backend_etag,
        "hash_algorithm": "SHA-256",
        "hash": hash_hex,
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// Fallback `Content-Type` for a download: used when `claims.content_type` is empty or not a
/// valid header value. The sidecar is a stateless byte-mover and only echoes the token's
/// claim; octet-stream is always a safe answer.
const FALLBACK_CONTENT_TYPE: &str = "application/octet-stream";

/// Resolve the download `Content-Type` from the token claims, else [`FALLBACK_CONTENT_TYPE`].
fn content_type_header(claims: &Claims) -> HeaderValue {
    if claims.content_type.is_empty() {
        return HeaderValue::from_static(FALLBACK_CONTENT_TYPE);
    }
    HeaderValue::from_str(&claims.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static(FALLBACK_CONTENT_TYPE))
}

/// Resolve the download `ETag` from the token claims: `claims.etag` already holds the quoted
/// opaque `ETag` (`domain::etag::content_etag`). `None` (header omitted) when empty or invalid.
fn etag_header(claims: &Claims) -> Option<HeaderValue> {
    if claims.etag.is_empty() {
        return None;
    }
    HeaderValue::from_str(&claims.etag).ok()
}

/// Build a `Content-Range` value, e.g. `bytes 0-99/1000` or `bytes */1000` (RFC 9110 §14.4).
fn header_value(s: &str) -> HeaderValue {
    // Callers pass ASCII only; fall back to a safe placeholder rather than panic.
    HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
}

/// `GET` download: verify token (op=GET), stream bytes, honour `Range`.
///
/// Backend errors stay distinct (not-found, unsatisfiable range, I/O failure never fold into
/// `416`). `Content-Range` is set on every `206` and on `416`. `Content-Type`/`ETag` come from
/// the token's `content_type`/`etag` claims ([`content_type_header`]/[`etag_header`]).
///
/// `If-None-Match` -> `304` is not implemented: tokens are scoped to one
/// `(file_id, version_id)`, so the bandwidth win is small.
async fn download(
    State(state): State<SidecarState>,
    Path((file_id, version_id)): Path<(Uuid, Uuid)>,
    Query(q): Query<TokenQuery>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_token(&q, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let claims = match state.verifier.verify(&token, OffsetDateTime::now_utc()) {
        Ok(c) => c,
        Err(e) => return (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    };
    if claims.op != Op::Get || claims.file_id != file_id || claims.version_id != version_id {
        return (
            StatusCode::FORBIDDEN,
            "token does not authorize this operation",
        )
            .into_response();
    }

    let backend = match state.backends.get(&claims.backend_id) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("unknown backend '{}': {e}", claims.backend_id),
            )
                .into_response();
        }
    };

    let path = &claims.backend_path;

    // `stat` gives existence and size together and distinguishes a real not-found (`404`) from
    // other I/O errors, so later failures are genuine backend errors, never `416`/missing blob.
    // Resolved once and passed to `download_range` and `download_whole`.
    let total = match backend.stat(path).await {
        Ok(Some(n)) => n,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => return backend_error_response(&e, "stat"),
    };

    // Range support: one signed URL serves many ranges.
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(range::parse);

    match range {
        Some(r) => download_range(&state, &backend, path, total, r, &claims).await,
        None => download_whole(&state, &backend, path, total, &claims).await,
    }
}

/// `HEAD` download: same token check and `404` contract as `download`, but metadata-only
/// (`StorageBackend::stat`) with an empty body. Registered via `.head(download_head)`.
///
/// Returns the same `Accept-Ranges`/`Content-Type`/`ETag` headers as `download`'s `200`, plus
/// `Content-Length` set explicitly from `backend.stat` (there is no body to derive it from).
async fn download_head(
    State(state): State<SidecarState>,
    Path((file_id, version_id)): Path<(Uuid, Uuid)>,
    Query(q): Query<TokenQuery>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_token(&q, &headers) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let claims = match state.verifier.verify(&token, OffsetDateTime::now_utc()) {
        Ok(c) => c,
        Err(e) => return (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    };
    if claims.op != Op::Get || claims.file_id != file_id || claims.version_id != version_id {
        return (
            StatusCode::FORBIDDEN,
            "token does not authorize this operation",
        )
            .into_response();
    }

    let backend = match state.backends.get(&claims.backend_id) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("unknown backend '{}': {e}", claims.backend_id),
            )
                .into_response();
        }
    };

    let path = &claims.backend_path;

    // Same existence-and-size contract as `download`, via one `stat`.
    let total = match backend.stat(path).await {
        Ok(Some(n)) => n,
        Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => return backend_error_response(&e, "stat"),
    };

    let mut resp = (StatusCode::OK, ()).into_response();
    let headers_mut = resp.headers_mut();
    headers_mut.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers_mut.insert(header::CONTENT_TYPE, content_type_header(&claims));
    if let Some(v) = etag_header(&claims) {
        headers_mut.insert(header::ETAG, v);
    }
    headers_mut.insert(header::CONTENT_LENGTH, header_value(&total.to_string()));
    resp
}

/// Map a [`StorageBackend::get_stream`]/[`StorageBackend::get_range_stream`] failure to a
/// response, after the caller's `stat` confirmed existence and range satisfiability.
///
/// [`DomainError::Conflict`] means the backend's own re-check found the object changed size
/// since that `stat`: a transient race, answered `503` + short `Retry-After` and logged at
/// `warn!`. Any other error is a genuine I/O fault: `500` + `error!`.
fn backend_read_error_response(e: &DomainError, context: &str) -> Response {
    if let DomainError::Conflict { .. } = e {
        tracing::warn!(error = %e, context, "object changed during read, retrying should succeed");
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            "object changed during read, retry",
        )
            .into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    backend_error_response(e, context)
}

/// Map any other backend-call failure to a response: `BackendUnavailable` (transient: network,
/// timeout, overload, a lost concurrent-change race; see
/// `docs/arch/errors/categories/14-service-unavailable.md`) gets `503` + `Retry-After` at
/// `warn!`; every other `DomainError` is a non-retryable fault: `500` + `error!`.
fn backend_error_response(e: &DomainError, context: &str) -> Response {
    if let DomainError::BackendUnavailable { .. } = e {
        tracing::warn!(error = %e, context, "backend temporarily unavailable");
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            "backend temporarily unavailable, retry",
        )
            .into_response();
        resp.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from(BACKEND_RETRY_AFTER_SECS),
        );
        return resp;
    }
    tracing::error!(error = %e, context, "backend error");
    (StatusCode::INTERNAL_SERVER_ERROR, "backend error").into_response()
}

/// Wrap a download body stream: record egress bytes per `Ok` chunk and log the first `Err` at
/// `warn!`, passing it through unchanged. Status and `Content-Length` are already sent, so the
/// `Err` must still reach hyper to abort the connection (not look like a short success); the
/// log tells it apart from a client disconnect.
fn download_stream_with_observability(
    stream: futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>>,
    metrics: Arc<dyn FileStorageMetricsPort>,
    context: &'static str,
    path: String,
) -> impl futures::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static {
    let mut bytes_sent: u64 = 0;
    let mut fault_logged = false;
    stream.map(move |chunk| {
        match &chunk {
            Ok(bytes) => {
                #[allow(clippy::cast_precision_loss)]
                metrics.record_egress_bytes(bytes.len() as f64);
                bytes_sent += bytes.len() as u64;
            }
            Err(e) if !fault_logged => {
                fault_logged = true;
                tracing::warn!(
                    error = %e,
                    context,
                    path,
                    bytes_sent,
                    "backend read failed mid-stream; response already committed, aborting connection"
                );
            }
            Err(_) => {}
        }
        chunk
    })
}

/// Serve a `Range`-qualified `GET`; `total` is the caller's single `stat` result (no extra
/// backend round-trip). Split out of `download` for cognitive complexity.
///
/// The body streams from `StorageBackend::get_range_stream` rather than being materialized:
/// `Range: bytes=0-` can span the whole object (a common first request from media players).
async fn download_range(
    state: &SidecarState,
    backend: &Arc<dyn StorageBackend>,
    path: &str,
    total: u64,
    r: file_storage_sdk::ByteRange,
    claims: &Claims,
) -> Response {
    let Some((start, end)) = r.resolve(total) else {
        // Range unsatisfiable (RFC 9110 §14.4): the blob exists but the range is past its end.
        let mut resp = (StatusCode::RANGE_NOT_SATISFIABLE, "range not satisfiable").into_response();
        let headers_mut = resp.headers_mut();
        headers_mut.insert(
            header::CONTENT_RANGE,
            header_value(&format!("bytes */{total}")),
        );
        // Every download response includes `Accept-Ranges`, the 416 path included.
        headers_mut.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        return resp;
    };
    // Exact length committed to the `Content-Length` header, passed to the backend so it can
    // refuse a body that would disagree.
    let range_len = end - start + 1;
    match backend.get_range_stream(path, r, range_len).await {
        Ok(stream) => {
            // Counted per chunk as it leaves the process, so a mid-transfer disconnect does not
            // over-report egress.
            let body_stream = download_stream_with_observability(
                stream,
                Arc::clone(&state.metrics),
                "range",
                path.to_owned(),
            );

            let mut resp =
                (StatusCode::PARTIAL_CONTENT, Body::from_stream(body_stream)).into_response();
            let headers_mut = resp.headers_mut();
            headers_mut.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            headers_mut.insert(
                header::CONTENT_RANGE,
                header_value(&format!("bytes {start}-{end}/{total}")),
            );
            // A streamed body gets no automatic `Content-Length`: set it from the resolved range,
            // the same value passed to `get_range_stream` as `range_len`.
            headers_mut.insert(header::CONTENT_LENGTH, header_value(&range_len.to_string()));
            headers_mut.insert(header::CONTENT_TYPE, content_type_header(claims));
            if let Some(v) = etag_header(claims) {
                headers_mut.insert(header::ETAG, v);
            }
            resp
        }
        // Existence and satisfiability were confirmed above; see `backend_read_error_response`
        // for how a size-change `Conflict` differs from an I/O fault.
        Err(e) => backend_read_error_response(&e, "get_range_stream"),
    }
}

/// Serve a whole-blob `GET` (no `Range`); see `download_range` for why `total` is a parameter.
///
/// The body streams from `StorageBackend::get_stream` rather than being materialized: the
/// default `FS_SIDECAR_MAX_BODY_BYTES` permits objects up to 5 GiB.
///
/// When `claims.content_sha256` is non-empty the stream is verified end-to-end
/// (`verify_whole_object_download_stream`). Otherwise whatever sits at `claims.backend_path`
/// is served on the token's word alone, and a deleted version's path can be reoccupied by a
/// new upload before an old download token is used, serving the new bytes under the old
/// `ETag`. A mismatch aborts the response mid-stream. `download_range` cannot do this (a
/// partial range cannot be compared with a whole-object digest; see `Claims::content_sha256`).
async fn download_whole(
    state: &SidecarState,
    backend: &Arc<dyn StorageBackend>,
    path: &str,
    total: u64,
    claims: &Claims,
) -> Response {
    // `total` is the value committed to `Content-Length`; the backend can refuse a body
    // that disagrees with it.
    match backend.get_stream(path, total).await {
        Ok(stream) => {
            // Whole-object hash verification (empty `content_sha256` = no check; see
            // `Claims::content_sha256`). Applied before the observability wrapper so a mismatch
            // `Err` is still counted/logged like any other mid-stream failure.
            let stream = if claims.content_sha256.is_empty() {
                stream
            } else {
                verify_whole_object_download_stream(stream, claims.content_sha256.clone())
            };
            // Counted per chunk as it is handed to the client (see `download_range`).
            let body_stream = download_stream_with_observability(
                stream,
                Arc::clone(&state.metrics),
                "whole",
                path.to_owned(),
            );

            let mut resp = (StatusCode::OK, Body::from_stream(body_stream)).into_response();
            let headers_mut = resp.headers_mut();
            headers_mut.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            headers_mut.insert(header::CONTENT_TYPE, content_type_header(claims));
            if let Some(v) = etag_header(claims) {
                headers_mut.insert(header::ETAG, v);
            }
            headers_mut.insert(header::CONTENT_LENGTH, header_value(&total.to_string()));
            resp
        }
        // Existence was confirmed above; see `backend_read_error_response` for how a
        // size-change `Conflict` differs from an I/O fault.
        Err(e) => backend_read_error_response(&e, "get_stream"),
    }
}

#[cfg(test)]
#[path = "sidecar_tests.rs"]
mod tests;
