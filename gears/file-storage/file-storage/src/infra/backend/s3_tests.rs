//! `S3Backend` tests against an in-process `s3s-fs` server.

use std::net::SocketAddr;

use bytes::Bytes;
use file_storage_sdk::ByteRange;
use futures::stream::{self, BoxStream};
use tempfile::TempDir;

use reqwest::StatusCode;

use super::{S3Backend, is_transient_s3};
use crate::infra::backend::StorageBackend;
use crate::infra::backend::backend_tests::{assert_backend_contract, read_all, write_all};
use crate::infra::content::hash;

const TEST_ACCESS_KEY: &str = "test-access-key";
const TEST_SECRET_KEY: &str = "test-secret-key";

/// In-process `s3s-fs` server on an ephemeral port; keep the returned `TempDir` alive.
async fn start_s3s_fs() -> (SocketAddr, TempDir) {
    let dir = tempfile::tempdir().expect("create temp dir for s3s-fs backing store");
    let fs = s3s_fs::FileSystem::new(dir.path()).expect("init s3s-fs FileSystem");

    let mut builder = s3s::service::S3ServiceBuilder::new(fs);
    builder.set_auth(s3s::auth::SimpleAuth::from_single(
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    ));
    let service = builder.build();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind ephemeral port for s3s-fs test server");
    let local_addr = listener.local_addr().expect("resolve bound local addr");

    tokio::spawn(async move {
        let http_server =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                continue;
            };
            let io = hyper_util::rt::TokioIo::new(socket);
            let conn = http_server
                .serve_connection(io, service.clone())
                .into_owned();
            tokio::spawn(async move {
                drop(conn.await);
            });
        }
    });

    (local_addr, dir)
}

/// `S3Backend` over a fresh `s3s-fs` server; the bucket dir is pre-created (not auto-created).
async fn make_backend(addr: SocketAddr, dir: &TempDir, bucket: &str) -> S3Backend {
    tokio::fs::create_dir_all(dir.path().join(bucket))
        .await
        .expect("pre-create s3s-fs bucket directory");
    let endpoint: url::Url = format!("http://{addr}")
        .parse()
        .expect("valid endpoint url");
    S3Backend::new(
        "s3-test",
        endpoint,
        "us-east-1",
        bucket,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .expect("construct S3Backend")
}

fn unique_bucket() -> String {
    format!("test-{}", uuid::Uuid::now_v7())
}

#[tokio::test]
async fn s3_backend_put_get_round_trip() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    assert_backend_contract(&backend).await;

    let on_disk = dir.path().join(&bucket).join("contract").join("put-get");
    let raw = tokio::fs::read(&on_disk)
        .await
        .unwrap_or_else(|e| panic!("expected object at {on_disk:?}: {e}"));
    assert_eq!(raw, b"hello, contract");
}

/// A large object's `get_stream` chunks must reassemble to the written bytes.
#[tokio::test]
async fn s3_backend_get_stream_reassembles_large_object() {
    use futures::StreamExt;

    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    let payload: Vec<u8> = (0..300_000)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect();
    write_all(&backend, "large/obj", Bytes::from(payload.clone())).await;

    let mut stream = backend
        .get_stream("large/obj", payload.len() as u64)
        .await
        .unwrap();
    let mut collected = Vec::new();
    while let Some(chunk) = stream.next().await {
        collected.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(collected, payload);
}

#[tokio::test]
async fn s3_backend_get_stream_missing_object_errors() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    assert!(backend.get_stream("nope/nope", 0).await.is_err());
}

async fn range_all(backend: &S3Backend, path: &str, range: ByteRange, expected_len: u64) -> Bytes {
    use futures::StreamExt;
    let mut stream = backend
        .get_range_stream(path, range, expected_len)
        .await
        .unwrap();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    Bytes::from(buf)
}

#[tokio::test]
async fn s3_backend_get_range_returns_native_partial_content() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    write_all(
        &backend,
        "range-obj",
        Bytes::from_static(b"0123456789abcdef"),
    )
    .await;

    let inclusive = range_all(
        &backend,
        "range-obj",
        ByteRange::Inclusive { start: 3, end: 7 },
        5,
    )
    .await;
    assert_eq!(inclusive, Bytes::from_static(b"34567"));

    let suffix = range_all(&backend, "range-obj", ByteRange::Suffix { length: 4 }, 4).await;
    assert_eq!(suffix, Bytes::from_static(b"cdef"));

    let open_ended = range_all(&backend, "range-obj", ByteRange::OpenEnded { start: 12 }, 4).await;
    assert_eq!(open_ended, Bytes::from_static(b"cdef"));
}

#[tokio::test]
async fn s3_backend_delete_is_idempotent() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    write_all(&backend, "to-delete", Bytes::from_static(b"gone soon")).await;
    backend.delete("to-delete").await.unwrap();
    // Second delete on an already-missing key: S3's DeleteObject returns a
    // success status regardless, so this must still be `Ok`.
    backend.delete("to-delete").await.unwrap();
    assert!(!backend.exists("to-delete").await.unwrap());
}

#[tokio::test]
async fn s3_backend_exists_distinguishes_missing_from_error() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    assert!(!backend.exists("never-uploaded").await.unwrap());

    write_all(&backend, "now-present", Bytes::from_static(b"x")).await;
    assert!(backend.exists("now-present").await.unwrap());
}

#[tokio::test]
async fn s3_is_ready_ok_against_s3s_fs() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    backend
        .is_ready()
        .await
        .expect("is_ready must succeed against a reachable, authenticated endpoint");
}

#[tokio::test]
async fn s3_is_ready_err_against_closed_port() {
    // Bind then drop: the port is closed, so the probe gets connection-refused.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("resolve bound local addr");
    drop(listener);

    let endpoint: url::Url = format!("http://{addr}")
        .parse()
        .expect("valid endpoint url");
    let backend = S3Backend::new(
        "s3-test",
        endpoint,
        "us-east-1",
        "irrelevant-bucket",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .expect("construct S3Backend");

    backend
        .is_ready()
        .await
        .expect_err("is_ready must fail against an unreachable endpoint");
}

/// `is_ready` must fail when the bucket does not exist: `NoSuchBucket` from `ListObjectsV2`
/// is distinguishable from an absent key (unlike `HeadObject`). Bypasses `make_backend`.
#[tokio::test]
async fn s3_is_ready_err_against_missing_bucket() {
    let (addr, _dir) = start_s3s_fs().await;
    let endpoint: url::Url = format!("http://{addr}")
        .parse()
        .expect("valid endpoint url");
    let backend = S3Backend::new(
        "s3-test",
        endpoint,
        "us-east-1",
        unique_bucket(),
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .expect("construct S3Backend");

    backend
        .is_ready()
        .await
        .expect_err("is_ready must fail when the target bucket does not exist");
}

#[tokio::test]
async fn s3_backend_list_paths_paginates_across_continuation_token() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    // Page size 2 over 5 objects forces at least 3 `ListObjectsV2` pages.
    let backend = make_backend(addr, &dir, &bucket)
        .await
        .with_list_page_size(2);

    let mut expected: Vec<String> = Vec::new();
    for i in 0..5 {
        let path = format!("file-{i}/version-{i}");
        write_all(
            &backend,
            &path,
            Bytes::from(format!("payload-{i}").into_bytes()),
        )
        .await;
        expected.push(format!("/{path}"));
    }

    let mut got = backend.list_paths().await.unwrap();
    got.sort();
    expected.sort();
    assert_eq!(got, expected);
}

#[tokio::test]
async fn s3_backend_multipart_initiate_upload_complete_round_trip() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    // S3 minimum part size is 5 MiB except the last; distinct patterns detect mis-ordering.
    let part_size = 5 * 1024 * 1024;
    let part1 = vec![b'a'; part_size];
    let part2 = vec![b'b'; part_size];
    let part3 = vec![b'c'; 1024]; // last part, below the minimum is fine

    let path = "multipart/round-trip";
    let upload_handle = backend.initiate_multipart(path).await.unwrap();

    // `upload_part_stream` takes each part's byte offset in the assembled object.
    let off1 = 0u64;
    let off2 = part_size as u64;
    let off3 = 2 * part_size as u64;
    let split_stream = |data: &[u8]| -> BoxStream<'static, std::io::Result<Bytes>> {
        #[allow(clippy::integer_division)]
        let mid = data.len() / 2;
        chunk_stream(vec![
            Bytes::from(data[..mid].to_vec()),
            Bytes::from(data[mid..].to_vec()),
        ])
    };
    let (etag1, hash1) = backend
        .upload_part_stream(
            path,
            &upload_handle,
            1,
            off1,
            split_stream(&part1),
            part1.len() as u64,
        )
        .await
        .unwrap();
    let (etag2, hash2) = backend
        .upload_part_stream(
            path,
            &upload_handle,
            2,
            off2,
            split_stream(&part2),
            part2.len() as u64,
        )
        .await
        .unwrap();
    let (etag3, hash3) = backend
        .upload_part_stream(
            path,
            &upload_handle,
            3,
            off3,
            split_stream(&part3),
            part3.len() as u64,
        )
        .await
        .unwrap();

    // The part hash is this gear's SHA-256, not S3's MD5 ETag.
    assert_eq!(hash1, hash::sha256(&part1));
    assert_eq!(hash2, hash::sha256(&part2));
    assert_eq!(hash3, hash::sha256(&part3));

    let to_arr = |v: Vec<u8>| -> [u8; 32] { v.try_into().unwrap() };
    // Deliberately out of order — `complete_multipart` sorts by offset.
    let completion_parts = vec![
        (3u32, off3, to_arr(hash3.clone()), etag3),
        (1u32, off1, to_arr(hash1.clone()), etag1),
        (2u32, off2, to_arr(hash2.clone()), etag2),
    ];
    let (manifest, root) = backend
        .complete_multipart(path, &upload_handle, &completion_parts)
        .await
        .unwrap();

    // The stored digest is `sha256(manifest)` (offset-manifest composite), not of the bytes.
    let expected_manifest = crate::infra::content::hash_mode::Manifest::new(vec![
        crate::infra::content::hash_mode::ManifestEntry {
            offset: off1,
            digest: to_arr(hash::sha256(&part1)),
        },
        crate::infra::content::hash_mode::ManifestEntry {
            offset: off2,
            digest: to_arr(hash::sha256(&part2)),
        },
        crate::infra::content::hash_mode::ManifestEntry {
            offset: off3,
            digest: to_arr(hash::sha256(&part3)),
        },
    ])
    .unwrap();
    assert_eq!(
        manifest.to_wire_string(),
        expected_manifest.to_wire_string()
    );
    assert_eq!(root, expected_manifest.root());

    let mut expected_bytes = Vec::with_capacity(part1.len() + part2.len() + part3.len());
    expected_bytes.extend_from_slice(&part1);
    expected_bytes.extend_from_slice(&part2);
    expected_bytes.extend_from_slice(&part3);
    let got = read_all(&backend, path, expected_bytes.len() as u64).await;
    assert_eq!(got.as_ref(), expected_bytes.as_slice());

    let on_disk = dir
        .path()
        .join(&bucket)
        .join("multipart")
        .join("round-trip");
    let raw = tokio::fs::read(&on_disk)
        .await
        .unwrap_or_else(|e| panic!("expected object at {on_disk:?}: {e}"));
    assert_eq!(raw, expected_bytes);
}

/// A part stream yielding fewer bytes than its declared `len` must be rejected.
#[tokio::test]
async fn s3_backend_upload_part_stream_rejects_undersized_stream() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    let path = "multipart/undersized";
    let upload_handle = backend.initiate_multipart(path).await.unwrap();

    // Declares 5 MiB but yields 10 bytes: must surface as an error, not a "successful" part.
    let declared_len = 5 * 1024 * 1024;
    let short_stream = chunk_stream(vec![Bytes::from_static(b"0123456789")]);
    let result = backend
        .upload_part_stream(path, &upload_handle, 1, 0, short_stream, declared_len)
        .await;
    assert!(
        result.is_err(),
        "a part stream shorter than its declared len must be rejected, not treated as uploaded"
    );
}

/// A part stream yielding more bytes than its declared `len` is rejected the same way.
#[tokio::test]
async fn s3_backend_upload_part_stream_rejects_oversized_stream() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    let path = "multipart/oversized";
    let upload_handle = backend.initiate_multipart(path).await.unwrap();

    let declared_len = 5u64;
    let long_stream = chunk_stream(vec![Bytes::from_static(b"0123456789")]); // 10 bytes > 5
    let result = backend
        .upload_part_stream(path, &upload_handle, 1, 0, long_stream, declared_len)
        .await;
    assert!(
        result.is_err(),
        "a part stream longer than its declared len must be rejected, not treated as uploaded"
    );
}

#[tokio::test]
async fn s3_backend_multipart_abort_discards_parts() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    let path = "multipart/aborted";
    let upload_handle = backend.initiate_multipart(path).await.unwrap();
    let data = Bytes::from_static(b"never completed");
    let len = data.len() as u64;
    backend
        .upload_part_stream(path, &upload_handle, 1, 0, chunk_stream(vec![data]), len)
        .await
        .unwrap();

    backend.abort_multipart(path, &upload_handle).await.unwrap();

    assert_eq!(backend.stat(path).await.unwrap(), None);
    assert!(!backend.exists(path).await.unwrap());
}

#[tokio::test]
async fn s3_backend_upload_part_rejects_part_number_outside_s3_limits() {
    // Validation precedes any network I/O, so no server is needed.
    let endpoint: url::Url = "http://127.0.0.1:1".parse().expect("valid endpoint url");
    let backend = S3Backend::new(
        "s3-test",
        endpoint,
        "us-east-1",
        "unused-bucket",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
    )
    .expect("construct S3Backend");

    let over_limit = backend
        .upload_part_stream(
            "some/path",
            "handle",
            10_001,
            0,
            chunk_stream(vec![Bytes::from_static(b"x")]),
            1,
        )
        .await;
    assert!(
        over_limit.is_err(),
        "part_number 10_001 exceeds S3's documented 10,000-part maximum and must be rejected"
    );

    let zero = backend
        .upload_part_stream(
            "some/path",
            "handle",
            0,
            0,
            chunk_stream(vec![Bytes::from_static(b"x")]),
            1,
        )
        .await;
    assert!(
        zero.is_err(),
        "part_number 0 is below S3's 1-indexed minimum and must be rejected"
    );
}

fn chunk_stream(chunks: Vec<Bytes>) -> BoxStream<'static, std::io::Result<Bytes>> {
    Box::pin(stream::iter(chunks.into_iter().map(Ok)))
}

#[tokio::test]
async fn s3_backend_put_stream_small_uses_single_put() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    // Default multipart threshold (8 MiB): this stream stays below it, so a single `PutObject`.
    let backend = make_backend(addr, &dir, &bucket).await;

    let chunk_bytes: Vec<&'static [u8]> = vec![b"small ", b"stream ", b"payload"];
    let concatenated: Vec<u8> = chunk_bytes.concat();
    let total_len = concatenated.len() as u64;
    let chunks: Vec<Bytes> = chunk_bytes.into_iter().map(Bytes::from_static).collect();

    let path = "put-stream/small";
    let (bytes_written, digest) = backend
        .put_stream(path, chunk_stream(chunks), None)
        .await
        .expect("put_stream should succeed for a small stream");

    assert_eq!(bytes_written, total_len);
    assert_eq!(digest, hash::digest_to_array(hash::sha256(&concatenated)));

    let got = read_all(&backend, path, total_len).await;
    assert_eq!(got.as_ref(), concatenated.as_slice());

    let on_disk = dir.path().join(&bucket).join("put-stream").join("small");
    let raw = tokio::fs::read(&on_disk)
        .await
        .unwrap_or_else(|e| panic!("expected object at {on_disk:?}: {e}"));
    assert_eq!(raw, concatenated);
}

#[tokio::test]
async fn s3_backend_put_stream_large_uses_multipart() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    // Low threshold so a multi-MiB stream crosses it with full 5 MiB parts.
    let part_size: u64 = 5 * 1024 * 1024;
    let backend = make_backend(addr, &dir, &bucket)
        .await
        .with_multipart_threshold_bytes(part_size);

    // 11 MiB in 1 MiB chunks: two 5 MiB parts plus a 1 MiB tail.
    let chunk_size = 1024 * 1024;
    let num_chunks: u8 = 11;
    let chunks: Vec<Bytes> = (0..num_chunks)
        .map(|i| Bytes::from(vec![b'a' + i; chunk_size]))
        .collect();
    let concatenated: Vec<u8> = chunks.iter().flat_map(|c| c.to_vec()).collect();
    let total_len = concatenated.len() as u64;

    let path = "put-stream/large";
    let (bytes_written, digest) = backend
        .put_stream(path, chunk_stream(chunks), None)
        .await
        .expect("put_stream should succeed for a large multipart stream");

    assert_eq!(bytes_written, total_len);
    assert_eq!(digest, hash::digest_to_array(hash::sha256(&concatenated)));

    let got = read_all(&backend, path, total_len).await;
    assert_eq!(got.as_ref(), concatenated.as_slice());

    // The digest `put_stream` returned must match a hash of the stored bytes.
    assert_eq!(digest, hash::digest_to_array(hash::sha256(&got)));
}

#[tokio::test]
async fn s3_backend_put_stream_enforces_max_size_mid_stream() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    // Threshold 8 bytes: the first 10-byte chunk starts multipart, the second exceeds
    // `max_size`, so an already-initiated session must be aborted.
    let backend = make_backend(addr, &dir, &bucket)
        .await
        .with_multipart_threshold_bytes(8);

    let chunks: Vec<Bytes> = vec![
        Bytes::from_static(b"0123456789"),
        Bytes::from_static(b"0123456789"),
        Bytes::from_static(b"0123456789"),
    ];

    let path = "put-stream/rejected";
    let result = backend
        .put_stream(path, chunk_stream(chunks), Some(15))
        .await;

    assert!(
        result.is_err(),
        "put_stream must reject a stream exceeding max_size"
    );

    // Nothing may be left behind: no object, and the multipart session was aborted.
    assert!(!backend.exists(path).await.unwrap());
    assert_eq!(backend.stat(path).await.unwrap(), None);
}

#[tokio::test]
async fn s3_backend_publish_exclusive_single_put_rejects_overwrite() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    let backend = make_backend(addr, &dir, &bucket).await;

    let path = "publish-exclusive/small";
    let first: &[u8] = b"the original immutable blob";
    let second: &[u8] = b"a replay attempt with different bytes";

    let outcome = backend
        .publish_exclusive(path, chunk_stream(vec![Bytes::from_static(first)]), None)
        .await
        .expect("first publish_exclusive should succeed");
    assert!(outcome.created, "first publish must report created = true");
    assert_eq!(outcome.bytes_written, first.len() as u64);
    assert_eq!(outcome.digest, hash::digest_to_array(hash::sha256(first)));

    // A replayed PUT token must not overwrite: `If-None-Match: *` -> 412 -> `created = false`.
    let outcome2 = backend
        .publish_exclusive(path, chunk_stream(vec![Bytes::from_static(second)]), None)
        .await
        .expect("second publish_exclusive must return Ok(created=false), not an error");
    assert!(
        !outcome2.created,
        "second publish to an existing path must report created = false"
    );
    assert_eq!(outcome2.bytes_written, second.len() as u64);

    let got = read_all(&backend, path, first.len() as u64).await;
    assert_eq!(
        got.as_ref(),
        first,
        "the original bytes must survive the rejected overwrite"
    );
}

#[tokio::test]
async fn s3_backend_publish_exclusive_multipart_rejects_overwrite() {
    let (addr, dir) = start_s3s_fs().await;
    let bucket = unique_bucket();
    // Low threshold so the stream takes the multipart path, whose `CompleteMultipartUpload`
    // carries `If-None-Match: *`.
    let part_size: u64 = 5 * 1024 * 1024;
    let backend = make_backend(addr, &dir, &bucket)
        .await
        .with_multipart_threshold_bytes(part_size);

    let chunk_size = 1024 * 1024;
    let num_chunks: u8 = 11;
    let first_chunks: Vec<Bytes> = (0..num_chunks)
        .map(|i| Bytes::from(vec![b'a' + i; chunk_size]))
        .collect();
    let first_concat: Vec<u8> = first_chunks.iter().flat_map(|c| c.to_vec()).collect();

    let path = "publish-exclusive/large";
    let outcome = backend
        .publish_exclusive(path, chunk_stream(first_chunks), None)
        .await
        .expect("first multipart publish_exclusive should succeed");
    assert!(outcome.created, "first multipart publish must create");
    assert_eq!(outcome.bytes_written, first_concat.len() as u64);

    // Second publish: 412 on complete, and the just-opened multipart session is aborted.
    let second_chunks: Vec<Bytes> = (0..num_chunks)
        .map(|i| Bytes::from(vec![b'z' - i; chunk_size]))
        .collect();
    let outcome2 = backend
        .publish_exclusive(path, chunk_stream(second_chunks), None)
        .await
        .expect("second multipart publish must return Ok(created=false)");
    assert!(
        !outcome2.created,
        "second multipart publish to an existing path must report created = false"
    );

    let got = read_all(&backend, path, first_concat.len() as u64).await;
    assert_eq!(
        got.as_ref(),
        first_concat.as_slice(),
        "the original multipart object must survive the rejected overwrite"
    );
}

// No concurrent-racer test here: `s3s-fs` checks `If-None-Match: *` with a plain `exists()` then
// writes, so concurrent publishes can both win. That is a test-double limitation, not
// `S3Backend`'s; the conditional header is covered sequentially by the tests above.

#[test]
fn is_transient_s3_true_for_5xx_and_throttling_status() {
    assert!(is_transient_s3(StatusCode::SERVICE_UNAVAILABLE, None));
    assert!(is_transient_s3(StatusCode::INTERNAL_SERVER_ERROR, None));
    assert!(is_transient_s3(StatusCode::BAD_GATEWAY, None));
    assert!(is_transient_s3(StatusCode::GATEWAY_TIMEOUT, None));
    assert!(is_transient_s3(StatusCode::TOO_MANY_REQUESTS, None));
}

#[test]
fn is_transient_s3_true_for_transient_s3_error_codes() {
    // A transient code can arrive under a non-5xx status; the string code is authoritative.
    assert!(is_transient_s3(
        StatusCode::SERVICE_UNAVAILABLE,
        Some("SlowDown")
    ));
    assert!(is_transient_s3(
        StatusCode::INTERNAL_SERVER_ERROR,
        Some("InternalError")
    ));
    assert!(is_transient_s3(
        StatusCode::SERVICE_UNAVAILABLE,
        Some("ServiceUnavailable")
    ));
    assert!(is_transient_s3(
        StatusCode::BAD_REQUEST,
        Some("RequestTimeout")
    ));
    assert!(is_transient_s3(
        StatusCode::TOO_MANY_REQUESTS,
        Some("ThrottlingException")
    ));
}

#[test]
fn is_transient_s3_false_for_permanent_faults() {
    assert!(!is_transient_s3(
        StatusCode::FORBIDDEN,
        Some("AccessDenied")
    ));
    assert!(!is_transient_s3(StatusCode::NOT_FOUND, Some("NoSuchKey")));
    assert!(!is_transient_s3(StatusCode::BAD_REQUEST, None));
    assert!(!is_transient_s3(StatusCode::FORBIDDEN, None));
    assert!(!is_transient_s3(StatusCode::NOT_FOUND, None));
}

#[test]
fn is_transient_s3_false_for_clock_skew() {
    // A retry re-signs with the same skewed clock, so this must NOT be transient.
    assert!(!is_transient_s3(
        StatusCode::FORBIDDEN,
        Some("RequestTimeTooSkewed")
    ));
}
