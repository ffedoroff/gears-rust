#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io;

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::{self, BoxStream};

use super::verify_stream;
use crate::infra::content::hash;
use crate::infra::content::hash_mode::{HashMode, Manifest, ManifestEntry};

fn ok_stream(chunks: Vec<Vec<u8>>) -> BoxStream<'static, io::Result<Bytes>> {
    Box::pin(stream::iter(chunks.into_iter().map(|c| Ok(Bytes::from(c)))))
}

async fn drain(mut s: BoxStream<'static, io::Result<Bytes>>) -> (Vec<u8>, Option<io::ErrorKind>) {
    let mut collected = Vec::new();
    let mut err_kind = None;
    while let Some(item) = s.next().await {
        match item {
            Ok(chunk) => collected.extend_from_slice(&chunk),
            Err(e) => {
                err_kind = Some(e.kind());
                assert!(
                    s.next().await.is_none(),
                    "the stream must not yield anything after its terminal error"
                );
                break;
            }
        }
    }
    (collected, err_kind)
}

fn build_composite(parts: &[&[u8]]) -> (Manifest, Vec<u8>) {
    let mut offset = 0u64;
    let entries: Vec<ManifestEntry> = parts
        .iter()
        .map(|p| {
            let entry = ManifestEntry {
                offset,
                digest: hash::digest_to_array(hash::sha256(p)),
            };
            offset += p.len() as u64;
            entry
        })
        .collect();
    let manifest = Manifest::new(entries).expect("valid manifest");
    let root = manifest.root().to_vec();
    (manifest, root)
}

#[tokio::test]
async fn whole_mode_matching_content_verifies_ok() {
    let content = b"the quick brown fox jumps over the lazy dog".to_vec();
    let hash_value = hash::sha256(&content);
    let inner = ok_stream(vec![
        content[0..10].to_vec(),
        content[10..20].to_vec(),
        content[20..].to_vec(),
    ]);
    let (wrapped, slot) = verify_stream(
        inner,
        content.len() as u64,
        HashMode::WholeSha256,
        hash_value,
        None,
    )
    .expect("valid whole-mode construction");
    let (collected, err) = drain(wrapped).await;
    assert_eq!(collected, content);
    assert_eq!(err, None);
    assert!(
        slot.lock()
            .unwrap()
            .take()
            .expect("verdict published")
            .is_ok(),
        "matching content must verify"
    );
}

#[tokio::test]
async fn whole_mode_tampered_content_fails_verification() {
    let content = b"the quick brown fox jumps over the lazy dog".to_vec();
    let hash_value = hash::sha256(&content);
    let mut tampered = content.clone();
    tampered[5] ^= 0xff;
    let inner = ok_stream(vec![tampered.clone()]);
    let (wrapped, slot) = verify_stream(
        inner,
        tampered.len() as u64,
        HashMode::WholeSha256,
        hash_value,
        None,
    )
    .expect("valid whole-mode construction");
    let (collected, err) = drain(wrapped).await;
    assert_eq!(collected, tampered);
    assert_eq!(err, None);
    let verdict = slot.lock().unwrap().take().expect("verdict published");
    assert!(
        matches!(
            verdict,
            Err(crate::domain::error::DomainError::HashMismatch { .. })
        ),
        "tampered content must fail verification: {verdict:?}"
    );
}

#[tokio::test]
async fn whole_mode_empty_object_verifies_against_empty_hash() {
    let hash_value = hash::sha256(b"");
    let inner = ok_stream(vec![]);
    let (wrapped, slot) = verify_stream(inner, 0, HashMode::WholeSha256, hash_value, None)
        .expect("valid whole-mode construction");
    let (collected, err) = drain(wrapped).await;
    assert!(collected.is_empty());
    assert_eq!(err, None);
    assert!(
        slot.lock()
            .unwrap()
            .take()
            .expect("verdict published")
            .is_ok()
    );
}

#[tokio::test]
async fn whole_mode_shorter_than_declared_size_fails_with_length_mismatch() {
    let content = b"short".to_vec();
    let hash_value = hash::sha256(&content);
    let inner = ok_stream(vec![content.clone()]);
    let (wrapped, slot) = verify_stream(
        inner,
        (content.len() + 5) as u64,
        HashMode::WholeSha256,
        hash_value,
        None,
    )
    .expect("valid whole-mode construction");
    let (_collected, err) = drain(wrapped).await;
    assert_eq!(
        err, None,
        "the wrapper itself never errors the stream on a length mismatch"
    );
    let verdict = slot.lock().unwrap().take().expect("verdict published");
    assert!(
        matches!(
            verdict,
            Err(crate::domain::error::DomainError::HashMismatch { .. })
        ),
        "an undersized stream must fail verification: {verdict:?}"
    );
}

#[tokio::test]
async fn whole_mode_longer_than_declared_size_fails_with_length_mismatch() {
    let content = b"this stream yields more bytes than declared".to_vec();
    let declared_len = 10u64; // much shorter than the real content
    let hash_value = hash::sha256(&content[..10]);
    let inner = ok_stream(vec![content.clone()]);
    let (wrapped, slot) =
        verify_stream(inner, declared_len, HashMode::WholeSha256, hash_value, None)
            .expect("valid whole-mode construction");
    let (collected, err) = drain(wrapped).await;
    assert_eq!(collected, content);
    assert_eq!(err, None);
    let verdict = slot.lock().unwrap().take().expect("verdict published");
    assert!(
        matches!(
            verdict,
            Err(crate::domain::error::DomainError::HashMismatch { .. })
        ),
        "an oversized stream must fail verification: {verdict:?}"
    );
}

#[tokio::test]
async fn whole_mode_rejects_a_manifest() {
    let err = verify_stream(
        ok_stream(vec![]),
        0,
        HashMode::WholeSha256,
        hash::sha256(b""),
        Some(
            Manifest::new(vec![ManifestEntry {
                offset: 0,
                digest: [0u8; 32],
            }])
            .unwrap(),
        ),
    )
    .map(|_| ())
    .expect_err("whole-sha256 with a manifest must be rejected");
    assert!(matches!(
        err,
        crate::domain::error::DomainError::Validation { .. }
    ));
}

#[tokio::test]
async fn composite_mode_matching_parts_verify_ok_with_chunk_boundaries_unaligned_to_parts() {
    let part1 = vec![b'a'; 100];
    let part2 = vec![b'b'; 200];
    let part3 = vec![b'c'; 50];
    let (manifest, root) = build_composite(&[&part1, &part2, &part3]);
    let mut whole = Vec::new();
    whole.extend_from_slice(&part1);
    whole.extend_from_slice(&part2);
    whole.extend_from_slice(&part3);

    // Chunk boundaries deliberately straddle part boundaries.
    let chunks = vec![
        whole[0..150].to_vec(),   // ends 50 bytes into part2
        whole[150..340].to_vec(), // ends 40 bytes into part3
        whole[340..].to_vec(),
    ];
    let inner = ok_stream(chunks);
    let (wrapped, slot) = verify_stream(
        inner,
        whole.len() as u64,
        HashMode::MultipartCompositeSha256,
        root,
        Some(manifest),
    )
    .expect("valid composite-mode construction");
    let (collected, err) = drain(wrapped).await;
    assert_eq!(collected, whole);
    assert_eq!(err, None);
    assert!(
        slot.lock()
            .unwrap()
            .take()
            .expect("verdict published")
            .is_ok(),
        "matching multipart content must verify, even with chunk boundaries crossing part boundaries"
    );
}

#[tokio::test]
async fn composite_mode_boundary_falls_mid_chunk_still_hashes_each_part_correctly() {
    let part1 = vec![1u8; 4];
    let part2 = vec![2u8; 4];
    let (manifest, root) = build_composite(&[&part1, &part2]);
    let mut whole = Vec::new();
    whole.extend_from_slice(&part1);
    whole.extend_from_slice(&part2);

    let inner = ok_stream(vec![whole.clone()]);
    let (wrapped, slot) = verify_stream(
        inner,
        whole.len() as u64,
        HashMode::MultipartCompositeSha256,
        root,
        Some(manifest),
    )
    .expect("valid composite-mode construction");
    let (collected, err) = drain(wrapped).await;
    assert_eq!(collected, whole);
    assert_eq!(err, None);
    assert!(
        slot.lock()
            .unwrap()
            .take()
            .expect("verdict published")
            .is_ok(),
        "a part boundary landing mid-chunk must still be hashed correctly per part"
    );
}

#[tokio::test]
async fn composite_mode_tampered_part_fails_verification() {
    let part1 = vec![b'x'; 30];
    let part2 = vec![b'y'; 30];
    let (manifest, root) = build_composite(&[&part1, &part2]);
    let mut tampered_part2 = part2.clone();
    tampered_part2[0] ^= 0xff;
    let mut whole = Vec::new();
    whole.extend_from_slice(&part1);
    whole.extend_from_slice(&tampered_part2);

    let inner = ok_stream(vec![whole.clone()]);
    let (wrapped, slot) = verify_stream(
        inner,
        whole.len() as u64,
        HashMode::MultipartCompositeSha256,
        root,
        Some(manifest),
    )
    .expect("valid composite-mode construction");
    let (_collected, err) = drain(wrapped).await;
    assert_eq!(err, None);
    let verdict = slot.lock().unwrap().take().expect("verdict published");
    assert!(
        matches!(
            verdict,
            Err(crate::domain::error::DomainError::HashMismatch { .. })
        ),
        "a tampered part must fail verification: {verdict:?}"
    );
}

/// Zero-byte object as a one-part composite manifest: EOF finalization of a span that got no bytes.
#[tokio::test]
async fn composite_mode_zero_byte_object_with_one_empty_part_verifies_ok() {
    let (manifest, root) = build_composite(&[&[]]);
    let inner = ok_stream(vec![]);
    let (wrapped, slot) = verify_stream(
        inner,
        0,
        HashMode::MultipartCompositeSha256,
        root,
        Some(manifest),
    )
    .expect("a single zero-length part covering a zero-byte object is a valid manifest");
    let (collected, err) = drain(wrapped).await;
    assert!(collected.is_empty());
    assert_eq!(err, None);
    assert!(
        slot.lock()
            .unwrap()
            .take()
            .expect("verdict published")
            .is_ok(),
        "a zero-byte composite object must verify against sha256(\"\") for its sole part"
    );
}

/// Zero-length trailing manifest part is legitimate; only the last entry can be empty.
#[tokio::test]
async fn composite_mode_trailing_empty_part_verifies_ok() {
    let part1 = vec![b'x'; 30];
    let (manifest, root) = build_composite(&[&part1, &[]]);

    let inner = ok_stream(vec![part1.clone()]);
    let (wrapped, slot) = verify_stream(
        inner,
        part1.len() as u64,
        HashMode::MultipartCompositeSha256,
        root,
        Some(manifest),
    )
    .expect("a trailing zero-length part is a valid manifest shape");
    let (collected, err) = drain(wrapped).await;
    assert_eq!(collected, part1);
    assert_eq!(err, None);
    assert!(
        slot.lock()
            .unwrap()
            .take()
            .expect("verdict published")
            .is_ok(),
        "a matching manifest with a trailing empty part must verify"
    );
}

/// Trailing empty part must not let a wrong root pass as a hash mismatch.
#[tokio::test]
async fn composite_mode_trailing_empty_part_with_wrong_root_fails_verification() {
    let part1 = vec![b'x'; 30];
    let (manifest, _real_root) = build_composite(&[&part1, &[]]);
    let bogus_root = vec![0xAB; 32];

    let inner = ok_stream(vec![part1.clone()]);
    let (wrapped, slot) = verify_stream(
        inner,
        part1.len() as u64,
        HashMode::MultipartCompositeSha256,
        bogus_root,
        Some(manifest),
    )
    .expect("a trailing zero-length part is a valid manifest shape");
    let (_collected, err) = drain(wrapped).await;
    assert_eq!(err, None);
    let verdict = slot.lock().unwrap().take().expect("verdict published");
    assert!(
        matches!(
            verdict,
            Err(crate::domain::error::DomainError::HashMismatch { .. })
        ),
        "a mismatched root must fail verification even with a trailing empty part: {verdict:?}"
    );
}

/// Manifest offset strictly beyond `expected_len` is rejected at construction.
#[tokio::test]
async fn composite_mode_rejects_manifest_offset_beyond_expected_len() {
    let part1 = vec![b'x'; 30];
    let (manifest, root) = build_composite(&[&part1]);
    let mut entries = manifest.entries().to_vec();
    entries.push(ManifestEntry {
        offset: part1.len() as u64 + 5,
        digest: [0u8; 32],
    });
    let manifest_out_of_range = Manifest::new(entries).expect("valid manifest shape");

    let err = verify_stream(
        ok_stream(vec![part1.clone()]),
        part1.len() as u64,
        HashMode::MultipartCompositeSha256,
        root,
        Some(manifest_out_of_range),
    )
    .map(|_| ())
    .expect_err("a manifest entry starting past expected_len must be rejected at construction");
    assert!(
        matches!(err, crate::domain::error::DomainError::HashMismatch { .. }),
        "expected HashMismatch, got {err:?}"
    );
}

/// `compare` called directly with a digest-count mismatch: `zip` alone would check only a prefix.
#[test]
fn compare_rejects_mismatched_composite_part_count() {
    let (manifest, _root) = build_composite(&[&[b'x'; 10], &[b'y'; 10]]);
    let entries = manifest.entries().to_vec();
    let spec = super::Spec::Composite { entries };
    let part_digests = vec![hash::digest_to_array(hash::sha256(b"xxxxxxxxxx"))];

    let err = super::compare(&spec, &[0u8; 32], part_digests)
        .expect_err("a part-count mismatch must fail verification, not silently zip-truncate");
    assert!(
        matches!(err, crate::domain::error::DomainError::HashMismatch { .. }),
        "expected HashMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn composite_mode_requires_a_manifest() {
    let err = verify_stream(
        ok_stream(vec![]),
        0,
        HashMode::MultipartCompositeSha256,
        vec![0u8; 32],
        None,
    )
    .map(|_| ())
    .expect_err("multipart-composite-sha256 without a manifest must be rejected");
    assert!(matches!(
        err,
        crate::domain::error::DomainError::Validation { .. }
    ));
}

#[tokio::test]
async fn inner_read_error_passes_through_and_never_publishes_a_verdict() {
    let inner: BoxStream<'static, io::Result<Bytes>> = Box::pin(stream::iter(vec![
        Ok(Bytes::from_static(b"partial")),
        Err(io::Error::new(io::ErrorKind::TimedOut, "boom")),
    ]));
    let (wrapped, slot) = verify_stream(
        inner,
        100,
        HashMode::WholeSha256,
        hash::sha256(b"irrelevant"),
        None,
    )
    .expect("valid whole-mode construction");
    let (collected, err) = drain(wrapped).await;
    assert_eq!(collected, b"partial");
    assert_eq!(err, Some(io::ErrorKind::TimedOut));
    assert!(
        slot.lock().unwrap().is_none(),
        "a stream that errors before completion must never publish a verdict"
    );
}
