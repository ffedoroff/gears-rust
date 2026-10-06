// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The decision about one `active` row: what the old store held, checked
//! against the fingerprint the shipped gear stored.

use credstore_sdk::SecretValue;

use crate::fence::{self, CURRENT_FENCE_KEY_ID};
use crate::state::{ProgressRow, RowState};

/// What becomes of one `active` row.
///
/// A row that is copied carries the value to copy, so there is no copyable
/// verdict without one.
#[derive(Debug)]
pub enum Verdict {
    /// The value is copied. `verified`: its fingerprint matched; otherwise the
    /// row carried no fingerprint (seeded out of band, served on trust by the
    /// shipped gear) and nothing could be verified.
    Copy {
        /// Whether a fingerprint was checked.
        verified: bool,
        /// What the old store returned.
        value: SecretValue,
    },
    /// The old store holds no value.
    Missing,
    /// The value failed the fingerprint check.
    FpMismatch,
    /// The fingerprint names a fence key the tool does not have.
    UnknownFenceKey,
}

impl Verdict {
    /// The state a row ends up in.
    #[must_use]
    pub fn state(&self) -> RowState {
        match self {
            Self::Copy { verified: true, .. } => RowState::Copied,
            Self::Copy {
                verified: false, ..
            } => RowState::UnverifiedCopied,
            Self::Missing => RowState::Missing,
            Self::FpMismatch => RowState::FpMismatch,
            Self::UnknownFenceKey => RowState::UnknownFenceKey,
        }
    }
}

/// Decides one row from the value the old store returned (`None` when absent)
/// and the old fence key (`None` when the store holds none).
///
/// The order mirrors the shipped gear: an absent value is `Missing` whatever
/// the fingerprint says; a row without a fingerprint is copied unverified; a
/// fingerprint that names another `fp_key_id` than the shipped one, or whose
/// fence key is not there to check it with, cannot be verified; otherwise
/// `HMAC-SHA256(fence_key, value)` must equal the fingerprint (constant-time
/// comparison).
///
/// The phases load the fence key with `load_fence_key` first, which stops the
/// run when the key is absent while a `pending` row carries a fingerprint: no
/// row of a run reaches the "no fence key" case, and if one ever did it would be
/// reported as not verifiable, never copied.
#[must_use]
pub fn judge(row: &ProgressRow, value: Option<SecretValue>, fence_key: Option<&[u8]>) -> Verdict {
    let Some(value) = value else {
        return Verdict::Missing;
    };
    let Some(fp) = row.value_fp.as_deref() else {
        return Verdict::Copy {
            verified: false,
            value,
        };
    };
    let (Some(CURRENT_FENCE_KEY_ID), Some(key)) = (row.fp_key_id, fence_key) else {
        return Verdict::UnknownFenceKey;
    };
    if fence::verify_fp(key, value.as_bytes(), fp) {
        Verdict::Copy {
            verified: true,
            value,
        }
    } else {
        Verdict::FpMismatch
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::fence::compute_fp;

    const KEY: [u8; 32] = [9; 32];

    fn row(fp: Option<Vec<u8>>, key_id: Option<i16>) -> ProgressRow {
        ProgressRow {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            reference: "k".to_owned(),
            sharing: 2,
            owner_id: Uuid::nil(),
            status_before: 2,
            secret_type_uuid: Uuid::nil(),
            value_fp: fp,
            fp_key_id: key_id,
            state: RowState::Pending,
            value_version: None,
            activated: false,
            tidied: false,
        }
    }

    fn judged(r: &ProgressRow, value: Option<&[u8]>, key: Option<&[u8]>) -> Verdict {
        judge(r, value.map(|v| SecretValue::new(v.to_vec())), key)
    }

    #[test]
    fn a_matching_fingerprint_is_copied_verified() {
        let r = row(Some(compute_fp(&KEY, b"v")), Some(1));
        let verdict = judged(&r, Some(b"v"), Some(&KEY));
        assert!(
            matches!(&verdict, Verdict::Copy { verified: true, value } if value.as_bytes() == b"v"),
            "expected a verified copy of the value, got {verdict:?}"
        );
        assert_eq!(verdict.state(), RowState::Copied);
    }

    #[test]
    fn a_different_value_or_key_is_a_mismatch() {
        let r = row(Some(compute_fp(&KEY, b"v")), Some(1));
        // (what differs, the value judged, the byte the fence key is made of)
        let cases: Vec<(&str, &str, u8)> =
            vec![("another value", "w", KEY[0]), ("another key", "v", 1)];
        for (what, value, key_byte) in cases {
            let verdict = judged(&r, Some(value.as_bytes()), Some(&[key_byte; 32]));
            assert!(
                matches!(verdict, Verdict::FpMismatch),
                "{what}: expected a mismatch, got {verdict:?}"
            );
            assert_eq!(verdict.state(), RowState::FpMismatch, "{what}");
        }
    }

    #[test]
    fn a_truncated_fingerprint_is_a_mismatch() {
        let r = row(Some(vec![1, 2, 3]), Some(1));
        let verdict = judged(&r, Some(b"v"), Some(&KEY));
        assert!(
            matches!(verdict, Verdict::FpMismatch),
            "expected a mismatch, got {verdict:?}"
        );
        assert_eq!(verdict.state(), RowState::FpMismatch);
    }

    #[test]
    fn no_fingerprint_is_copied_unverified_even_without_a_fence_key() {
        let r = row(None, None);
        let verdict = judged(&r, Some(b"v"), None);
        assert!(
            matches!(&verdict, Verdict::Copy { verified: false, value } if value.as_bytes() == b"v"),
            "expected an unverified copy of the value, got {verdict:?}"
        );
        assert_eq!(verdict.state(), RowState::UnverifiedCopied);
    }

    #[test]
    fn an_absent_value_is_missing_before_anything_else() {
        let r = row(Some(compute_fp(&KEY, b"v")), Some(2));
        let verdict = judged(&r, None, None);
        assert!(
            matches!(verdict, Verdict::Missing),
            "expected Missing, got {verdict:?}"
        );
        assert_eq!(verdict.state(), RowState::Missing);
    }

    #[test]
    fn another_fence_key_id_cannot_be_verified() {
        let r = row(Some(compute_fp(&KEY, b"v")), Some(2));
        let verdict = judged(&r, Some(b"v"), Some(&KEY));
        assert!(
            matches!(verdict, Verdict::UnknownFenceKey),
            "expected UnknownFenceKey, got {verdict:?}"
        );
        assert_eq!(verdict.state(), RowState::UnknownFenceKey);
    }

    #[test]
    fn a_fingerprint_without_a_fence_key_is_never_copied() {
        let r = row(Some(compute_fp(&KEY, b"v")), Some(1));
        let verdict = judged(&r, Some(b"v"), None);
        assert!(
            matches!(verdict, Verdict::UnknownFenceKey),
            "expected UnknownFenceKey, got {verdict:?}"
        );
        assert_eq!(verdict.state(), RowState::UnknownFenceKey);
    }
}
