// Created: 2026-10-02 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The shipped value-fingerprint fence, reduced to what the migration needs.
//!
//! Mirrors `domain/secret/fence.rs` of the shipped gear: the fence key is
//! stored raw (32 bytes) in the legacy store under [`FENCE_KEY_REF`] (nil
//! tenant, tenant key class), and the fingerprint is
//! `HMAC-SHA256(fence_key, value)` compared in constant time.

use aws_lc_rs::hmac;

/// Reserved legacy reference of the fence key (nil tenant, owner `None`).
pub const FENCE_KEY_REF: &str = "cfs-internal-fence-key";

/// The only `fp_key_id` the shipped gear ever wrote.
pub const CURRENT_FENCE_KEY_ID: i16 = 1;

/// Constant-time check of `fp == HMAC-SHA256(key, value)`.
#[must_use]
pub fn verify_fp(key: &[u8], value: &[u8], fp: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&key, value, fp).is_ok()
}

/// `HMAC-SHA256(key, value)`; exposed for tests and fixtures.
#[must_use]
pub fn compute_fp(key: &[u8], value: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, value).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_rfc_4231_test_vector() {
        // RFC 4231, test case 1: key = 20 x 0x0b, data = "Hi There".
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(compute_fp(&[0x0b; 20], b"Hi There"), expected);
        assert!(verify_fp(&[0x0b; 20], b"Hi There", &expected));
    }

    #[test]
    fn verification_rejects_other_values_keys_and_lengths() {
        let key = [3_u8; 32];
        let fp = compute_fp(&key, b"value");
        assert!(verify_fp(&key, b"value", &fp));
        assert!(!verify_fp(&key, b"Value", &fp));
        assert!(!verify_fp(&[4_u8; 32], b"value", &fp));
        assert!(!verify_fp(&key, b"value", &fp[..31]));
        assert!(!verify_fp(&key, b"value", &[]));
    }
}
