//! Pure ETag formula, defined once for every call site.
//!
//! The content ETag is an opaque token derived from `(file_id, content_id)` via SHA-256
//! with a domain-separation prefix (a fingerprint, not a MAC). It never encodes the raw
//! content hash.

// Domain terms (ETag, If-Match) appear in doc comments.
#![allow(clippy::doc_markdown)]

use uuid::Uuid;

use file_storage_sdk::File;

use crate::infra::content::hash;

/// Quoted (`"<hex>"`) per RFC 9110 §8.8.3; the 16-byte digest prefix is enough for an
/// optimistic-concurrency token.
#[must_use]
pub fn content_etag(file_id: Uuid, content_id: Uuid) -> String {
    let digest = hash::sha256_parts(&[b"fs-etag-v1", file_id.as_bytes(), content_id.as_bytes()]);
    format!("\"{}\"", hex::encode(&digest[..16]))
}

/// Current content ETag for `file`, or `None` if no content is bound yet.
#[must_use]
pub fn etag_for(file: &File) -> Option<String> {
    file.content_id.map(|cid| content_etag(file.file_id, cid))
}

/// Whether a conditional `If-None-Match` matches `current_etag` (so a `304` applies), per
/// RFC 9110 §13.1.2: `"*"`, or a comma-separated list of entity-tags (optionally weak,
/// `W/"..."`) compared weakly. No match, or no current ETag, is never "unchanged".
/// Shared by the REST handler and the SDK local client.
#[must_use]
pub fn if_none_match_satisfied(if_none_match: Option<&str>, current_etag: Option<&str>) -> bool {
    let (Some(inm), Some(tag)) = (if_none_match, current_etag) else {
        return false;
    };
    let inm = inm.trim();
    if inm == "*" {
        return true;
    }
    split_etag_list(inm).any(|candidate| weak_tag(candidate) == weak_tag(tag))
}

/// Strip the weak-validator prefix (`W/`) for weak comparison (RFC 9110 §8.8.3.2).
#[must_use]
fn weak_tag(raw: &str) -> &str {
    raw.strip_prefix("W/").unwrap_or(raw)
}

/// Split an `If-None-Match` value into trimmed, non-empty tags on commas, except commas
/// inside a quoted tag (e.g. `"a,b"`).
#[must_use]
fn split_etag_list(list: &str) -> EtagListSplit<'_> {
    EtagListSplit { rest: list }
}

/// Iterator returned by `split_etag_list`.
struct EtagListSplit<'a> {
    rest: &'a str,
}

impl<'a> Iterator for EtagListSplit<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        while !self.rest.is_empty() {
            let mut in_quotes = false;
            let mut comma_at = None;
            for (i, c) in self.rest.char_indices() {
                match c {
                    '"' => in_quotes = !in_quotes,
                    ',' if !in_quotes => {
                        comma_at = Some(i);
                        break;
                    }
                    _ => {}
                }
            }
            let (item, rest) = match comma_at {
                Some(i) => (&self.rest[..i], &self.rest[i + 1..]),
                None => (self.rest, ""),
            };
            self.rest = rest;
            let item = item.trim();
            if !item.is_empty() {
                return Some(item);
            }
        }
        None
    }
}

#[cfg(test)]
mod etag_tests {
    use super::if_none_match_satisfied;

    #[test]
    fn wildcard_matches_any_current_etag() {
        assert!(if_none_match_satisfied(Some("*"), Some("\"abc\"")));
    }

    #[test]
    fn exact_match_is_satisfied() {
        assert!(if_none_match_satisfied(Some("\"abc\""), Some("\"abc\"")));
    }

    #[test]
    fn mismatch_is_not_satisfied() {
        assert!(!if_none_match_satisfied(Some("\"abc\""), Some("\"def\"")));
    }

    #[test]
    fn no_if_none_match_header_is_not_satisfied() {
        assert!(!if_none_match_satisfied(None, Some("\"abc\"")));
    }

    #[test]
    fn no_current_etag_is_never_satisfied_even_with_wildcard() {
        assert!(!if_none_match_satisfied(Some("*"), None));
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert!(if_none_match_satisfied(
            Some("  \"abc\"  "),
            Some("\"abc\"")
        ));
    }

    #[test]
    fn list_matches_when_any_tag_matches() {
        assert!(if_none_match_satisfied(Some("\"a\", \"b\""), Some("\"b\"")));
    }

    #[test]
    fn list_is_not_satisfied_when_no_tag_matches() {
        assert!(!if_none_match_satisfied(
            Some("\"a\", \"b\""),
            Some("\"c\"")
        ));
    }

    #[test]
    fn comma_inside_quotes_is_not_a_list_separator() {
        assert!(if_none_match_satisfied(Some("\"a,b\""), Some("\"a,b\"")));
        assert!(!if_none_match_satisfied(Some("\"a,b\""), Some("\"a\"")));
    }

    #[test]
    fn weak_validator_matches_strong_current_etag() {
        assert!(if_none_match_satisfied(Some("W/\"b\""), Some("\"b\"")));
    }

    #[test]
    fn list_with_blank_elements_and_whitespace_is_handled() {
        assert!(if_none_match_satisfied(
            Some("\"a\", , \"b\""),
            Some("\"b\"")
        ));
    }
}
