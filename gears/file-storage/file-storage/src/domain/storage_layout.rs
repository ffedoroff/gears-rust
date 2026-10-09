//! The single definition of the backend object path layout.
//!
//! A version's path is derived from `(file_id, version_id)` alone.

use uuid::Uuid;

/// Backend object path for a version's content: `/{file_id}/{version_id}`.
///
/// Computed once at version creation and persisted in `file_versions.backend_path` (and
/// `multipart_uploads.backend_path`); readers use the stored value. Recomputed only for
/// legacy sessions without that column (`MultipartUploadSession::backend_path_or_default`).
pub fn backend_path(file_id: Uuid, version_id: Uuid) -> String {
    format!("/{file_id}/{version_id}")
}

#[cfg(test)]
mod tests {
    use super::backend_path;
    use uuid::Uuid;

    #[test]
    fn formats_as_slash_file_id_slash_version_id() {
        let file_id = Uuid::from_u128(1);
        let version_id = Uuid::from_u128(2);
        assert_eq!(
            backend_path(file_id, version_id),
            "/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002"
        );
    }
}
