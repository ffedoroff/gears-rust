//! Custom-metadata queries and the atomic patch operation.

use std::collections::{HashMap, HashSet};

use time::OffsetDateTime;
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::CustomMetadataEntry;
use file_storage_sdk::CustomMetadataPatch;

use crate::domain::audit::{AuditEntry, FileEvent};
use crate::domain::error::DomainError;
use crate::infra::storage::db::{db_err, transaction_with_bounded_retry};
use crate::infra::storage::store::Store;

impl Store {
    /// List all custom-metadata entries for a file, ordered by key.
    pub async fn list_metadata(
        &self,
        file_id: Uuid,
    ) -> Result<Vec<CustomMetadataEntry>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .metadata
            .list(&conn, &AccessScope::allow_all(), file_id)
            .await
    }

    /// Batched `list_metadata` for a page of files, grouped by `file_id` (avoids N+1 queries).
    pub async fn list_metadata_for_files(
        &self,
        file_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<CustomMetadataEntry>>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .metadata
            .list_for_files(&conn, &AccessScope::allow_all(), file_ids)
            .await
    }

    /// Bump `meta_version` and apply a JSON-merge patch in a single transaction, writing the
    /// audit row and the optional `file.metadata_updated` event in the same transaction.
    ///
    /// Returns `false` (nothing written) when `expected_meta_version` does not match the
    /// current row.
    #[allow(clippy::too_many_arguments)]
    pub async fn patch_metadata_atomic(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        expected_meta_version: Option<i64>,
        patch: CustomMetadataPatch,
        now: OffsetDateTime,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<bool, DomainError> {
        let files = self.repos.files.clone();
        let metadata = self.repos.metadata.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let patch_scope = scope.clone();
        let db = self.db.db();
        // Retryable: shares the `files` row with `finalize_version`'s auto-bind and the delete
        // paths, which can invert the lock order under concurrent writers.
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let metadata = metadata.clone();
            let audit_repo = audit_repo.clone();
            let events_repo = events_repo.clone();
            let patch_scope = patch_scope.clone();
            let patch = patch.clone();
            let audit = audit.clone();
            let event = event.clone();
            Box::pin(async move {
                let Some(new_meta_version) = files
                    .touch_meta(tx, &patch_scope, file_id, expected_meta_version, now)
                    .await?
                else {
                    return Ok(false);
                };
                // Delete every touched key first (upsert semantics), then insert the `Some`
                // values in one multi-row statement. Duplicate keys in one patch must be
                // deduped (last write wins), or the multi-row insert would violate the
                // primary key.
                let all_keys = dedup_patch_keys(&patch.entries);
                metadata
                    .delete_keys(tx, &AccessScope::allow_all(), file_id, &all_keys)
                    .await?;
                let mut deduped: HashMap<&str, &str> = HashMap::new();
                for (k, v) in &patch.entries {
                    if let Some(v) = v {
                        deduped.insert(k.as_str(), v.as_str());
                    } else {
                        deduped.remove(k.as_str());
                    }
                }
                let inserts: Vec<(String, String)> = deduped
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
                metadata
                    .insert_many(tx, &AccessScope::allow_all(), file_id, &inserts, now)
                    .await?;
                audit_repo.insert(tx, &audit).await?;
                if let Some(mut ev) = event {
                    // The domain builds the event before the transaction, so the committed
                    // revision is stamped here.
                    if let Some(obj) = ev.payload.as_object_mut() {
                        obj.insert(
                            "meta_version".to_owned(),
                            serde_json::Value::from(new_meta_version),
                        );
                    }
                    events_repo.enqueue(tx, &ev).await?;
                }
                Ok::<bool, DomainError>(true)
            })
        })
        .await
    }
}

/// Distinct keys touched by a patch (set or removed), so `delete_keys` is not padded with
/// duplicates. Order is irrelevant.
fn dedup_patch_keys(entries: &[(String, Option<String>)]) -> Vec<String> {
    entries
        .iter()
        .map(|(k, _)| k.clone())
        .collect::<HashSet<String>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::dedup_patch_keys;

    #[test]
    fn dedup_patch_keys_collapses_repeated_keys() {
        let entries = vec![
            ("a".to_owned(), Some("1".to_owned())),
            ("b".to_owned(), Some("2".to_owned())),
            ("a".to_owned(), Some("3".to_owned())),
            ("a".to_owned(), None),
            ("c".to_owned(), Some("4".to_owned())),
            ("b".to_owned(), None),
        ];
        let keys = dedup_patch_keys(&entries);
        assert_eq!(
            keys.len(),
            3,
            "6 entries over 3 distinct keys ('a', 'b', 'c') must dedup to 3, not the \
             pre-dedup entry count"
        );
        let mut sorted = keys;
        sorted.sort_unstable();
        assert_eq!(sorted, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    }

    #[test]
    fn dedup_patch_keys_keeps_distinct_keys_untouched() {
        let entries = vec![
            ("a".to_owned(), Some("1".to_owned())),
            ("b".to_owned(), None),
            ("c".to_owned(), Some("3".to_owned())),
        ];
        let mut keys = dedup_patch_keys(&entries);
        keys.sort_unstable();
        assert_eq!(keys, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
    }

    #[test]
    fn dedup_patch_keys_empty_patch_yields_no_keys() {
        assert!(dedup_patch_keys(&[]).is_empty());
    }
}
