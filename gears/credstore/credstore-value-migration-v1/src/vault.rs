// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! A `CredStorePluginClientV1` over Vault / `OpenBao` KV v2: the reference OLD
//! store of this tool.
//!
//! **No such plugin shipped in this repository.** This is the layout the
//! rehearsal writes and the migration reads; a real installation brings its own
//! old plugin. Everything here is deleted with the tool.
//!
//! # Layout
//!
//! | Entry | KV v2 data path |
//! |---|---|
//! | tenant key class (`owner_id = None`) | `{mount}/data/{prefix}/{tenant_id}/{reference}` |
//! | owner (private) key class (`owner_id = Some(o)`) | `{mount}/data/{prefix}/{tenant_id}/{reference}/owner/{o}` |
//! | the shipped gear's fence key | tenant `00000000-0000-0000-0000-000000000000`, reference `cfs-internal-fence-key`, tenant key class |
//!
//! * The value is the base64 text in the field `value` of the secret.
//! * V1 overwrites in place: the **latest KV version is the current value**;
//!   `put` writes a new KV version, `get` reads the latest one.
//! * `delete` removes the key with every version (`DELETE .../metadata/...`);
//!   an absent key is success.
//! * Authentication is a Vault token, held in the configuration.
//!
//! The old tenant layout is the same shape as the new store's key
//! `{prefix}/{tenant_id}/{record_id}`: on one mount with one prefix, an old
//! reference that is a UUID equal to a record id IS a new key. That is what
//! `cleanup` refuses to delete.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use credstore_sdk_v02::{
    CredStoreError, CredStorePluginClientV1, OwnerId, SecretRef, SecretValue, TenantId,
};
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use reqwest::{Client, Method};
use serde_json::{Value, json};
use toolkit_security_v02::SecurityContext;

/// Settings of [`VaultV1`].
#[derive(Clone)]
pub struct VaultV1Config {
    /// Base URL of the server, e.g. `http://127.0.0.1:8200`.
    pub address: String,
    /// Vault token.
    pub token: String,
    /// KV v2 mount point.
    pub mount: String,
    /// Path segment under the mount that holds the entries.
    pub path_prefix: String,
    /// Optional namespace (`X-Vault-Namespace`).
    pub namespace: Option<String>,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl VaultV1Config {
    /// A configuration with a ten-second timeout and no namespace.
    #[must_use]
    pub fn new(
        address: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        path_prefix: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            token: token.into(),
            mount: mount.into(),
            path_prefix: path_prefix.into(),
            namespace: None,
            timeout: Duration::from_secs(10),
        }
    }
}

impl fmt::Debug for VaultV1Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultV1Config")
            .field("address", &self.address)
            .field("token", &"<redacted>")
            .field("mount", &self.mount)
            .field("path_prefix", &self.path_prefix)
            .field("namespace", &self.namespace)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// The reference old store over Vault KV v2 (see the module docs).
pub struct VaultV1 {
    http: Client,
    cfg: VaultV1Config,
}

impl fmt::Debug for VaultV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultV1")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl VaultV1 {
    /// Builds the client; performs no I/O.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be built.
    pub fn new(cfg: VaultV1Config) -> anyhow::Result<Self> {
        let http = Client::builder().timeout(cfg.timeout).build()?;
        Ok(Self { http, cfg })
    }

    /// `{mount}/{kind}/{prefix}/{tenant}/{reference}[/owner/{owner}]`, relative
    /// to `/v1/`; `kind` is `data` or `metadata`.
    fn path(
        &self,
        kind: &str,
        tenant: &TenantId,
        key: &SecretRef,
        owner: Option<&OwnerId>,
    ) -> String {
        let base = format!(
            "{}/{kind}/{}/{}/{}",
            self.cfg.mount,
            self.cfg.path_prefix,
            tenant.0,
            key.as_ref()
        );
        match owner {
            Some(owner) => format!("{base}/owner/{owner}"),
            None => base,
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
    ) -> Result<(u16, String), CredStoreError> {
        let url = format!("{}/v1/{path}", self.cfg.address.trim_end_matches('/'));
        let mut token = HeaderValue::from_str(&self.cfg.token).map_err(|_| {
            CredStoreError::internal("vault: the token is not a valid header value")
        })?;
        token.set_sensitive(true);
        let mut request = self
            .http
            .request(method, url)
            .header("X-Vault-Token", token);
        if let Some(namespace) = &self.cfg.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        // The client error's text can embed the URL: report only that it failed.
        let response = request
            .send()
            .await
            .map_err(|_| CredStoreError::service_unavailable("vault: request failed"))?;
        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|_| CredStoreError::service_unavailable("vault: response unreadable"))?;
        Ok((status, text))
    }
}

/// Reads the value out of a KV v2 read response; `None` when the version has no
/// data (soft-deleted).
fn decode_value(body: &str) -> Result<Option<Vec<u8>>, CredStoreError> {
    let parsed: Value = serde_json::from_str(body)
        .map_err(|_| CredStoreError::internal("vault: response is not JSON"))?;
    let secret = &parsed["data"]["data"];
    if secret.is_null() {
        return Ok(None);
    }
    let encoded = secret["value"]
        .as_str()
        .ok_or_else(|| CredStoreError::internal("vault: the entry has no `value` field"))?;
    BASE64
        .decode(encoded)
        .map(Some)
        .map_err(|_| CredStoreError::internal("vault: the entry is not valid base64"))
}

/// Whether a `404` body is a plain miss (`{"errors":[]}`, or soft-deleted data)
/// rather than a missing mount (a non-empty `errors` list).
fn is_plain_miss(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .is_none_or(|v| v["errors"].as_array().is_none_or(Vec::is_empty))
}

/// Maps a status that is not a success to the V1 error.
fn failure(status: u16) -> CredStoreError {
    match status {
        403 => CredStoreError::AccessDenied,
        408 | 429 | 500..=599 => {
            CredStoreError::service_unavailable(format!("vault: HTTP status {status}"))
        }
        other => CredStoreError::internal(format!("vault: unexpected HTTP status {other}")),
    }
}

#[async_trait]
impl CredStorePluginClientV1 for VaultV1 {
    async fn get(
        &self,
        _ctx: &SecurityContext,
        tenant_id: &TenantId,
        key: &SecretRef,
        owner_id: Option<&OwnerId>,
    ) -> Result<Option<SecretValue>, CredStoreError> {
        let path = self.path("data", tenant_id, key, owner_id);
        let (status, body) = self.call(Method::GET, &path, None).await?;
        match status {
            200 => Ok(decode_value(&body)?.map(SecretValue::new)),
            404 if is_plain_miss(&body) => Ok(None),
            404 => Err(CredStoreError::internal(
                "vault: not found with errors (is the mount configured?)",
            )),
            other => Err(failure(other)),
        }
    }

    async fn put(
        &self,
        _ctx: &SecurityContext,
        tenant_id: &TenantId,
        key: &SecretRef,
        value: SecretValue,
        owner_id: Option<&OwnerId>,
    ) -> Result<(), CredStoreError> {
        let path = self.path("data", tenant_id, key, owner_id);
        let body = json!({ "data": { "value": BASE64.encode(value.as_bytes()) } }).to_string();
        let (status, _) = self.call(Method::POST, &path, Some(body)).await?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(failure(status))
        }
    }

    async fn delete(
        &self,
        _ctx: &SecurityContext,
        tenant_id: &TenantId,
        key: &SecretRef,
        owner_id: Option<&OwnerId>,
    ) -> Result<(), CredStoreError> {
        let path = self.path("metadata", tenant_id, key, owner_id);
        let (status, _) = self.call(Method::DELETE, &path, None).await?;
        if (200..300).contains(&status) || status == 404 {
            Ok(())
        } else {
            Err(failure(status))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn client() -> VaultV1 {
        VaultV1::new(VaultV1Config::new("http://v:8200/", "tok", "kv", "old")).unwrap()
    }

    #[test]
    fn paths_follow_the_documented_layout() {
        let v = client();
        let tenant = TenantId(Uuid::from_u128(7));
        let key = SecretRef::new("db-password").unwrap();
        let owner = OwnerId(Uuid::from_u128(9));
        assert_eq!(
            v.path("data", &tenant, &key, None),
            format!("kv/data/old/{}/db-password", Uuid::from_u128(7))
        );
        assert_eq!(
            v.path("metadata", &tenant, &key, Some(&owner)),
            format!(
                "kv/metadata/old/{}/db-password/owner/{}",
                Uuid::from_u128(7),
                Uuid::from_u128(9)
            )
        );
        let fence = TenantId(Uuid::nil());
        let fence_key = SecretRef::new("cfs-internal-fence-key").unwrap();
        assert_eq!(
            v.path("data", &fence, &fence_key, None),
            "kv/data/old/00000000-0000-0000-0000-000000000000/cfs-internal-fence-key"
        );
    }

    #[test]
    fn values_decode_and_soft_deleted_data_is_a_miss() {
        let body =
            json!({"data": {"data": {"value": BASE64.encode(b"\x00secret\xff")}}}).to_string();
        assert_eq!(
            decode_value(&body).unwrap(),
            Some(b"\x00secret\xff".to_vec())
        );
        let soft_deleted = json!({"data": {"data": null, "metadata": {"deletion_time": "x"}}});
        assert_eq!(decode_value(&soft_deleted.to_string()).unwrap(), None);
        for bad in [
            "not json".to_owned(),
            json!({"data": {"data": {"other": "x"}}}).to_string(),
            json!({"data": {"data": {"value": "!!!"}}}).to_string(),
        ] {
            assert!(decode_value(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_not_found_with_errors_is_a_missing_mount_not_a_miss() {
        assert!(is_plain_miss(r#"{"errors":[]}"#));
        assert!(is_plain_miss(""));
        assert!(!is_plain_miss(r#"{"errors":["no handler for route"]}"#));
    }

    #[test]
    fn statuses_map_to_the_v1_errors() {
        assert!(matches!(failure(403), CredStoreError::AccessDenied));
        for transient in [408, 429, 500, 503] {
            assert!(matches!(
                failure(transient),
                CredStoreError::ServiceUnavailable { .. }
            ));
        }
        assert!(matches!(failure(400), CredStoreError::Internal(_)));
    }

    #[test]
    #[allow(
        clippy::use_debug,
        reason = "the point of the test is the Debug output"
    )]
    fn the_token_never_shows_in_debug_output() {
        let secret = "hvs.super-secret-token-value";
        let v = VaultV1::new(VaultV1Config::new("http://v:8200", secret, "kv", "old")).unwrap();
        let text = format!("{v:?}");
        assert!(!text.contains(secret), "{text}");
        assert!(text.contains("<redacted>"));
    }
}
