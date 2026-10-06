// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! A `hashicorp/vault` dev server in Docker for the rehearsal: a KV v2 mount
//! configured the way the new plugin's docs prescribe (many versions kept, no
//! expiry, no CAS), and tokens holding the minimal ACL policy for the prefixes
//! the old and the new store use.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    reason = "test fixture: a setup failure IS the test failure"
)]

use std::fmt::Write as _;
use std::time::Duration;

use serde_json::{Value, json};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, Image, ImageExt};

/// The dev server's root token. Only the fixture's admin calls use it.
pub const ROOT_TOKEN: &str = "root";
/// The KV v2 mount the fixture creates.
pub const MOUNT: &str = "credstore-rehearsal";

/// The host port Docker mapped to the container's Vault port. Right after `start` (nothing is
/// waited for) the runtime may not have published the mapping yet, so it is asked again for a
/// few seconds before the setup fails.
async fn mapped_vault_port(container: &ContainerAsync<GenericImage>) -> u16 {
    let mut last = String::new();
    for _ in 0..100 {
        match container.get_host_port_ipv4(8200.tcp()).await {
            Ok(port) => return port,
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the container does not map the Vault port: {last}");
}

/// A running Vault dev server.
pub struct VaultServer {
    _container: ContainerAsync<GenericImage>,
    http: reqwest::Client,
    /// `http://127.0.0.1:<mapped port>`.
    pub address: String,
}

impl VaultServer {
    /// Starts the server and creates the mount; `None` when Docker is not
    /// reachable and `CREDSTORE_MIGRATION_REQUIRE_DOCKER` is not set.
    pub async fn start() -> Option<Self> {
        // The image and its tag come from `libs/test-containers`; the tag can be
        // overridden with `GEARS_TEST_VAULT_TAG`.
        let image = test_containers::vault();
        let image_ref = format!("{}:{}", image.name(), image.tag());
        let request = image
            .with_exposed_port(8200.tcp())
            .with_wait_for(WaitFor::Nothing)
            .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
            .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .with_cap_add("IPC_LOCK")
            .with_cmd(["server", "-dev"]);
        let container = match request.start().await {
            Ok(c) => c,
            Err(e) => {
                assert!(
                    std::env::var_os("CREDSTORE_MIGRATION_REQUIRE_DOCKER").is_none(),
                    "CREDSTORE_MIGRATION_REQUIRE_DOCKER is set but {image_ref} could not start: {e}"
                );
                eprintln!(
                    "SKIPPING: Docker is not reachable or {image_ref} could not be started ({e})"
                );
                return None;
            }
        };
        let port = mapped_vault_port(&container).await;
        let server = Self {
            _container: container,
            http: reqwest::Client::new(),
            address: format!("http://127.0.0.1:{port}"),
        };
        server.wait_until_ready().await;
        let (status, body) = server
            .raw(
                "POST",
                &format!("sys/mounts/{MOUNT}"),
                Some(json!({"type": "kv", "options": {"version": "2"}})),
            )
            .await;
        assert!(status < 300, "mount KV v2: {status} {body}");
        let (status, body) = server
            .raw(
                "POST",
                &format!("{MOUNT}/config"),
                Some(json!({"max_versions": 1000, "delete_version_after": "0s", "cas_required": false})),
            )
            .await;
        assert!(status < 300, "configure the mount: {status} {body}");
        Some(server)
    }

    async fn wait_until_ready(&self) {
        for _ in 0..300 {
            if let Ok(r) = self
                .http
                .get(format!("{}/v1/sys/health", self.address))
                .send()
                .await
                && r.status().is_success()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("Vault did not become healthy within 60 s");
    }

    /// A token that may use exactly the given prefixes of the mount (the minimal
    /// policy of the new plugin's docs, per prefix).
    pub async fn token_for(&self, name: &str, prefixes: &[&str]) -> String {
        let mut policy = String::new();
        for prefix in prefixes {
            write!(
                policy,
                r#"
path "{MOUNT}/data/{prefix}/*" {{ capabilities = ["create", "update", "read"] }}
path "{MOUNT}/metadata/{prefix}/*" {{ capabilities = ["read", "delete"] }}
path "{MOUNT}/destroy/{prefix}/*" {{ capabilities = ["update"] }}
"#
            )
            .unwrap();
        }
        let (status, body) = self
            .raw(
                "PUT",
                &format!("sys/policies/acl/{name}"),
                Some(json!({ "policy": policy })),
            )
            .await;
        assert!(status < 300, "write the policy: {status} {body}");
        let (status, body) = self
            .raw(
                "POST",
                "auth/token/create",
                Some(json!({"policies": [name], "no_default_policy": true, "ttl": "1h"})),
            )
            .await;
        assert!(status < 300, "create a token: {status} {body}");
        body["auth"]["client_token"].as_str().unwrap().to_owned()
    }

    /// A request with the root token; `path` is relative to `/v1/`.
    pub async fn raw(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self
            .http
            .request(
                method.parse().unwrap(),
                format!("{}/v1/{path}", self.address),
            )
            .header("X-Vault-Token", ROOT_TOKEN);
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// Version metadata of a key (`data.versions`), `Null` when the key is gone.
    pub async fn versions(&self, prefix: &str, tenant: &str, leaf: &str) -> Value {
        let (status, body) = self
            .raw(
                "GET",
                &format!("{MOUNT}/metadata/{prefix}/{tenant}/{leaf}"),
                None,
            )
            .await;
        if status == 404 {
            return Value::Null;
        }
        assert_eq!(status, 200, "{body}");
        body["data"]["versions"].clone()
    }
}
