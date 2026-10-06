Created:  2026-10-04 by Constructor Tech
Updated:  2026-10-06 by Constructor Tech

# `credstore-value-migration-v1`

The operator-facing front of the `CredStore` value migration for an installation
whose old plugin implements the **published** `CredStorePluginClientV1`
(`cf-gears-credstore-sdk` 0.2). The engine, the commands, the phases and the
exit codes are in `cf-gears-credstore-value-migration`
(`gears/credstore/credstore-value-migration`, read its README first); this crate
adds only:

* [`V1Store`] - the bridge from the published V1 contract to the engine's
  `LegacyStore`, so an out-of-tree plugin's **existing** V1 implementation plugs
  in with no adapter of the operator's own;
* [`run`] / [`run_from`] - the engine's entry points taking `Arc<dyn
  CredStorePluginClientV1>`;
* [`vault::VaultV1`] - the reference old store over Vault KV v2, used for the
  end-to-end rehearsal (see below);
* the Docker rehearsal and the bridge's tests.

It is deleted together with the engine once every installation has migrated.

## Why a separate crate outside the workspace

Depending on the published `cf-gears-credstore-sdk` 0.2 means a second version of
that package name (and, through it, registry copies of `cf-gears-toolkit`,
`cf-gears-toolkit-security`, ...) in the Cargo graph. In the root workspace that
makes every `cargo -p cf-gears-credstore-sdk` (and `make GEAR=credstore test`,
which expands to such flags) fail with "specification is ambiguous". So the
engine, which the workspace builds and tests, never sees the old SDK, and this
crate is its own workspace (like `tools/fuzz`) with its own `Cargo.lock`. Build
and test it through its manifest:

```text
cargo test   --manifest-path gears/credstore/credstore-value-migration-v1/Cargo.toml
cargo clippy --manifest-path gears/credstore/credstore-value-migration-v1/Cargo.toml --all-targets -- -D warnings
```

## The operator's binary

```no_run
use std::process::ExitCode;
use std::sync::Arc;

use credstore_sdk::CredStorePluginClientV2;
use credstore_sdk_v02::CredStorePluginClientV1;

// Your pre-ADR-0006 plugin, through its published V1 contract (it decrypts in-process).
async fn build_old_plugin() -> anyhow::Result<Arc<dyn CredStorePluginClientV1>> {
    anyhow::bail!("construct your old plugin here, with the deployment's own configuration")
}

// Your new plugin, constructed directly (no `ClientHub`) with the SAME configuration the
// new gear will use: a different mount, prefix or key makes the copy useless. For the Vault /
// OpenBao plugin of this repository that is `vault_credstore_plugin::client_from_config(&cfg)`
// (the plugin's own validation, no request to Vault); see `examples/migrate.rs`.
async fn build_new_plugin() -> anyhow::Result<Arc<dyn CredStorePluginClientV2>> {
    anyhow::bail!("construct your new plugin here")
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let old = build_old_plugin().await?;
    let new = build_new_plugin().await?;
    credstore_value_migration_v1::run(old, new).await
}
```

Depend on this crate (by path or git, it is not published), the current
`cf-gears-credstore-sdk` (the V2 contract) and your plugins; your old plugin keeps
compiling against the published SDK, which Cargo unifies with the one this crate
uses (`cf-gears-credstore-sdk` 0.2.17 or a compatible 0.2). `examples/migrate.rs`
is a compilable skeleton: a placeholder for the old plugin, and the new store built
with `cf-gears-vault-credstore-plugin`'s public `client_from_config`. The old plugin is only called through `get` (verify and
copy) and `delete` (`cleanup`).

The calls carry the tool's fixed service identity in the old contract's
`SecurityContext`. A `ServiceUnavailable` answer is transient (retried with a
bounded backoff), `NotFound` is read as an absent entry, anything else aborts the
run (exit `1`). A reference the old SDK's `SecretRef` rejects never reaches the
plugin: it aborts the run naming the row.

## Reference old store for Vault

[`vault::VaultV1`] is a `CredStorePluginClientV1` over Vault KV v2, the reference
old store of the rehearsal. **No such plugin shipped in this repository**; a real
installation brings its own. Layout: the value, base64 in the field `value`, at
`{mount}/data/{prefix}/{tenant_id}/{reference}` for the tenant key class and
`{mount}/data/{prefix}/{tenant_id}/{reference}/owner/{owner_id}` for the owner
class; the latest KV version is the current value (V1 overwrites in place); the
fence key at tenant `00000000-0000-0000-0000-000000000000`, reference
`cfs-internal-fence-key`; `delete` removes the key with all versions
(`DELETE .../metadata/...`, a missing key is success). Token authentication.

## Tests

```text
cargo test --manifest-path gears/credstore/credstore-value-migration-v1/Cargo.toml
CREDSTORE_MIGRATION_REQUIRE_DOCKER=1 cargo test \
    --manifest-path gears/credstore/credstore-value-migration-v1/Cargo.toml -- --ignored
```

The default run covers the bridge (addressing, error classification, an invalid
reference) and the whole tool through a V1 plugin written the way an out-of-tree
one would be, over `SQLite`. The ignored tests need Docker: the rehearsal on real
services - the old Vault layout written through [`vault::VaultV1`], shipped rows
with real fingerprints in a `PostgreSQL` container, `migrate` into the real
`cf-gears-vault-credstore-plugin` (built with its public `client_from_config`, as an
operator's binary builds it), every credential read back by the pointer in
`PostgreSQL`, then `cleanup`; and the same on a shared mount and prefix, where
`cleanup` refuses the old address that is a new key.

The Vault image and its tag come from `test_containers::vault()`
(`libs/test-containers`); another Vault release is tried with
`GEARS_TEST_VAULT_TAG=<tag>`.
