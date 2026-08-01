use serde::{Deserialize, Serialize};

/// Configuration for the `users_info` gear
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsersInfoConfig {
    #[serde(default = "default_page_size")]
    pub default_page_size: u32,
    #[serde(default = "default_max_page_size")]
    pub max_page_size: u32,
    #[serde(default = "default_audit_base_url")]
    pub audit_base_url: String,
    #[serde(default = "default_notifications_base_url")]
    pub notifications_base_url: String,
}

impl Default for UsersInfoConfig {
    fn default() -> Self {
        Self {
            default_page_size: default_page_size(),
            max_page_size: default_max_page_size(),
            audit_base_url: default_audit_base_url(),
            notifications_base_url: default_notifications_base_url(),
        }
    }
}

impl UsersInfoConfig {
    /// Reject a zero `default_page_size`/`max_page_size` at config load
    /// time.
    ///
    /// `domain::service::ServiceConfig::limit_cfg` builds a
    /// `toolkit::api::odata::LimitCfg` straight from these two fields, and
    /// `LimitCfg::new` panics on a zero bound by design (see its docs) —
    /// deliberately, because a zero page-size bound is a deployment bug,
    /// not a per-request condition that should propagate as a `Result`.
    /// That panic fires wherever `limit_cfg()` is actually called
    /// (`gear.rs::init`, once per boot), so without this check a
    /// misconfigured `0` would only surface as a boot-time panic anyway —
    /// but an unlabelled one, indistinguishable from any other bug. This
    /// check turns it into a readable startup error instead. Mirrors
    /// `file_storage::config::FileStorageConfig::validate`'s identical
    /// guard for the same `LimitCfg` invariant.
    ///
    /// # Errors
    /// Returns an error naming the field(s) if `default_page_size` or
    /// `max_page_size` is `0`.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.default_page_size == 0 || self.max_page_size == 0 {
            anyhow::bail!(
                "invalid users_info config: default_page_size and max_page_size must be > 0 \
                 (got default_page_size={}, max_page_size={})",
                self.default_page_size,
                self.max_page_size
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

fn default_page_size() -> u32 {
    50
}

fn default_max_page_size() -> u32 {
    1000
}

fn default_audit_base_url() -> String {
    "http://audit.local".to_owned()
}

fn default_notifications_base_url() -> String {
    "http://notifications.local".to_owned()
}
