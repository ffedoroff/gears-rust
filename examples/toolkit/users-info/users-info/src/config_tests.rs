//! Unit tests for [`super::UsersInfoConfig::validate`].
//!
//! `domain::service::ServiceConfig::limit_cfg` builds a `LimitCfg` directly
//! from `default_page_size`/`max_page_size` and `LimitCfg::new` panics on a
//! zero bound. `gear.rs::init` calls `limit_cfg()` once per boot, so a zero
//! here would otherwise surface as an unlabelled startup panic instead of a
//! readable config error.

use super::UsersInfoConfig;

#[test]
fn validate_accepts_default_config() {
    UsersInfoConfig::default()
        .validate()
        .expect("the serde-default config must be valid");
}

#[test]
fn validate_rejects_zero_page_size_bounds() {
    for (default_page_size, max_page_size) in [(0, 100), (25, 0), (0, 0)] {
        let cfg = UsersInfoConfig {
            default_page_size,
            max_page_size,
            ..UsersInfoConfig::default()
        };
        assert!(
            cfg.validate().is_err(),
            "default_page_size={default_page_size}, max_page_size={max_page_size} \
             must be rejected: a zero bound panics in LimitCfg::new at boot"
        );
    }
}

#[test]
fn validate_accepts_positive_bounds_even_when_default_exceeds_max() {
    // `default > max` is not this check's concern: `resolve_page_size`
    // clamps the default down to `max` at call time, which is a coherent
    // outcome, not a panic — only a zero bound panics in `LimitCfg::new`.
    let cfg = UsersInfoConfig {
        default_page_size: 500,
        max_page_size: 100,
        ..UsersInfoConfig::default()
    };
    cfg.validate()
        .expect("default > max is not rejected by this guard");
}
