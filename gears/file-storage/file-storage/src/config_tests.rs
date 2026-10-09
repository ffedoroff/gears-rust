use super::*;

#[test]
fn default_max_url_ttl_is_seven_days() {
    let cfg = FileStorageConfig::default();
    assert_eq!(cfg.max_url_ttl_secs, 7 * 24 * 60 * 60);
}

#[test]
fn default_url_ttl_is_short_and_within_ceiling() {
    let cfg = FileStorageConfig::default();
    assert_eq!(cfg.default_url_ttl_secs, 15 * 60);
    assert!(
        cfg.default_url_ttl_secs <= cfg.max_url_ttl_secs,
        "default issuance TTL must not exceed the hard ceiling"
    );
}

#[test]
fn default_finalize_token_grace_is_one_hour() {
    let cfg = FileStorageConfig::default();
    assert_eq!(cfg.finalize_token_grace_secs, 3600);
}

#[test]
fn finalize_token_grace_can_be_overridden() {
    let cfg: FileStorageConfig =
        serde_json::from_str(r#"{"finalize_token_grace_secs": 0}"#).unwrap();
    assert_eq!(cfg.finalize_token_grace_secs, 0);
}

#[test]
fn default_url_ttl_can_be_overridden() {
    let cfg: FileStorageConfig = serde_json::from_str(r#"{"default_url_ttl_secs": 300}"#).unwrap();
    assert_eq!(cfg.default_url_ttl_secs, 300);
}

#[test]
fn serde_default_applies_when_field_absent() {
    let cfg: FileStorageConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(
        cfg.max_url_ttl_secs,
        FileStorageConfig::default().max_url_ttl_secs,
        "serde(default) must fall back to the Default impl"
    );
}

#[test]
fn max_url_ttl_can_be_overridden() {
    let cfg: FileStorageConfig = serde_json::from_str(r#"{"max_url_ttl_secs": 3600}"#).unwrap();
    assert_eq!(cfg.max_url_ttl_secs, 3600);
}

#[test]
fn rejects_unknown_fields() {
    let json = r#"{"max_url_ttl_secs": 60, "unexpected": true}"#;
    assert!(
        serde_json::from_str::<FileStorageConfig>(json).is_err(),
        "unknown keys must be rejected"
    );
}

fn cfg_with_secret() -> FileStorageConfig {
    FileStorageConfig {
        finalize_internal_secret: Some(SecretString::new("test-internal-secret")),
        ..FileStorageConfig::default()
    }
}

#[test]
fn removed_background_sweep_keys_are_rejected() {
    for key in [
        "enable_background_sweep",
        "sweep_interval_secs",
        "orphan_grace_secs",
        "sweep_time_budget_secs",
        "require_finalize_internal_secret",
    ] {
        let json = format!(r#"{{"{key}": 1}}"#);
        assert!(
            serde_json::from_str::<FileStorageConfig>(&json).is_err(),
            "{key} must be rejected as an unknown field"
        );
    }
}

#[test]
fn validate_rejects_missing_signing_key_seed_when_required_flag_set() {
    let cfg = FileStorageConfig {
        signing_key_seed: None,
        require_signing_key_seed: true,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "a missing signing_key_seed must be rejected when require_signing_key_seed is true"
    );
}

#[test]
fn validate_allows_missing_signing_key_seed_when_required_flag_unset() {
    let cfg = FileStorageConfig {
        signing_key_seed: None,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "a missing signing_key_seed must be allowed when require_signing_key_seed is false"
    );
}

#[test]
fn validate_allows_present_signing_key_seed_when_required_flag_set() {
    const SEED: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let cfg = FileStorageConfig {
        signing_key_seed: Some(SecretString::new(SEED)),
        require_signing_key_seed: true,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "a present signing_key_seed must pass validation even when required"
    );

    // Redaction proof: the raw seed must not appear in Debug output.
    let cfg_debug = format!("{cfg:?}");
    assert!(
        !cfg_debug.contains(SEED),
        "FileStorageConfig's Debug output must never contain the raw signing_key_seed: {cfg_debug}"
    );
}

#[test]
fn default_require_signing_key_seed_is_true() {
    assert!(
        FileStorageConfig::default().require_signing_key_seed,
        "require_signing_key_seed must default to true (secure-by-default)"
    );
}

#[test]
fn missing_finalize_internal_secret_fails_validate() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        finalize_internal_secret: None,
        ..cfg_with_secret()
    };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("finalize_internal_secret"), "{err}");
    assert!(err.contains("FS_SIDECAR_INTERNAL_TOKEN"), "{err}");

    let empty = FileStorageConfig {
        finalize_internal_secret: Some(SecretString::new("")),
        ..cfg
    };
    assert!(
        empty.validate().is_err(),
        "an empty secret must be rejected"
    );
}

#[test]
fn present_finalize_internal_secret_passes_validate_and_is_redacted() {
    const SECRET: &str = "interim-shared-secret";
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        finalize_internal_secret: Some(SecretString::new(SECRET)),
        ..cfg_with_secret()
    };
    assert!(cfg.validate().is_ok());

    // Redaction proof: the raw secret must not appear in Debug output.
    let cfg_debug = format!("{cfg:?}");
    assert!(
        !cfg_debug.contains(SECRET),
        "FileStorageConfig's Debug output must never contain the raw finalize_internal_secret: {cfg_debug}"
    );
}

#[test]
fn serde_round_trip_preserves_value() {
    let original = FileStorageConfig {
        max_url_ttl_secs: 12_345,
        ..cfg_with_secret()
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: FileStorageConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.max_url_ttl_secs, original.max_url_ttl_secs);
}

#[test]
fn config_s3_backends_serde_round_trip() {
    const SECRET: &str = "super-secret-value-do-not-print-me";

    let original = FileStorageConfig {
        s3_backends: vec![S3BackendConfig {
            id: "s3-primary".to_owned(),
            endpoint: Some("http://127.0.0.1:9000".to_owned()),
            region: "us-east-1".to_owned(),
            bucket: "my-bucket".to_owned(),
            access_key_id: Some("AKIAEXAMPLE".to_owned()),
            secret_access_key: Some(SecretString::new(SECRET)),
            path_style: true,
        }],
        ..cfg_with_secret()
    };

    let json = serde_json::to_string(&original).unwrap();
    let back: FileStorageConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(back.s3_backends.len(), 1);
    let entry = &back.s3_backends[0];
    assert_eq!(entry.id, "s3-primary");
    assert_eq!(entry.endpoint.as_deref(), Some("http://127.0.0.1:9000"));
    assert_eq!(entry.region, "us-east-1");
    assert_eq!(entry.bucket, "my-bucket");
    assert_eq!(entry.access_key_id.as_deref(), Some("AKIAEXAMPLE"));
    assert_eq!(
        entry
            .secret_access_key
            .as_ref()
            .map(toolkit_utils::SecretString::expose),
        Some(SECRET)
    );
    assert!(entry.path_style);

    // Redaction proof: the raw secret must not appear anywhere in either
    // struct's `Debug` output.
    let cfg_debug = format!("{back:?}");
    assert!(
        !cfg_debug.contains(SECRET),
        "FileStorageConfig's Debug output must never contain the raw secret_access_key: {cfg_debug}"
    );
    let entry_debug = format!("{entry:?}");
    assert!(
        !entry_debug.contains(SECRET),
        "S3BackendConfig's Debug output must never contain the raw secret_access_key: {entry_debug}"
    );
    assert!(cfg_debug.contains("<redacted>"));
}

#[test]
fn config_s3_backends_defaults_to_empty() {
    let cfg: FileStorageConfig = serde_json::from_str("{}").unwrap();
    assert!(
        cfg.s3_backends.is_empty(),
        "s3_backends must default to empty so existing configs keep parsing"
    );
}

#[test]
fn config_default_backend_id_defaults_to_none() {
    let cfg: FileStorageConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(cfg.default_backend_id, None);
}

#[test]
fn config_default_backend_id_serde_round_trip() {
    let original = FileStorageConfig {
        default_backend_id: Some("s3-primary".to_owned()),
        ..cfg_with_secret()
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: FileStorageConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.default_backend_id.as_deref(), Some("s3-primary"));
}

#[test]
fn default_multipart_session_ttl_is_24_hours() {
    let cfg = FileStorageConfig::default();
    assert_eq!(cfg.multipart_session_ttl_secs, 86400);
}

#[test]
fn multipart_session_ttl_can_be_overridden() {
    let cfg: FileStorageConfig =
        serde_json::from_str(r#"{"multipart_session_ttl_secs": 3600}"#).unwrap();
    assert_eq!(cfg.multipart_session_ttl_secs, 3600);
}

#[test]
fn validate_rejects_multipart_session_ttl_shorter_than_default_url_ttl() {
    let cfg = FileStorageConfig {
        default_url_ttl_secs: 900,
        multipart_session_ttl_secs: 300,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "multipart_session_ttl_secs shorter than default_url_ttl_secs is a direct \
         self-contradiction and must be rejected"
    );
}

#[test]
fn validate_accepts_multipart_session_ttl_equal_to_default_url_ttl() {
    let cfg = FileStorageConfig {
        default_url_ttl_secs: 900,
        multipart_session_ttl_secs: 900,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "multipart_session_ttl_secs == default_url_ttl_secs must be accepted"
    );
}

#[test]
fn default_config_passes_validation() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };

    assert!(
        cfg.multipart_session_ttl_secs > cfg.default_url_ttl_secs,
        "sanity: the stock defaults are 24h session vs 15min url ttl"
    );
    assert!(
        cfg.default_url_ttl_secs <= cfg.max_url_ttl_secs,
        "sanity: the stock defaults must not exhibit the condition this test guards against"
    );
    assert!(
        cfg.default_page_size <= cfg.max_page_size,
        "sanity: the stock defaults must not exhibit the condition this test guards against"
    );
    assert!(
        cfg.max_page_size <= MAX_PAGE_SIZE_CEILING,
        "sanity: the shipped default_max_page_size must not itself exceed the ceiling"
    );
    assert!(
        cfg.max_url_ttl_secs <= MAX_URL_TTL_CEILING,
        "sanity: the shipped default_max_url_ttl_secs must not itself exceed the ceiling"
    );
    assert!(
        cfg.multipart_session_ttl_secs <= MAX_MULTIPART_SESSION_TTL_SECS,
        "sanity: the shipped default_multipart_session_ttl_secs must not itself exceed the \
         ceiling"
    );
    assert!(
        cfg.multipart_complete_lease_secs <= MAX_MULTIPART_COMPLETE_LEASE_SECS,
        "sanity: the shipped default_multipart_complete_lease_secs must not itself exceed the \
         ceiling"
    );
    assert!(
        cfg.migrate_timeout_secs <= MAX_MIGRATE_TIMEOUT_SECS,
        "sanity: the shipped default_migrate_timeout_secs must not itself exceed the ceiling"
    );
    assert!(
        cfg.migrate_lease_margin_secs <= MAX_MIGRATE_LEASE_MARGIN_SECS,
        "sanity: the shipped default_migrate_lease_margin_secs must not itself exceed the ceiling"
    );
    assert!(
        cfg.idempotency_ttl_secs <= MAX_IDEMPOTENCY_TTL_SECS,
        "sanity: the shipped default_idempotency_ttl_secs must not itself exceed the ceiling"
    );

    assert!(
        cfg.validate().is_ok(),
        "the stock default config (module-config knobs only) must pass validation"
    );
}

#[test]
fn validate_rejects_default_url_ttl_exceeding_max_url_ttl() {
    let cfg = FileStorageConfig {
        default_url_ttl_secs: 200,
        max_url_ttl_secs: 100,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "default_url_ttl_secs exceeding max_url_ttl_secs is a direct self-contradiction \
         and must be rejected"
    );
}

#[test]
fn validate_accepts_default_url_ttl_equal_to_max_url_ttl() {
    let cfg = FileStorageConfig {
        default_url_ttl_secs: 100,
        max_url_ttl_secs: 100,
        multipart_session_ttl_secs: 100,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "default_url_ttl_secs == max_url_ttl_secs must be accepted"
    );
}

#[test]
fn validate_rejects_zero_default_url_ttl() {
    let cfg = FileStorageConfig {
        default_url_ttl_secs: 0,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "default_url_ttl_secs == 0 must be rejected"
    );
}

#[test]
fn validate_accepts_default_url_ttl_of_one() {
    let cfg = FileStorageConfig {
        default_url_ttl_secs: 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "default_url_ttl_secs == 1 must be accepted"
    );
}

#[test]
fn validate_rejects_default_page_size_exceeding_max_page_size() {
    let cfg = FileStorageConfig {
        default_page_size: 150,
        max_page_size: 100,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "default_page_size exceeding max_page_size is a direct self-contradiction \
         and must be rejected"
    );
}

#[test]
fn validate_accepts_default_page_size_equal_to_max_page_size() {
    let cfg = FileStorageConfig {
        default_page_size: 100,
        max_page_size: 100,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "default_page_size == max_page_size must be accepted"
    );
}

#[test]
fn validate_accepts_max_page_size_at_ceiling() {
    let cfg = FileStorageConfig {
        default_page_size: MAX_PAGE_SIZE_CEILING,
        max_page_size: MAX_PAGE_SIZE_CEILING,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "max_page_size == MAX_PAGE_SIZE_CEILING must be accepted"
    );
}

#[test]
fn validate_rejects_max_page_size_above_ceiling() {
    let cfg = FileStorageConfig {
        default_page_size: MAX_PAGE_SIZE_CEILING,
        max_page_size: MAX_PAGE_SIZE_CEILING + 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "max_page_size exceeding MAX_PAGE_SIZE_CEILING must be rejected regardless of what an \
         operator configures"
    );
}

// Guards the saturating `i64` conversion: an unbounded grace would become `i64::MAX` seconds.
#[test]
fn validate_accepts_finalize_token_grace_at_max() {
    let cfg = FileStorageConfig {
        finalize_token_grace_secs: MAX_FINALIZE_TOKEN_GRACE_SECS,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "finalize_token_grace_secs == MAX_FINALIZE_TOKEN_GRACE_SECS must be accepted"
    );
}

#[test]
fn validate_rejects_finalize_token_grace_above_max() {
    let cfg = FileStorageConfig {
        finalize_token_grace_secs: MAX_FINALIZE_TOKEN_GRACE_SECS + 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "finalize_token_grace_secs exceeding MAX_FINALIZE_TOKEN_GRACE_SECS must be rejected"
    );
}

#[test]
fn validate_accepts_zero_finalize_token_grace() {
    let cfg = FileStorageConfig {
        finalize_token_grace_secs: 0,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "finalize_token_grace_secs == 0 (grace disabled) must be accepted"
    );
}

#[test]
fn validate_accepts_max_url_ttl_at_ceiling() {
    let cfg = FileStorageConfig {
        max_url_ttl_secs: MAX_URL_TTL_CEILING,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "max_url_ttl_secs == MAX_URL_TTL_CEILING must be accepted"
    );
}

#[test]
fn validate_rejects_max_url_ttl_above_ceiling() {
    let cfg = FileStorageConfig {
        max_url_ttl_secs: MAX_URL_TTL_CEILING + 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "max_url_ttl_secs exceeding MAX_URL_TTL_CEILING must be rejected"
    );
}

#[test]
fn validate_accepts_multipart_session_ttl_at_ceiling() {
    let cfg = FileStorageConfig {
        multipart_session_ttl_secs: MAX_MULTIPART_SESSION_TTL_SECS,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "multipart_session_ttl_secs == MAX_MULTIPART_SESSION_TTL_SECS must be accepted"
    );
}

#[test]
fn validate_rejects_multipart_session_ttl_above_ceiling() {
    let cfg = FileStorageConfig {
        multipart_session_ttl_secs: MAX_MULTIPART_SESSION_TTL_SECS + 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "multipart_session_ttl_secs exceeding MAX_MULTIPART_SESSION_TTL_SECS must be rejected"
    );
}

#[test]
fn validate_rejects_zero_multipart_session_ttl() {
    let cfg = FileStorageConfig {
        multipart_session_ttl_secs: 0,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "multipart_session_ttl_secs == 0 must be rejected"
    );
}

#[test]
fn validate_accepts_multipart_session_ttl_of_one() {
    let cfg = FileStorageConfig {
        default_url_ttl_secs: 1,
        multipart_session_ttl_secs: 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "multipart_session_ttl_secs == 1 must be accepted"
    );
}

#[test]
fn validate_accepts_multipart_complete_lease_at_ceiling() {
    let cfg = FileStorageConfig {
        multipart_complete_lease_secs: MAX_MULTIPART_COMPLETE_LEASE_SECS,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "multipart_complete_lease_secs == MAX_MULTIPART_COMPLETE_LEASE_SECS must be accepted"
    );
}

// The lease must be bounded: an oversized value would delay another caller taking over.
#[test]
fn validate_rejects_multipart_complete_lease_above_ceiling() {
    let cfg = FileStorageConfig {
        multipart_complete_lease_secs: MAX_MULTIPART_COMPLETE_LEASE_SECS + 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "multipart_complete_lease_secs exceeding MAX_MULTIPART_COMPLETE_LEASE_SECS must be \
         rejected"
    );
}

#[test]
fn validate_rejects_zero_multipart_complete_lease() {
    let cfg = FileStorageConfig {
        multipart_complete_lease_secs: 0,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "multipart_complete_lease_secs == 0 must be rejected"
    );
}

#[test]
fn validate_accepts_multipart_complete_lease_of_one() {
    let cfg = FileStorageConfig {
        multipart_complete_lease_secs: 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "multipart_complete_lease_secs == 1 must be accepted"
    );
}

#[test]
fn validate_accepts_migrate_timeout_at_ceiling() {
    let cfg = FileStorageConfig {
        migrate_timeout_secs: MAX_MIGRATE_TIMEOUT_SECS,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "migrate_timeout_secs == MAX_MIGRATE_TIMEOUT_SECS must be accepted"
    );
}

#[test]
fn validate_rejects_migrate_timeout_above_ceiling() {
    let cfg = FileStorageConfig {
        migrate_timeout_secs: MAX_MIGRATE_TIMEOUT_SECS + 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "migrate_timeout_secs exceeding MAX_MIGRATE_TIMEOUT_SECS must be rejected"
    );
}

#[test]
fn validate_rejects_zero_migrate_timeout() {
    let cfg = FileStorageConfig {
        migrate_timeout_secs: 0,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "migrate_timeout_secs == 0 must be rejected"
    );
}

#[test]
fn validate_accepts_migrate_timeout_of_one() {
    let cfg = FileStorageConfig {
        migrate_timeout_secs: 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "migrate_timeout_secs == 1 must be accepted"
    );
}

#[test]
fn validate_accepts_migrate_lease_margin_at_ceiling() {
    let cfg = FileStorageConfig {
        migrate_lease_margin_secs: MAX_MIGRATE_LEASE_MARGIN_SECS,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "migrate_lease_margin_secs == MAX_MIGRATE_LEASE_MARGIN_SECS must be accepted"
    );
}

#[test]
fn validate_rejects_migrate_lease_margin_above_ceiling() {
    let cfg = FileStorageConfig {
        migrate_lease_margin_secs: MAX_MIGRATE_LEASE_MARGIN_SECS + 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "migrate_lease_margin_secs exceeding MAX_MIGRATE_LEASE_MARGIN_SECS must be rejected"
    );
}

#[test]
fn validate_rejects_zero_migrate_lease_margin() {
    let cfg = FileStorageConfig {
        migrate_lease_margin_secs: 0,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "migrate_lease_margin_secs == 0 must be rejected"
    );
}

#[test]
fn validate_accepts_migrate_lease_margin_of_one() {
    let cfg = FileStorageConfig {
        migrate_lease_margin_secs: 1,
        require_signing_key_seed: false,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "migrate_lease_margin_secs == 1 must be accepted"
    );
}

#[test]
fn validate_accepts_idempotency_ttl_at_ceiling() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        idempotency_ttl_secs: MAX_IDEMPOTENCY_TTL_SECS,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "idempotency_ttl_secs == MAX_IDEMPOTENCY_TTL_SECS must be accepted"
    );
}

#[test]
fn validate_rejects_idempotency_ttl_above_ceiling() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        idempotency_ttl_secs: MAX_IDEMPOTENCY_TTL_SECS + 1,
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "idempotency_ttl_secs exceeding MAX_IDEMPOTENCY_TTL_SECS must be rejected"
    );
}

#[test]
fn default_previous_signing_public_keys_is_empty() {
    assert!(
        FileStorageConfig::default()
            .previous_signing_public_keys
            .is_empty()
    );
}

#[test]
fn validate_accepts_empty_previous_signing_public_keys() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        previous_signing_public_keys: Vec::new(),
        ..cfg_with_secret()
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn validate_accepts_well_formed_previous_signing_public_keys() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let key = crate::infra::signed_url::Issuer::generate(60)
        .expect("issuer")
        .public_key();
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        previous_signing_public_keys: vec![URL_SAFE_NO_PAD.encode(key)],
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "a validly-formed (base64url, 32-byte) previous key must be accepted"
    );
}

#[test]
fn validate_rejects_non_base64_previous_signing_public_key() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        previous_signing_public_keys: vec!["not-valid-base64!!!".to_owned()],
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_err(),
        "a non-base64url entry must fail gear init, not surface lazily at the first callback"
    );
}

#[test]
fn validate_rejects_wrong_length_previous_signing_public_key() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        previous_signing_public_keys: vec![URL_SAFE_NO_PAD.encode([1, 2, 3, 4, 5, 6, 7, 8])],
        ..cfg_with_secret()
    };
    let err = cfg
        .validate()
        .expect_err("a wrong-length previous key must fail gear init");
    assert!(
        err.to_string().contains("length"),
        "error should name the length mismatch: {err}"
    );
}

fn synthetic_previous_keys(n: usize) -> Vec<String> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    (0..n)
        .map(|i| {
            let b = u8::try_from(i).expect("test count stays well within u8 range");
            URL_SAFE_NO_PAD.encode([b; 32])
        })
        .collect()
}

#[test]
fn validate_accepts_previous_signing_public_keys_at_max() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        previous_signing_public_keys: synthetic_previous_keys(
            crate::infra::signed_url::MAX_PREVIOUS_SIGNING_PUBLIC_KEYS,
        ),
        ..cfg_with_secret()
    };
    assert!(
        cfg.validate().is_ok(),
        "exactly MAX_PREVIOUS_SIGNING_PUBLIC_KEYS entries must be accepted"
    );
}

#[test]
fn validate_rejects_previous_signing_public_keys_above_max() {
    let cfg = FileStorageConfig {
        require_signing_key_seed: false,
        previous_signing_public_keys: synthetic_previous_keys(
            crate::infra::signed_url::MAX_PREVIOUS_SIGNING_PUBLIC_KEYS + 1,
        ),
        ..cfg_with_secret()
    };
    let err = cfg
        .validate()
        .expect_err("one entry over MAX_PREVIOUS_SIGNING_PUBLIC_KEYS must fail gear init");
    assert!(
        err.to_string().contains("MAX_PREVIOUS_SIGNING_PUBLIC_KEYS"),
        "error should name the exceeded ceiling: {err}"
    );
}
