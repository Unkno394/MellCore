use honeyforge_backend::config::{Config, IntegrationMode};

fn config(values: &[(&str, &str)]) -> Result<Config, honeyforge_backend::config::ConfigError> {
    Config::from_lookup(|key| {
        Ok(values
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.to_string()))
    })
}

#[test]
fn defaults_are_local_with_documentation_disabled() {
    let config = config(&[]).unwrap();
    assert!(config.bind.ip().is_loopback());
    assert!(!config.docs_enabled);
    assert_eq!(config.integration_mode, IntegrationMode::Mock);
    assert_eq!(config.telemetry.retention_days, 30);
}

#[test]
fn refuses_public_documentation_until_authentication_exists() {
    for bind in ["0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080"] {
        assert_eq!(
            config(&[("API_BIND", bind), ("DOCS_ENABLED", "true")])
                .unwrap_err()
                .key,
            "DOCS_ENABLED"
        );
    }
    assert!(config(&[("API_BIND", "[::1]:8080"), ("DOCS_ENABLED", "true")]).is_ok());
}

#[test]
fn rejects_invalid_or_unbounded_settings_without_echoing_input() {
    for (key, value) in [
        ("API_BIND", "secret-token"),
        ("DOCS_ENABLED", "yes"),
        ("TELEMETRY_MAX_BATCH_EVENTS", "0"),
        ("TELEMETRY_MAX_BATCH_EVENTS", "10001"),
        ("HTTP_MAX_BODY_BYTES", "-1"),
        ("RETENTION_DAYS", "0"),
        ("TELEMETRY_MAX_EVENT_AGE_SECONDS", "0"),
        ("INTEGRATION_MODE", "typo"),
    ] {
        let error = config(&[(key, value)]).unwrap_err();
        assert_eq!(error.key, key);
        assert!(!error.to_string().contains("secret-token"));
    }
}

#[test]
fn payload_limits_cannot_exceed_http_body_limit() {
    assert_eq!(
        config(&[("HTTP_MAX_BODY_BYTES", "1024")]).unwrap_err().key,
        "TELEMETRY_MAX_PAYLOAD_BYTES"
    );
    assert!(
        config(&[
            ("HTTP_MAX_BODY_BYTES", "1024"),
            ("TELEMETRY_MAX_PAYLOAD_BYTES", "512"),
            ("TELEMETRY_MAX_METADATA_BYTES", "128")
        ])
        .is_ok()
    );
}

#[test]
fn real_mode_is_recognized_but_never_silently_replaced_with_mock() {
    assert_eq!(
        config(&[("INTEGRATION_MODE", "real")])
            .unwrap()
            .integration_mode,
        IntegrationMode::Real
    );
}

#[test]
fn non_unicode_environment_is_an_error() {
    let error = Config::from_lookup(|key| {
        Err(honeyforge_backend::config::ConfigError {
            key,
            reason: "must contain valid Unicode",
        })
    })
    .unwrap_err();
    assert_eq!(error.key, "API_BIND");
}

#[test]
fn frontend_origin_paths_and_smtp_tls_are_explicit_and_secrets_redacted() {
    let cfg = config(&[
        ("FRONTEND_URL", "http://localhost:5173/"),
        ("FRONTEND_RESET_PATH", "/auth/reset"),
        ("FRONTEND_VERIFY_PATH", "/auth/verify"),
    ])
    .unwrap();
    assert_eq!(cfg.app_origin, "http://localhost:5173");
    assert_eq!(cfg.frontend_url, "http://localhost:5173");
    assert_eq!(cfg.frontend_reset_path, "/auth/reset");
    assert!(!cfg.require_email_verification);
    for (key, value) in [
        ("FRONTEND_URL", "https://user:secret@example.com"),
        ("FRONTEND_URL", "https://example.com?token=secret"),
        ("FRONTEND_URL", "https://example.com/subpath"),
        ("FRONTEND_RESET_PATH", "//attacker.example"),
        ("FRONTEND_VERIFY_PATH", "/verify#token=secret"),
        ("REQUIRE_EMAIL_VERIFICATION", "yes"),
    ] {
        let error = config(&[(key, value)]).unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }
    let smtp = config(&[
        ("SMTP_HOST", "smtp.example.test"),
        ("SMTP_USERNAME", "account"),
        ("SMTP_PASSWORD", "never-log-smtp-secret"),
        ("SMTP_FROM", "noreply@example.test"),
        ("SMTP_TLS_MODE", "starttls"),
        ("SMTP_PORT", "587"),
    ])
    .unwrap();
    assert!(smtp.smtp.as_ref().unwrap().starttls);
    assert_eq!(smtp.smtp.as_ref().unwrap().port, 587);
    assert!(!format!("{smtp:?}").contains("never-log"));
}
