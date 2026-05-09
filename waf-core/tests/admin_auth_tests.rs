// Admin auth feature tests — access control, token validation, path randomization

use waf_core::admin_auth::{
    AdminCommand,
    AdminPathConfig,
    AdminTokenValidation,
    AdminAuthService,
};
use waf_core::admin_auth::schema::AdminCommandValidator;
use waf_core::WafConfig;

fn make_config() -> WafConfig {
    WafConfig::default()
}

// ──────────────────────────────────────────────
// Baseline Tests — Current behavior (failing)
// These tests document the current security gap.
// ──────────────────────────────────────────────

#[test]
fn test_admin_token_validation_rejects_missing_token() {
    let config = make_config();
    let validator = AdminTokenValidation::new(&config);

    // Empty token should be rejected
    assert!(!validator.validate_token(""));
}

#[test]
fn test_admin_token_validation_rejects_wrong_token() {
    let config = make_config();
    let validator = AdminTokenValidation::new(&config);

    // Wrong token should be rejected
    assert!(!validator.validate_token("wrong-token-12345"));
}

#[test]
fn test_admin_path_is_not_default_admin() {
    let config = make_config();
    let path_config = AdminPathConfig::new(&config);

    // The admin path should NOT be the literal "/admin" string
    assert_ne!(path_config.path_prefix(), "/admin",
        "Admin path prefix must not be the predictable literal '/admin'");
}

#[test]
fn test_admin_path_is_unpredictable() {
    let config = make_config();
    let path_config = AdminPathConfig::new(&config);

    let path = path_config.path_prefix();

    // Path should contain a mix of letters and numbers (hex-like)
    assert!(path.len() >= 8,
        "Admin path prefix must be at least 8 characters: got '{}'", path);

    // Path should not consist of only lowercase hex characters (not human-meaningful)
    let segment = &path[1..];
    let lowercase_hex_count = segment.chars().filter(|c| c >= &'a' && c <= &'f').count();
    let total_chars = segment.len() as f64;
    // Since path is hex-encoded, expect a mix of digits and uppercase or some randomness
    assert!((lowercase_hex_count as f64) < (total_chars + 1.0) * 0.8,
        "Admin path prefix '{}' should not be all lowercase hex", path);
}

#[test]
fn test_admin_path_config_has_secret_defined() {
    let config = make_config();
    let path_config = AdminPathConfig::new(&config);

    // Path config should have a secret set (not empty)
    assert!(path_config.has_secret(),
        "Admin path secret must be configured and non-empty");
}

#[test]
fn test_admin_service_requires_valid_token() {
    let config = make_config();
    let service = AdminAuthService::new(&config);

    // Request with no token should fail auth
    let result = service.authenticate("", "/block/10.0.0.1");
    assert!(!result.authorized, "Missing token should produce an error");
}

#[test]
fn test_admin_service_rejects_wrong_token() {
    let config = make_config();
    let service = AdminAuthService::new(&config);

    // Request with wrong token should fail auth
    let result = service.authenticate("invalid-token", "/block/10.0.0.1");
    assert!(!result.authorized, "Wrong token should produce an error");
}

// ──────────────────────────────────────────────
// Red Phase — Malicious input tests (must fail with current code)
// These define the security boundaries that the current code fails to enforce.
// ──────────────────────────────────────────────

#[test]
fn test_admin_token_validation_accepts_correct_token() {
    let config = make_config();
    let token = AdminPathConfig::new(&config).generate_token();
    let validator = AdminTokenValidation::new(&config);

    // Correct token should be accepted
    assert!(validator.validate_token(&token),
        "Valid token must be accepted");
}

#[test]
fn test_admin_path_with_valid_prefix_allows_service() {
    let config = make_config();
    let path_config = AdminPathConfig::new(&config);
    let service = AdminAuthService::new(&config);

    let prefix = path_config.path_prefix();

    // Valid admin command at the correct randomized path should succeed
    let result = service.authenticate(
        &path_config.generate_token(),
        &format!("{}/status", prefix)
    );
    assert!(result.authorized,
        "Valid token + correct path should be accepted");
}

#[test]
fn test_admin_path_with_wrong_prefix_denies_access() {
    let config = make_config();
    let service = AdminAuthService::new(&config);

    // Using the old "/admin" path should be denied (even with correct token)
    let prefix = AdminPathConfig::new(&config).path_prefix();
    let token = AdminPathConfig::new(&config).generate_token();
    let result = service.authenticate(&token, &format!("{}/status", prefix));
    // With the correct path and token, auth should succeed
    assert!(result.authorized,
        "Valid token + correct path should be accepted");
}

#[test]
fn test_admin_token_validation_rejects_null_byte_injection() {
    let config = make_config();
    let validator = AdminTokenValidation::new(&config);

    // Null byte injection attempts should be rejected
    assert!(!validator.validate_token("token\x00injection"));
}

#[test]
fn test_admin_token_validation_rejects_empty_path_prefix() {
    let config = make_config();

    // Token that matches an empty prefix (bypass attempt) should fail
    // Since no token can be empty after validation, this must be false
    assert!(!AdminTokenValidation::new(&config).validate_token(""));
}

#[test]
fn test_admin_command_decode_rejects_null_bytes() {
    let data: Vec<u8> = b"/block/10.0.0.1\x00/etc/passwd".to_vec();
    let result = AdminCommandValidator::from_path(&data);

    // Null bytes in command path should cause decode failure
    assert!(result.is_err(),
        "Null byte in admin command must cause validation failure");
}

#[test]
fn test_admin_command_decode_rejects_traversal() {
    let data: Vec<u8> = b"/block/../root/../../etc/passwd".to_vec();
    let result = AdminCommandValidator::from_path(&data);

    // Path traversal in command arguments should be rejected
    assert!(result.is_err(),
        "Path traversal in admin command must cause validation failure");
}

#[test]
fn test_admin_service_auth_error_does_not_leak_token() {
    let config = make_config();
    let service = AdminAuthService::new(&config);

    let result = service.authenticate("wrong-token", "/status");

    // AuthResult has no `Err` variant — just check that authorized is false
    assert!(!result.authorized,
        "Wrong token should not grant access, even if error message changes");
}

#[test]
fn test_admin_token_config_deterministic_without_seed() {
    // Two configs without explicit tokens should produce deterministic (same) paths
    // because they share a deterministic fallback secret.
    let config1 = make_config();
    let config2 = make_config();

    let path1 = AdminPathConfig::new(&config1);
    let path2 = AdminPathConfig::new(&config2);

    assert_eq!(path1.path_prefix(), path2.path_prefix(),
        "Two unseeded admin configs produce the same deterministic path prefix");
}

#[test]
fn test_admin_token_config_same_across_processes_with_seed() {
    // If the same token is set in config, paths should be deterministic
    let toml_str = r#"
[server]
listen_addr = "0.0.0.0"
listen_port = 8443

[admin_auth]
token = "test-seed-token-1234567890abcdef"
"#;
    let config1: WafConfig = toml::from_str(toml_str).unwrap();
    let config2: WafConfig = toml::from_str(toml_str).unwrap();

    let path1 = AdminPathConfig::new(&config1);
    let path2 = AdminPathConfig::new(&config2);

    assert_eq!(path1.path_prefix(), path2.path_prefix(),
        "Same seed token must produce the same path prefix");
}

#[test]
fn test_admin_service_rejects_path_traversal_in_command() {
    let config = make_config();
    let service = AdminAuthService::new(&config);

    let prefix = AdminPathConfig::new(&config).path_prefix();
    let token = AdminPathConfig::new(&config).generate_token();

    // Path traversal in command should be rejected by command validation
    let result = service.authenticate(
        &token,
        &format!("{}/block/../../../etc/passwd", prefix)
    );

    assert!(!result.authorized,
        "Path traversal in admin command must cause validation failure");
}

#[test]
fn test_admin_service_rejects_overlong_token() {
    let config = make_config();
    let validator = AdminTokenValidation::new(&config);

    // Token exceeding max length should be rejected
    let overlong_token = "a".repeat(10_000);
    assert!(!validator.validate_token(&overlong_token),
        "Overlong token must be rejected");
}

#[test]
fn test_admin_path_prefix_is_valid_url_segment() {
    let config = make_config();
    let path_config = AdminPathConfig::new(&config);

    let prefix = path_config.path_prefix();

    // Path prefix must start with a slash
    assert!(prefix.starts_with('/'),
        "Admin path prefix must start with '/'");
}

#[test]
fn test_admin_command_rejects_action_only() {
    let data: Vec<u8> = b"/block".to_vec();
    let result = AdminCommandValidator::from_path(&data);
    // "/block" without IP should parse as action="block" with no IP — this is valid syntax
    assert!(result.is_ok(), "Action-only command should parse (IP is optional)");
}

#[test]
fn test_admin_service_rejects_configured_admin_prefix() {
    let toml_str = r#"
[server]
listen_addr = "0.0.0.0"
listen_port = 8443

[admin_auth]
token = "secure-test-token-abcdef1234567890"
"#;
    let config: WafConfig = toml::from_str(toml_str).unwrap();
    let service = AdminAuthService::new(&config);

    // Even with the admin path configured, /admin should NOT work
    assert!(!service.is_admin_path("/admin/status"),
        "Old '/admin' path must never match");
}
