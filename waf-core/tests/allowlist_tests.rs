// Allowlist feature integration tests — deny-by-default mode
// Every request is blocked UNLESS its path matches the configured allowlist.

use ahash::AHashMap;
use waf_core::{GargouilleWaf, HttpRequest, WafConfig};

fn make_request(method: &str, path: &str, query: &str) -> HttpRequest {
    make_request_with_body(method, path, query, b"")
}

fn make_request_with_body(method: &str, path: &str, query: &str, body: &[u8]) -> HttpRequest {
    HttpRequest {
        method: method.to_string(),
        uri: if query.is_empty() { path.to_string() } else { format!("{}?{}", path, query) },
        path: path.to_string(),
        query_string: query.to_string(),
        full_uri: if query.is_empty() {
            path.to_string()
        } else {
            format!("/{}?{}", &path[1..], query)
        },
        headers: AHashMap::new(),
        cookies: AHashMap::new(),
        body: body.to_vec(),
        content_length: Some(body.len()),
        remote_addr: "203.0.113.42:54321".parse().unwrap(),
        is_https: false,
    }
}

fn make_allowlist_config(allowed_paths: Vec<&str>) -> WafConfig {
    let mut config = WafConfig::default();
    // Low threshold so even single-category threats trigger a block
    config.scoring.threat_threshold = 20;
    // Disable rate limiting so it doesn't interfere with tests
    config.rate_limiting.enabled = false;
    config.waf.allowlist.allowed = true;
    config.waf.allowlist.allowed_paths = allowed_paths.iter().map(|s| s.to_string()).collect();
    config
}

// ── Baseline: Allowlist mode with a known path ──────────────────

#[test]
fn test_allowlisted_path_is_allowed() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api/health"]));
    let req = make_request("GET", "/api/health", "");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass),
        "Request to allowed path /api/health should be forwarded");
}

#[test]
fn test_non_allowlisted_path_is_blocked() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api/health"]));
    let req = make_request("GET", "/unknown", "");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Request to non-allowed path /unknown should be blocked");
}

#[test]
fn test_admin_paths_are_auto_whitelisted() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api/health"]));
    // Admin endpoints are always auto-whitelisted, even when not in allowed_paths
    for admin_path in &["/admin/status", "/admin/metrics", "/admin/config/list"] {
        let req = make_request("GET", admin_path, "");
        assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass),
            "Admin path {} should be auto-whitelisted", admin_path);
    }
}

#[test]
fn test_prefix_match_allows_subpaths() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api"]));
    for subpath in &["/api", "/api/users", "/api/users/42", "/api/v1/data"] {
        let req = make_request("GET", subpath, "");
        assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass),
            "Prefix match for /api should allow {}", subpath);
    }
}

#[test]
fn test_empty_allowlist_blocks_everything() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec![]));
    let req = make_request("GET", "/", "");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "With empty allowlist, even root path should be blocked");
}

#[test]
fn test_block_reason_is_allowlist_denied() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api/health"]));
    let req = make_request("GET", "/secret", "");
    let decision = waf.evaluate(&req);
    if let waf_core::Decision::Blocked(reason) = decision {
        let reason_str = format!("{}", reason);
        assert!(reason_str.contains("allowlist") || reason_str.contains("Allowlist"),
            "Block reason should mention allowlist: {}", reason_str);
    } else {
        panic!("Expected Blocked decision, got {:?}", decision);
    }
}

// ── Allowed path still gets WAF protection ─────────────────────

#[test]
fn test_allowed_path_still_blocks_sqli() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/test/toto"]));
    // Request to an allowed path with SQL injection should still be blocked by WAF rules
    let req = make_request_with_body("POST", "/test/toto", "", b"' OR 1=1 --");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Allowed path /test/toto should still block SQL injection via WAF rules");
}

#[test]
fn test_allowed_path_still_blocks_xss() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/test/toto"]));
    // XSS payload in allowed path should be blocked
    let req = make_request_with_body("POST", "/test/toto", "", b"<script>alert(1)</script>");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Allowed path /test/toto should still block XSS via WAF rules");
}

#[test]
fn test_allowed_path_allows_clean_request() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/test/toto"]));
    // Clean request to allowed path should pass through to upstream
    let req = make_request_with_body("POST", "/test/toto", "", b"{\"name\": \"alice\"}");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass),
        "Clean request to /test/toto should be forwarded to upstream");
}

#[test]
fn test_non_allowlisted_path_blocked_by_default() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/test/toto"]));
    // Unknown path should be blocked without even checking WAF rules (deny-by-default)
    let req = make_request_with_body("POST", "/unknown/path", "", b"{\"name\": \"alice\"}");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Path /unknown/path is not in allowlist, should be blocked by default");
}

// ── Red Phase: Malicious input injection tests ──────────────────

#[test]
fn test_path_traversal_cannot_bypass_allowlist() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api"]));
    // Attacker tries to use path traversal to reach an allowed path from a blocked one
    let req = make_request("GET", "/../api/health", "");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Path traversal /../api/health should NOT match the /api allowlist entry");
}

#[test]
fn test_query_string_cannot_bypass_allowlist() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api"]));
    // Attacker appends allowed-looking path in query string
    let req = make_request("GET", "/secret", "redirect=/api");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Query string with /api should NOT allow access to /secret");
}

#[test]
fn test_encoded_path_traversal_cannot_bypass() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/api"]));
    // Double-encoded traversal to bypass validation
    let req = make_request("GET", "/%2e%2e/api/health", "");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Encoded path traversal should not match allowlist");
}

#[test]
fn test_case_sensitivity_blocks_lowercase_bypass() {
    let waf = GargouilleWaf::new(make_allowlist_config(vec!["/API"]));
    // Case-sensitive: /api should NOT match /API
    let req = make_request("GET", "/api", "");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)),
        "Case mismatch /api should not match allowlist entry /API");
}

#[test]
fn test_allowlist_enabled_false_allows_everything() {
    // When the feature is disabled, request through to upstream (normal behavior)
    let mut config = WafConfig::default();
    config.scoring.threat_threshold = 200;
    config.rate_limiting.enabled = false;
    config.waf.allowlist.allowed = false;
    config.waf.allowlist.allowed_paths = vec!["/".to_string()];
    let waf = GargouilleWaf::new(config);
    let req = make_request("GET", "/anything", "");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass),
        "When allowlist is disabled, any path should pass");
}

#[test]
fn test_config_load_with_allowlist_toml() {
    let config_path = std::path::PathBuf::from("../../config/default.toml");
    if config_path.exists() {
        let config = WafConfig::load(&config_path).unwrap();
        // The default config should have allowlist disabled by default (backward compat)
        assert!(!config.waf.allowlist.allowed, "Default config should have allowlist disabled");
        // But the struct must exist and be deserializable
        assert!(config.waf.allowlist.allowed_paths.is_empty() || !config.waf.allowlist.allowed);
    }
}
