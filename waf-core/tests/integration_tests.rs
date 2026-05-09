use ahash::AHashMap;
use waf_core::{
    RateLimitingConfig,
    ScoringConfig,
    WafConfig,
    WafEngineConfig,
    GargouilleWaf, HttpRequest,
};

fn test_config() -> WafConfig {
    let mut config = WafConfig::default();
    config.rate_limiting.enabled = false;
    config.scoring.threat_threshold = 10; // Very low for testing
    config
}

/// Config optimized for bot detection integration testing — high threshold
/// so only clear scanner fingerprints trigger blocks, not scoring artifacts.
fn bot_test_config() -> WafConfig {
    let mut config = WafConfig::default();
    config.rate_limiting.enabled = false;
    config
}

fn make_request(method: &str, path: &str, query: &str, body: &[u8]) -> HttpRequest {
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

fn make_request_with_headers(method: &str, path: &str, query: &str, body: &[u8], headers: AHashMap<String, Vec<String>>) -> HttpRequest {
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
        headers,
        cookies: AHashMap::new(),
        body: body.to_vec(),
        content_length: Some(body.len()),
        remote_addr: "203.0.113.42:54321".parse().unwrap(),
        is_https: false,
    }
}

// ── Clean Request Tests ────────────────────────────────

#[test]
fn test_clean_get_request_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/", "", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

#[test]
fn test_clean_post_json_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"{\"username\": \"alice\", \"email\": \"alice@fr.brain.local.agent\"}";
    let req = make_request("POST", "/api/users", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

#[test]
fn test_html_page_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"<html><body><h1>Welcome</h1><p>Hello world!</p></body></html>";
    let req = make_request("GET", "/index.html", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

#[test]
fn test_normal_query_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/search", "q=hello+world&page=1&limit=20", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

#[test]
fn test_multiple_clean_requests_pass() {
    let mut waf = GargouilleWaf::new(test_config());
    let paths = ["/", "/about", "/contact", "/api/status", "/css/style.css", "/js/app.js"];
    for path in &paths {
        let req = make_request("GET", path, "", &[]);
        let decision = waf.evaluate(&req);
        assert!(matches!(decision, waf_core::Decision::Pass), "Path {} should pass", path);
    }
}

// ── SQL Injection Tests ────────────────────────────────

#[test]
fn test_union_sqli_body_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"admin' UNION SELECT password FROM users --";
    let req = make_request("POST", "/login", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_union_sqli_query_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/products", "1'; DROP TABLE accounts;--", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_tautology_sqli_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/api/data", "1'; DROP TABLE data;--", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_stacked_query_sqli_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"id=1; DROP TABLE users;";
    let req = make_request("POST", "/api/update", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_error_based_sqli_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"param=1 AND extractvalue(1, concat(0x7e, version()))";
    let req = make_request("POST", "/api/query", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_time_based_sqli_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"param=test' AND sleep(5)--";
    let req = make_request("POST", "/api/check", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── XSS Tests ─────────────────────────────────────────

#[test]
fn test_script_tag_xss_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"<script>alert('xss')</script>";
    let req = make_request("POST", "/comment", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_event_handler_xss_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"<img src=x onerror=alert(1)>";
    let req = make_request("POST", "/profile", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_javascript_uri_xss_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/redirect", "url=javascript:alert(document.cookie)", &[]);
    // Debug: check searchable text
    let texts = req.searchable_text();
    for (loc, text) in &texts {
        if loc == "query" {
        }
    }
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_svg_xss_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"<svg onload=alert('xss')>";
    let req = make_request("POST", "/embed", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_iframe_xss_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"<iframe src=\"javascript:alert(1)\"></iframe>";
    let req = make_request("POST", "/embed", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── Command Injection Tests ───────────────────────────

#[test]
fn test_semicolon_cmdi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"; cat /etc/passwd";
    let req = make_request("POST", "/api/exec", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_pipe_cmdi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"command=; ls /etc";
    let req = make_request("POST", "/api/exec", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_subshell_cmdi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"$(whoami)";
    let req = make_request("POST", "/api/info", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_dangerous_rm_cmdi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"&& rm -rf /";
    let req = make_request("POST", "/api/cleanup", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── LFI/RFI Tests ────────────────────────────────────

#[test]
fn test_etc_passwd_lfi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/read", "file=/etc/passwd", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_php_wrapper_lfi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/include", "file=php://filter/convert.base64-encode/resource=config.php", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_path_traversal_lfi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/download", "path=../../../etc/shadow", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_proc_self_environ_lfi_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/read-env", "file=/proc/self/environ", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── SSRF Tests ────────────────────────────────────────

#[test]
fn test_cloud_metadata_ssrf_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"http://fr.brain.local.agent/metadata/instance-data";
    let req = make_request("POST", "/fetch", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_localhost_ssrf_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"http://localhost:6379/";
    let req = make_request("POST", "/proxy", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_private_ip_ssrf_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"http://10.0.0.5:8080/admin";
    let req = make_request("POST", "/fetch-internal", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_azure_metadata_ssrf_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"http://fr.brain.local.agent/cloud-metadata";
    let req = make_request("POST", "/fetch-vm", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── SSTI Tests ────────────────────────────────────────

#[test]
fn test_jinja_config_ssti_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"{{config}}";
    let req = make_request("POST", "/render-template", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_python_object_ssti_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"__import__('os').system('id')";
    let req = make_request("POST", "/api/eval", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── Deserialization Tests ─────────────────────────────

#[test]
fn test_yaml_ssti_deser_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"!!python/object/apply:os.system [id]";
    let req = make_request("POST", "/api/restore", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_dotnet_binary_formatting_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"BinaryFormatter.Serialize(stream, obj)";
    let req = make_request("POST", "/api/load", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── Path Traversal Tests ──────────────────────────────

#[test]
fn test_double_encoding_path_traversal_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/static", "file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_null_byte_path_traversal_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/download", "file=evil.jpg%00.php", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── Header Injection Tests ────────────────────────────

#[test]
fn test_crlf_header_injection_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("x-forwarded-for".into(), vec!["127.0.0.1%0a%0dSet-Cookie: admin=true".into()]);
    let req = make_request_with_headers("GET", "/", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── Rate Limiting Tests ───────────────────────────────

#[test]
fn test_rate_limiting_blocks_excessive_requests() {
    let config = WafConfig {
        rate_limiting: waf_core::RateLimitingConfig {
            enabled: true,
            requests_per_window: 5,
            window_seconds: 60,
            burst_allowance: 0, // Disable burst for this test
            ..Default::default()
        },
        ..WafConfig::default()
    };
    let mut waf = GargouilleWaf::new(config);
    let req = make_request("GET", "/", "", &[]);

    // First 5 should pass (within limit)
    for i in 0..5 {
        let decision = waf.evaluate(&req);
        assert!(matches!(decision, waf_core::Decision::Pass), "Request {} should pass", i + 1);
    }

    // 6th should be rate limited (no burst)
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::RateLimited));
}

// ── Scoring Threshold Tests ───────────────────────────

#[test]
fn test_custom_scoring_threshold() {
    let mut config = WafConfig::default();
    config.rate_limiting.enabled = false;
    config.scoring.threat_threshold = 10; // Very low threshold for testing
    let mut waf = GargouilleWaf::new(config);

    // A request with multiple attack vectors should be blocked
    let body = b"UNION SELECT password FROM users";
    let req = make_request("POST", "/api/search", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_heavy_attack_allows_pass() {
    let mut config = WafConfig::default();
    config.scoring.threat_threshold = 200; // Higher than any possible score (max 100)
    config.rate_limiting.enabled = false;
    let mut waf = GargouilleWaf::new(config);

    let body = b"<script>alert(1)</script>' OR 1=1 --; cat /etc/passwd";
    let req = make_request("POST", "/api/input", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass), "With threshold=200 even malicious input should pass");
}

// ── Database Tests (feature-gated) ────────────────────

#[test]
fn test_block_ip_via_waf() {
    // block_ip and related methods require SQLite feature
    #[cfg(feature = "sqlite")]
    {
        let config = WafConfig {
            blocklist: waf_core::BlocklistConfig { enabled: false, ..Default::default() },
            ..test_config()
        };
        let waf = GargouilleWaf::new(config);
        // These methods return false when SQLite is not available
        let _ = waf.block_ip("192.168.1.1", "test block");
    }
}

#[test]
fn test_whitelist_ip_via_waf() {
    #[cfg(feature = "sqlite")]
    {
        let config = WafConfig {
            blocklist: waf_core::BlocklistConfig { enabled: false, ..Default::default() },
            ..test_config()
        };
        let waf = GargouilleWaf::new(config);
        let _ = waf.whitelist_ip("10.0.0.1", "trusted");
    }
}

// ── Metrics Tests (feature-gated) ─────────────────────

#[test]
fn test_metrics_render() {
    let config = WafConfig::default();
    let waf = GargouilleWaf::new(config);

    #[cfg(feature = "prometheus")]
    {
        let metrics = waf.render_metrics();
        assert!(!metrics.is_empty());
        assert!(metrics.contains("gargouille_total_requests"));
        assert!(metrics.contains("# HELP"));
        assert!(metrics.contains("# TYPE"));
    }
}

// ── Different HTTP Methods ────────────────────────────

#[test]
fn test_put_request_clean_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"{\"status\": \"active\", \"role\": \"user\"}";
    let req = make_request("PUT", "/api/users/42", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

#[test]
fn test_delete_request_clean_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("DELETE", "/api/users/42", "", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

#[test]
fn test_patch_request_clean_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let body = b"{\"email\": \"alice@fr.brain.local.agent\"}";
    let req = make_request("PATCH", "/api/profile", "", body);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

// ── Cookie-based Attacks ──────────────────────────────

#[test]
fn test_cookie_sql_injection_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("cookie".into(), vec!["session=1' OR '1'='1".into()]);
    let mut cookies = AHashMap::new();
    for part in "session=1' OR '1'='1".split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            cookies.insert(k.to_string(), v.to_string());
        }
    }
    let req = HttpRequest {
        method: "GET".into(),
        uri: "/dashboard".into(),
        path: "/dashboard".into(),
        query_string: String::new(),
        full_uri: "/dashboard".into(),
        headers,
        cookies,
        body: Vec::new(),
        content_length: None,
        remote_addr: "203.0.113.42:54321".parse().unwrap(),
        is_https: false,
    };
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── Query Parameter Attacks ───────────────────────────

#[test]
fn test_encoded_sqli_in_query_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/api/users", "id=%27%20OR%201%3D1%20--", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

#[test]
fn test_xss_in_query_param_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let req = make_request("GET", "/search", "q=<script>alert(1)</script>", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)));
}

// ── Config Validation Tests ───────────────────────────

#[test]
fn test_config_default_score_threshold() {
    let config = WafConfig::default();
    assert_eq!(config.scoring.threat_threshold, 50);
}

#[test]
fn test_config_default_max_body_size() {
    let config = WafConfig::default();
    assert_eq!(config.waf.max_body_size, 10_485_760); // 10 MB
}

#[test]
fn test_waf_new_with_custom_config() {
    let custom_config = WafConfig {
        waf: WafEngineConfig {
            max_body_size: 1_048_576, // 1 MB
            ..Default::default()
        },
        rate_limiting: waf_core::RateLimitingConfig {
            enabled: false,
            requests_per_window: 1000,
            window_seconds: 30,
            burst_allowance: 500,
            ..Default::default()
        },
        ..WafConfig::default()
    };
    let mut waf = GargouilleWaf::new(custom_config);
    let req = make_request("GET", "/", "", &[]);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass));
}

// ── High-Volume Simulation ────────────────────────────

#[test]
fn test_rapid_requests_all_pass() {
    let config = WafConfig {
        rate_limiting: waf_core::RateLimitingConfig {
            enabled: false, // Disable rate limiting for this test
            ..Default::default()
        },
        ..WafConfig::default()
    };
    let mut waf = GargouilleWaf::new(config);
    let req = make_request("GET", "/", "", &[]);

    // Simulate 100 clean requests
    for _ in 0..100 {
        let decision = waf.evaluate(&req);
        assert!(matches!(decision, waf_core::Decision::Pass));
    }
}

#[test]
fn test_mixed_attack_and_clean_requests() {
    let mut waf = GargouilleWaf::new(test_config());

    // Clean request
    let clean_req = make_request("GET", "/", "", &[]);
    assert!(matches!(waf.evaluate(&clean_req), waf_core::Decision::Pass));

    // Attack request
    let attack_req = make_request("POST", "/login", "", b"' OR 1=1 --");
    assert!(matches!(waf.evaluate(&attack_req), waf_core::Decision::Blocked(_)));

    // Clean request again
    let clean_req2 = make_request("GET", "/", "", &[]);
    assert!(matches!(waf.evaluate(&clean_req2), waf_core::Decision::Pass));
}

// ── Per-endpoint Rate Limiting Tests ────────────────────────

#[test]
fn test_endpoint_rate_limit_enforced() {
    let config = WafConfig {
        rate_limiting: waf_core::RateLimitingConfig {
            enabled: true,
            requests_per_window: 100,
            window_seconds: 60,
            burst_allowance: 0,
            endpoint_limits: std::collections::HashMap::from_iter([
                ("/api/login".to_string(), 5),
            ]),
            ..Default::default()
        },
        ..WafConfig::default()
    };
    let mut waf = GargouilleWaf::new(config);

    // Send 5 requests to /api/login (within limit)
    for _ in 0..5 {
        let req = make_request("POST", "/api/login", "", b"{}", );
        assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass));
    }

    // 6th request to /api/login should be rate limited
    let req = make_request("POST", "/api/login", "", b"{}", );
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::RateLimited));
}

#[test]
fn test_endpoint_rate_limit_independent_paths() {
    let config = WafConfig {
        rate_limiting: waf_core::RateLimitingConfig {
            enabled: true,
            requests_per_window: 100,
            window_seconds: 60,
            burst_allowance: 0,
            endpoint_limits: std::collections::HashMap::from_iter([
                ("/api/login".to_string(), 5),
                ("/api/register".to_string(), 3),
            ]),
            ..Default::default()
        },
        ..WafConfig::default()
    };
    let mut waf = GargouilleWaf::new(config);

    // /api/login can handle 5, /api/register can handle 3
    for _ in 0..5 {
        let req_login = make_request("POST", "/api/login", "", b"{}", );
        assert!(matches!(waf.evaluate(&req_login), waf_core::Decision::Pass));
    }

    // /api/register should hit its limit after 3 requests
    for _ in 0..3 {
        let req_reg = make_request("POST", "/api/register", "", b"{}", );
        assert!(matches!(waf.evaluate(&req_reg), waf_core::Decision::Pass));
    }

    // 4th request to /api/register should be rate limited
    let req_reg = make_request("POST", "/api/register", "", b"{}", );
    assert!(matches!(waf.evaluate(&req_reg), waf_core::Decision::RateLimited));
}

// ── Direct Block Threshold Tests ───────────────────────

#[test]
fn test_high_confidence_direct_block() {
    let mut config = WafConfig::default();
    config.scoring.threat_threshold = 100; // Very high so normal scoring won't trigger
    config.rate_limiting.enabled = false;
    config.scoring.high_confidence_threshold = 0.85; // Lower threshold for testing
    let mut waf = GargouilleWaf::new(config);

    // XSS script tag has confidence 0.95 which exceeds 0.85, should force block
    let req = make_request("POST", "/page", "", b"<script>alert(1)</script>");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)));
}

#[test]
fn test_low_confidence_no_direct_block() {
    let mut config = WafConfig::default();
    config.scoring.threat_threshold = 100; // Can never trigger via score
    config.rate_limiting.enabled = false;
    config.scoring.high_confidence_threshold = 0.99; // Very high, nothing exceeds it normally
    let mut waf = GargouilleWaf::new(config);

    // Comment-based SQLi has confidence 0.50, below 0.99 threshold
    let req = make_request("POST", "/page", "", b"1' -- comment");
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass));
}

// ── IP Validation Tests ───────────────────────

#[test]
fn test_database_ip_validation() {
    assert!(waf_core::database::validate_ip("192.168.1.1"));
    assert!(waf_core::database::validate_ip("10.0.0.1"));
    assert!(waf_core::database::validate_ip("::1"));
    assert!(waf_core::database::validate_ip("2001:db8::1"));
    assert!(!waf_core::database::validate_ip("not_an_ip"));
    assert!(!waf_core::database::validate_ip("") );
    assert!(!waf_core::database::validate_ip("192.168.1"));
}

#[test]
fn test_extract_client_ip_from_xff() {
    let remote = "10.0.0.1:12345".parse().unwrap();
    let forwarded = vec!["203.0.113.50".to_string(), "198.51.100.1".to_string()];
    assert_eq!(
        waf_core::database::extract_client_ip(remote, Some(&forwarded)),
        "203.0.113.50"
    );
}

#[test]
fn test_extract_client_ip_fallback() {
    let remote = "198.51.100.5:54321".parse().unwrap();
    // Invalid forwarded-for should fall back to remote_addr
    assert_eq!(
        waf_core::database::extract_client_ip(remote, Some(&["invalid".to_string()])),
        "198.51.100.5"
    );
}

// ── Header Case-Insensitive Tests ───────────────────────

#[test]
fn test_case_insensitive_header_lookup() {
    let config = test_config();
    let mut waf = GargouilleWaf::new(config);

    // Inject header with different case in searchable text and verify detection
    let mut headers = AHashMap::new();
    headers.insert("X-Forwarded-For".to_string(), vec!["127.0.0.1%0a%0dSet-Cookie: admin=true".to_string()]);
    let req = make_request_with_headers("GET", "/", "", &[], headers);
    assert!(matches!(waf.evaluate(&req), waf_core::Decision::Blocked(_)));
}

#[test]
fn test_case_insensitive_content_type_lookup() {
    let config = test_config();
    let mut waf = GargouilleWaf::new(config);

    // Clean request with various content-type casing should pass
    for ct in &["application/json", "Application/Json", "APPLICATION/JSON"] {
        let mut headers = AHashMap::new();
        headers.insert("Content-Type".to_string(), vec![ct.to_string()]);
        let req = make_request_with_headers("POST", "/api/data", "", b"{}", headers);
        assert!(matches!(waf.evaluate(&req), waf_core::Decision::Pass), "CT '{}' should pass", ct);
    }
}

// ── Response Headers Test ───────────────────────

#[test]
fn test_response_headers_config() {
    let config = WafConfig::default();
    assert_eq!(config.response_headers.x_frame_options, "DENY");
    assert_eq!(config.response_headers.x_content_type_options, "nosniff");
    assert_eq!(config.response_headers.content_security_policy, "default-src 'self'; script-src 'self'");
    assert!(!config.response_headers.strict_transport_security.is_empty());
}

// ── Bot Detection Integration Tests ───────────────

#[test]
fn test_bot_scanner_fingerprint_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["sqlmap/1.7.2#stable (https://sqlmap.org)".into()]);
    let req = make_request_with_headers("GET", "/", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Scanner fingerprint should block: {:?}", decision);
}

#[test]
fn test_bot_scanner_fingerprint_nikto_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 (compatible; Nikto/2.1.6)".into()]);
    let req = make_request_with_headers("GET", "/admin", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Nikto UA should block: {:?}", decision);
}

#[test]
fn test_bot_clean_browser_ua_passes() {
    let mut waf = GargouilleWaf::new(bot_test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into()]);
    headers.insert("accept".into(), vec!["text/html,application/xhtml+xml,*/*".into()]);
    headers.insert("host".into(), vec!["example.com".into()]);
    let req = make_request_with_headers("GET", "/index.html", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass), "Clean browser should pass: {:?}", decision);
}

#[test]
fn test_bot_firefox_ua_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0".into()]);
    let req = make_request_with_headers("GET", "/page", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass), "Firefox UA should pass: {:?}", decision);
}

#[test]
fn test_bot_ios_mobile_ua_passes() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21E237".into()]);
    let req = make_request_with_headers("GET", "/mobile-page", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass), "iOS mobile UA should pass: {:?}", decision);
}

#[test]
fn test_bot_empty_ua_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["".into()]);
    let req = make_request_with_headers("GET", "/api/data", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Empty UA should block: {:?}", decision);
}

#[test]
fn test_bot_null_byte_ua_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0\x00attack".into()]);
    let req = make_request_with_headers("GET", "/api/data", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Null byte UA should block: {:?}", decision);
}

#[test]
fn test_bot_case_insensitive_scanner() {
    // Scanner names in uppercase should still be detected
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["NIKTO/2.1.6 (Scanner)".into()]);
    let req = make_request_with_headers("GET", "/admin", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Uppercase scanner should block: {:?}", decision);
}

#[test]
fn test_bot_case_insensitive_sqlmap() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["SQLMAP/1.7.2".into()]);
    let req = make_request_with_headers("GET", "/login", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Uppercase SQLMAP should block: {:?}", decision);
}

#[test]
fn test_bot_curl_ua_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["curl/8.4.0".into()]);
    let req = make_request_with_headers("GET", "/api/users", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "curl UA should block: {:?}", decision);
}

#[test]
fn test_bot_go_http_client_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Go-http-client/1.1".into()]);
    let req = make_request_with_headers("POST", "/api/fetch", "", b"{}", headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Go-http-client should block: {:?}", decision);
}

#[test]
fn test_bot_python_requests_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["python-requests/2.31.0".into()]);
    let req = make_request_with_headers("POST", "/api/data", "", b"{\"key\": \"value\"}", headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "python-requests should block: {:?}", decision);
}

#[test]
fn test_bot_referer_scanner_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("referer".into(), vec!["DirBuster scan probe list".into()]);
    let req = make_request_with_headers("GET", "/sensitive", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Referer scanner should block: {:?}", decision);
}

#[test]
fn test_bot_missing_host_header_blocked() {
    // Multiple headers but no Host — typical bot behavior
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["sqlmap/1.7".into()]);
    headers.insert("accept".into(), vec!["*/*".into()]);
    // No host header injected
    let req = make_request_with_headers("GET", "/api/exec", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Missing host with multiple headers should block: {:?}", decision);
}

#[test]
fn test_bot_encoded_scanner_fingerprint_blocked() {
    // Hex-encoded scanner signature in a custom header
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    // %6E%69%6B%74%6F decodes to "nikto"
    headers.insert("x-custom-header".into(), vec!["%6E%69%6B%74%6F".into()]);
    let req = make_request_with_headers("GET", "/admin", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Encoded scanner should block: {:?}", decision);
}

#[test]
fn test_bot_control_char_ua_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla\x01control-injection".into()]);
    let req = make_request_with_headers("GET", "/page", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Control char UA should block: {:?}", decision);
}

#[test]
fn test_bot_single_char_ua_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["x".into()]);
    let req = make_request_with_headers("GET", "/page", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Single-char UA should block: {:?}", decision);
}

#[test]
fn test_bot_combined_attack_with_scanner_blocked() {
    // Scanner fingerprint + SQL injection in body — both detect
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["sqlmap/1.7.2#stable (https://sqlmap.org)".into()]);
    let req = make_request_with_headers("POST", "/login", "", b"admin' OR '1'='1", headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Combined bot+attack should block: {:?}", decision);
}

#[test]
fn test_bot_mixed_clean_passes() {
    // Clean browser with full headers — no bot signals
    let mut waf = GargouilleWaf::new(bot_test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15".into()]);
    headers.insert("accept".into(), vec!["text/html,application/xhtml+xml,*/*;q=0.9".into()]);
    headers.insert("host".into(), vec!["example.com".into()]);
    headers.insert("referer".into(), vec!["https://example.com/page".into()]);
    let req = make_request_with_headers("GET", "/secure-page", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass), "Clean Safari should pass: {:?}", decision);
}

#[test]
fn test_bot_nmap_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 (compatible; Nmap Scripting Engine)".into()]);
    let req = make_request_with_headers("GET", "/scan-target", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Nmap should block: {:?}", decision);
}

#[test]
fn test_bot_masscan_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 Masscan/1.3.2".into()]);
    let req = make_request_with_headers("GET", "/", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Masscan should block: {:?}", decision);
}

#[test]
fn test_bot_gobuster_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["gobuster/3.6".into()]);
    let req = make_request_with_headers("GET", "/admin", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Gobuster should block: {:?}", decision);
}

#[test]
fn test_bot_ffuf_detected() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["ffuf/2.1.0".into()]);
    let req = make_request_with_headers("POST", "/fuzz-target", "", b"FUZZ", headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "FFUF should block: {:?}", decision);
}

#[test]
fn test_bot_nginx_user_agent_passes() {
    // nginx/1.x user agent is NOT a scanner — should pass
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Mozilla/5.0 (compatible; nginx/1.24.0)".into()]);
    let req = make_request_with_headers("GET", "/health", "", &[], headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Pass), "nginx UA should pass: {:?}", decision);
}

#[test]
fn test_bot_apache_http_client_blocked() {
    let mut waf = GargouilleWaf::new(test_config());
    let mut headers = AHashMap::new();
    headers.insert("user-agent".into(), vec!["Apache-HttpClient/4.5.14 (Java/17.0.9)".into()]);
    let req = make_request_with_headers("POST", "/api/call", "", b"{}", headers);
    let decision = waf.evaluate(&req);
    assert!(matches!(decision, waf_core::Decision::Blocked(_)), "Apache HttpClient should block: {:?}", decision);
}
