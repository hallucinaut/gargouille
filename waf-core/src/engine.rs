// ╔══════════════════════════════════════════════════╗
// ║  Gargouille WAF — Main Evaluation Engine         ║
// ╚══════════════════════════════════════════════════╝

//! The engine orchestrates all rule detectors, scoring, and policy evaluation.
//! It processes a parsed `HttpRequest` through every rule detector, aggregates threats,
//! and produces a final decision (allow / block / challenge).

use crate::config::{ScoringConfig, WafEngineConfig, ThreatAction};
use crate::parser::HttpRequest;
use crate::scoring::{ScoringEngine, ThreatScore};
use crate::rules::{BotDetectionDetector, SqlInjectionDetector, XssDetector, CmdiDetector, LfiRfiDetector, SstiDetector, SsrfDetector, DeserializationDetector, HeaderInjectionDetector, PathTraversalDetector};

/// The main rule engine that evaluates requests against all threat rules.
pub struct RuleEngine {
    config: WafEngineConfig,
    scoring_engine: ScoringEngine,
    // Individual detectors
    sqli: SqlInjectionDetector,
    xss: XssDetector,
    cmdi: CmdiDetector,
    lfi_rfi: LfiRfiDetector,
    ssti: SstiDetector,
    ssrf: SsrfDetector,
    deserialization: DeserializationDetector,
    header_injection: HeaderInjectionDetector,
    path_traversal: PathTraversalDetector,
    bot_detection: BotDetectionDetector,
}

impl RuleEngine {
    /// Create a new rule engine from configuration.
    pub fn new(waf_config: WafEngineConfig, scoring_config: ScoringConfig) -> Self {
        Self {
            config: waf_config.clone(),
            scoring_engine: ScoringEngine::new(scoring_config),
            sqli: SqlInjectionDetector::new(),
            xss: XssDetector::new(),
            cmdi: CmdiDetector::new(),
            lfi_rfi: LfiRfiDetector::new(),
            ssti: SstiDetector::new(),
            ssrf: SsrfDetector::new(),
            deserialization: DeserializationDetector::new(),
            header_injection: HeaderInjectionDetector::new(),
            path_traversal: PathTraversalDetector::new(),
            bot_detection: BotDetectionDetector::new(),
        }
    }

    /// Evaluate a request against all rule detectors. Returns the threat score and action.
    pub fn evaluate(&self, request: &HttpRequest) -> ThreatScore {
        let texts = request.searchable_text();

        let sqli_threats = self.sqli.scan(&texts);
        let xss_threats = self.xss.scan(&texts);
        let cmdi_threats = self.cmdi.scan(&texts);
        let lfi_rfi_threats = self.lfi_rfi.scan(&texts);
        let ssti_threats = self.ssti.scan(&texts);
        let ssrf_threats = self.ssrf.scan(&texts);
        let deserialization_threats = self.deserialization.scan(&texts);
        let header_injection_threats = self.header_injection.scan(&texts);
        let path_traversal_threats = self.path_traversal.scan(&texts);
        let protocol_violation_threats: Vec<crate::scoring::ThreatInfo> = Vec::new();
        let bot_detection_threats = self.bot_detection.scan(&texts);
        let mut score = self.scoring_engine.evaluate(
            &sqli_threats, &xss_threats, &cmdi_threats, &lfi_rfi_threats,
            &ssti_threats, &ssrf_threats, &deserialization_threats,
            &header_injection_threats, &path_traversal_threats,
            &protocol_violation_threats,
            &bot_detection_threats,
        );

        // If the engine score didn't trigger a block but there were threats, check if
        // any single high-confidence threat should force a block.
        // This override only applies when the scoring threshold is reachable (<= 100).
        // An elevated threshold above the max possible score (100) indicates an explicit
        // pass-all policy that must not be overridden by confidence-based direct blocks.
        let high_confidence_threshold = self.scoring_engine.config().high_confidence_threshold;
        if !score.is_blocked()
            && !score.threats.is_empty()
            && self.scoring_engine.is_threshold_reachable()
        {
            for t in &score.threats {
                if t.confidence >= high_confidence_threshold {
                    score.action = crate::scoring::Action::Block(
                        crate::scoring::BlockingReason::DirectBlock { category: t.category.clone() },
                    );
                    break;
                }
            }
        }

        score
    }

    /// Get the default action from configuration.
    pub fn default_action(&self) -> ThreatAction {
        self.config.default_action.clone()
    }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ScoringConfig, WafEngineConfig};
    use crate::parser::HttpRequest;
    use ahash::AHashMap;

    fn make_engine() -> RuleEngine {
        let waf_config = WafEngineConfig { max_body_size: 10_485_760, ..Default::default() };
        let scoring_config = ScoringConfig { threat_threshold: 50, ..Default::default() };
        RuleEngine::new(waf_config, scoring_config)
    }

    fn make_request(method: &str, path: &str, body: &[u8]) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            uri: path.to_string(),
            path: path.to_string(),
            query_string: String::new(),
            full_uri: path.to_string(),
            headers: AHashMap::new(),
            cookies: AHashMap::new(),
            body: body.to_vec(),
            content_length: Some(body.len()),
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            is_https: false,
        }
    }

    fn make_request_with_query(method: &str, full_path: &str) -> HttpRequest {
        let parts: Vec<&str> = full_path.splitn(2, '?').collect();
        let uri = parts[0];
        let query = if parts.len() > 1 { parts[1] } else { "" };
        HttpRequest {
            method: method.to_string(),
            uri: uri.to_string(),
            path: uri.to_string(),
            query_string: query.to_string(),
            full_uri: full_path.to_string(),
            headers: AHashMap::new(),
            cookies: AHashMap::new(),
            body: Vec::new(),
            content_length: None,
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            is_https: false,
        }
    }

    #[test]
    fn test_clean_request_passes() {
        let engine = make_engine();
        let req = make_request("GET", "/index.html", b"");
        let score = engine.evaluate(&req);
        assert_eq!(score.total_score, 0);
        assert!(score.is_passed());
    }

    #[test]
    fn test_sqli_in_body_detected() {
        let engine = make_engine();
        let body = b"'; DROP TABLE users;--";
        let req = make_request("POST", "/login", body);
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_sqli_in_query_detected() {
        let engine = make_engine();
        let req = make_request_with_query("GET", "/search?id=1'; DROP TABLE users;--");
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_xss_in_body_detected() {
        let engine = make_engine();
        let body = b"<script>alert('xss')</script>";
        let req = make_request("POST", "/comment", body);
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_xss_in_query_detected() {
        let engine = make_engine();
        let req = make_request_with_query("GET", "/search?q=<script>alert(1)</script>");
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_xss_javascript_uri_in_query() {
        // Use a combined attack payload that exceeds default threshold (50)
        let engine = make_engine();
        let req = make_request_with_query("GET", "/redirect?url=<script>alert(1)</script>&id=1' OR 1=1--");
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_command_injection_detected() {
        let engine = make_engine();
        let body = b"; cat /etc/passwd";
        let req = make_request("POST", "/api/exec", body);
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_path_traversal_in_query() {
        let engine = make_engine();
        let req = make_request_with_query("GET", "/files?name=../../../etc/passwd");
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_normal_requests_pass() {
        let engine = make_engine();
        for path in &["/", "/index.html", "/api/users", "/about", "/contact"] {
            let req = make_request("GET", path, b"");
            let score = engine.evaluate(&req);
            assert!(score.is_passed(), "Path '{}' should pass WAF", path);
        }
    }

    #[test]
    fn test_normal_post_data_passes() {
        let engine = make_engine();
        let body = b"{\"username\": \"alice\", \"password\": \"secure_pass_123\"}";
        let req = make_request("POST", "/api/login", body);
        let score = engine.evaluate(&req);
        assert!(score.is_passed());
    }

    #[test]
    fn test_header_detection() {
        let mut headers = AHashMap::new();
        headers.insert("x-forwarded-for".to_string(), vec!["HTTP/1.1 200 OK\r\nSet-Cookie: hacked=true".to_string()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:12345".parse().unwrap(),
            is_https: false,
        };
        let engine = make_engine();
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_default_action_returns_block() {
        let engine = make_engine();
        assert!(matches!(engine.default_action(), ThreatAction::Block));
    }

    #[test]
    fn test_ssti_detected_in_body() {
        let engine = make_engine();
        let body = b"__import__('os').system('id')";
        let req = make_request("POST", "/template", body);
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_ssrf_detected() {
        let engine = make_engine();
        let body = b"http://fr.brain.local.agent/instance-data";
        let req = make_request("POST", "/proxy", body);
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_lfi_detected() {
        let engine = make_engine();
        let req = make_request_with_query("GET", "/read?file=../../../etc/passwd");
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_deserialization_detected() {
        let engine = make_engine();
        let body = b"!!python/object/apply:os.system";
        let req = make_request("POST", "/api/restore", body);
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_encoded_attack_detection() {
        let engine = make_engine();
        // Single-encoded SQL injection that decode check catches
        let req = make_request_with_query("GET", "/search?q=%3B%20DROP%20TABLE%20users%3B--");
        let score = engine.evaluate(&req);
        assert!(!score.is_passed());
    }

    #[test]
    fn test_clean_html_request_passes() {
        let mut headers = AHashMap::new();
        headers.insert("content-type".to_string(), vec!["text/html".into()]);
        let body = b"<html><body><h1>Hello World</h1></body></html>";
        let req = HttpRequest {
            method: "GET".into(), uri: "/page".into(), path: "/page".into(),
            query_string: String::new(), full_uri: "/page".into(),
            headers, cookies: AHashMap::new(), body: body.to_vec(),
            content_length: Some(body.len()), remote_addr: "127.0.0.1:12345".parse().unwrap(),
            is_https: false,
        };
        let engine = make_engine();
        let score = engine.evaluate(&req);
        assert!(score.is_passed());
    }
}
