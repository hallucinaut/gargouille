//! HTTP Header Injection / CRLF injection detection.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct HeaderInjectionDetector {
    crlf_direct: Regex, crlf_header_manip: Regex, host_injection: Regex, response_splitting: Regex,
}

impl HeaderInjectionDetector {
    pub fn new() -> Self {
        Self {
            crlf_direct: compile_regex(r"%0[Aa]%0[Dd]|%5[Cc]%5[Dd]|%0[Dd]|\\r\\n"),
            crlf_header_manip: compile_regex(r"(?:Set-Cookie|Location|Refresh|Content-Type)\s*[:=]\s*.*%0[Aa]%0[Dd]"),
            host_injection: compile_regex(r"X-Forwarded-Host.*(?:%3[Cc])script|%3[Cc]ookie|set-cookie"),
            response_splitting: compile_regex(r"(?:HTTP/\d\.\d\s+\d{3})"),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();
        for (location, text) in texts {
            if self.crlf_direct.is_match(text) || self.crlf_header_manip.is_match(text) {
                threats.push(ThreatInfo { rule_id: "HJ-001".into(), category: crate::scoring::ThreatCategory::HeaderInjection, matched_value: text.chars().take(200).collect(), location: map_location(location), confidence: 0.85 });
            }
            if self.host_injection.is_match(text) {
                threats.push(ThreatInfo { rule_id: "HJ-002".into(), category: crate::scoring::ThreatCategory::HeaderInjection, matched_value: text.chars().take(200).collect(), location: map_location(location), confidence: 0.80 });
            }
            if self.response_splitting.is_match(text) {
                threats.push(ThreatInfo { rule_id: "HJ-010".into(), category: crate::scoring::ThreatCategory::HeaderInjection, matched_value: text.chars().take(200).collect(), location: map_location(location), confidence: 0.95 });
            }
        }
        threats
    }
}

fn map_location(location: &str) -> crate::scoring::ThreatLocation {
    match location { "path" => crate::scoring::ThreatLocation::Uri, "query" => crate::scoring::ThreatLocation::QueryString, "body" => crate::scoring::ThreatLocation::Body, _ if location.starts_with("header") => crate::scoring::ThreatLocation::Headers, _ if location.starts_with("cookie") => crate::scoring::ThreatLocation::Cookie, _ => crate::scoring::ThreatLocation::Uri }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_texts(text: &str) -> Vec<(String, String)> {
        vec![("body".into(), text.to_string())]
    }

    #[test]
    fn test_crlf_direct_detected() {
        let detector = HeaderInjectionDetector::new();
        let threats = detector.scan(&make_texts("%0a%0dSet-Cookie: hack=true"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_crlf_header_manip_detected() {
        let detector = HeaderInjectionDetector::new();
        let threats = detector.scan(&make_texts("Location: http://fr.brain.local.agent%0a%0dSet-Cookie: admin=true"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_response_splitting_detected() {
        let detector = HeaderInjectionDetector::new();
        let threats = detector.scan(&make_texts("HTTP/1.1 200 OK\r\nSet-Cookie: injected=true"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_host_injection_detected() {
        let detector = HeaderInjectionDetector::new();
        let threats = detector.scan(&make_texts("X-Forwarded-Host: fr.brain.local.agent.evil%3Cscript%3E"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_headers_pass() {
        let detector = HeaderInjectionDetector::new();
        let threats = detector.scan(&make_texts("Content-Type: application/json"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_normal_url_passes() {
        let detector = HeaderInjectionDetector::new();
        let threats = detector.scan(&make_texts("http://fr.brain.local.agent/page?param=value"));
        assert!(threats.is_empty());
    }
}