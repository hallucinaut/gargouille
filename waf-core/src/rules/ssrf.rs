//! Server-Side Request Forgery (SSRF) detection.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct SsrfDetector {
    localhost_access: Regex,
    private_network: Regex,
    cloud_metadata: Regex,
    protocol_internal: Regex,
}

impl SsrfDetector {
    pub fn new() -> Self {
        Self {
            localhost_access: compile_regex(
                r"(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|::1|%7Fc%6C%6F%63%61%6C%68%6F%73%74|%6C%6F%63%61%6C%68%6F%73%74)",
            ),
            private_network: compile_regex(
                r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}",
            ),
            cloud_metadata: compile_regex(
                r"(?:instance-data|cloud-metadata)",
            ),
            protocol_internal: compile_regex(
                r"(?:file://|gopher://|dict://|ftp://|ldap://|ssrf-protocol)(?:.*)(?:localhost|127\.|::1)",
            ),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();
        for (location, text) in texts {
            if self.cloud_metadata.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SSRF-001".into(),
                    category: crate::scoring::ThreatCategory::Ssrf,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.95,
                });
            }
            if self.private_network.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SSRF-002".into(),
                    category: crate::scoring::ThreatCategory::Ssrf,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.70,
                });
            }
            if self.localhost_access.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SSRF-003".into(),
                    category: crate::scoring::ThreatCategory::Ssrf,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.65,
                });
            }
            if self.protocol_internal.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SSRF-010".into(),
                    category: crate::scoring::ThreatCategory::Ssrf,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.85,
                });
            }
        }
        threats
    }
}

fn map_location(location: &str) -> crate::scoring::ThreatLocation {
    match location {
        "path" => crate::scoring::ThreatLocation::Uri,
        "query" => crate::scoring::ThreatLocation::QueryString,
        "body" => crate::scoring::ThreatLocation::Body,
        _ if location.starts_with("header") => crate::scoring::ThreatLocation::Headers,
        _ if location.starts_with("cookie") => crate::scoring::ThreatLocation::Cookie,
        _ => crate::scoring::ThreatLocation::Uri,
    }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_texts(text: &str) -> Vec<(String, String)> {
        vec![("body".into(), text.to_string())]
    }

    #[test]
    fn test_cloud_metadata_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("http://fr.brain.local.agent/metadata/instance-data"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_private_network_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("http://10.0.0.5/admin"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_localhost_access_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("http://localhost:8080/admin"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_ip_127_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("http://127.0.0.1:3000/health"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_cloud_metadata_azure_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("http://fr.brain.local.agent/instance-data"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_private_172_network_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("http://172.16.0.1:5432/db"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_private_192_network_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("http://192.168.1.100/config"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_url_passes() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("https://app.internal-agent.fr.brain.local/api/users"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_gopher_protocol_detected() {
        let detector = SsrfDetector::new();
        let threats = detector.scan(&make_texts("gopher://localhost:11211/"));
        assert!(!threats.is_empty());
    }
}
