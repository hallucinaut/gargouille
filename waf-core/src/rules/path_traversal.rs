//! Path Traversal detection — directory escape attempts via encoded/obfuscated sequences.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct PathTraversalDetector {
    classic_traversal: Regex,
    double_encoding: Regex,
    null_byte_injection: Regex,
    backslash_traversal: Regex,
}

impl PathTraversalDetector {
    pub fn new() -> Self {
        Self {
            classic_traversal: compile_regex(
                r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/%7c|\.%2e|%252e%252e%252f)",
            ),
            double_encoding: compile_regex(
                r"(?:%25[25]2[eE]|%25[25]2[eE]%25[25]2[eE]%25[25]2[fF])",
            ),
            null_byte_injection: compile_regex(r"(?:%00|\\x00|%2500)"),
            backslash_traversal: compile_regex(
                r"\.\.\\|%5[Cc]\.\.%5[Cc]|\\\.\.",
            ),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();
        for (location, text) in texts {
            if self.null_byte_injection.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "PT-001".into(),
                    category: crate::scoring::ThreatCategory::PathTraversal,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.90,
                });
            }
            if self.classic_traversal.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "PT-002".into(),
                    category: crate::scoring::ThreatCategory::PathTraversal,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.75,
                });
            }
            if self.double_encoding.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "PT-010".into(),
                    category: crate::scoring::ThreatCategory::PathTraversal,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.85,
                });
            }
            if self.backslash_traversal.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "PT-020".into(),
                    category: crate::scoring::ThreatCategory::PathTraversal,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.70,
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
    fn test_classic_traversal_detected() {
        let detector = PathTraversalDetector::new();
        let threats = detector.scan(&make_texts("../../../etc/passwd"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_double_encoding_detected() {
        let detector = PathTraversalDetector::new();
        let threats = detector.scan(&make_texts("%252e%252e%252f%252e%252e%252fetc%252fpasswd"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_null_byte_detected() {
        let detector = PathTraversalDetector::new();
        let threats = detector.scan(&make_texts("evil.jpg%00.php"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_backslash_traversal_detected() {
        let detector = PathTraversalDetector::new();
        let threats = detector.scan(&make_texts("..\\..\\windows\\system32"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_encoded_traversal_detected() {
        let detector = PathTraversalDetector::new();
        let threats = detector.scan(&make_texts("%2e%2e%2f%2e%2e%2fetc%2fpasswd"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_file_path_passes() {
        let detector = PathTraversalDetector::new();
        let threats = detector.scan(&make_texts("/var/www/html/images/logo.png"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_relative_path_passes() {
        let detector = PathTraversalDetector::new();
        let threats = detector.scan(&make_texts("./index.html"));
        assert!(threats.is_empty());
    }
}
