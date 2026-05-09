//! Local/Remote File Inclusion (LFI/RFI) detection.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct LfiRfiDetector {
    path_traversal: Regex,
    etc_passwd_access: Regex,
    php_wrappers: Regex,
    java_class_loading: Regex,
}

impl LfiRfiDetector {
    pub fn new() -> Self {
        Self {
            path_traversal: compile_regex(
                r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e%2f|%5[Cc]%2[Ee]%2[Ff]|%2[Ee]%2[Ff]\.\.)",
            ),
            etc_passwd_access: compile_regex(
                r"/(?:etc/(?:passwd|shadow|hosts)|proc/self/environ|proc/self/cmdline|(?:windows|(?:sysroot))?/(?:windows|winnt)/(?:system32|system)/(?:win\.ini|boot\.ini))",
            ),
            php_wrappers: compile_regex(r"php://(?:input|filter|data|expect|stdout)/"),
            java_class_loading: compile_regex(
                r"classpath://|jar://|file:///.*\.class",
            ),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();
        for (location, text) in texts {
            if self.etc_passwd_access.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "LFI-001".into(),
                    category: crate::scoring::ThreatCategory::LfiRfi,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.95,
                });
            }
            if self.php_wrappers.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "LFI-002".into(),
                    category: crate::scoring::ThreatCategory::LfiRfi,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.90,
                });
            }
            if self.path_traversal.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "LFI-010".into(),
                    category: crate::scoring::ThreatCategory::LfiRfi,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.60,
                });
            }
            if self.java_class_loading.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "LFI-020".into(),
                    category: crate::scoring::ThreatCategory::LfiRfi,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.80,
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
    fn test_etc_passwd_access_detected() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("/etc/passwd"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_etc_shadow_access_detected() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("file=/etc/shadow"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_php_wrapper_detected() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("php://filter/convert.base64-encode/resource=config.php"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_path_traversal_sequence_detected() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("../../../etc/passwd"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_java_class_loading_detected() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("classpath://evil.class"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_file_path_passes() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("/var/www/html/index.html"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_encoded_traversal_detected() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("%2e%2e%2f%2e%2e%2fetc%2fpasswd"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_proc_self_environ_detected() {
        let detector = LfiRfiDetector::new();
        let threats = detector.scan(&make_texts("/proc/self/environ"));
        assert!(!threats.is_empty());
    }
}
