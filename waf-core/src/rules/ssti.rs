//! Server-Side Template Injection (SSTI) detection.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct SstiDetector {
    jinja_twig: Regex,
    groovy_spel: Regex,
    python_object_access: Regex,
}

impl SstiDetector {
    pub fn new() -> Self {
        Self {
            jinja_twig: compile_regex(
                r"\{\{(?:.*?)(?:config|self|classes|request|g\.(?:session|schema)|__class__|__globals__|mro|subclasses|render)",
            ),
            groovy_spel: compile_regex(r"\#\{[^}]*\.(?:getClass|Runtime|process|exec)"),
            python_object_access: compile_regex(
                r"(?:(?:__import__|__builtins__|__reduce__|pickle))",
            ),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();
        for (location, text) in texts {
            if self.jinja_twig.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SSTI-001".into(),
                    category: crate::scoring::ThreatCategory::Ssti,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.85,
                });
            }
            if self.python_object_access.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SSTI-010".into(),
                    category: crate::scoring::ThreatCategory::Ssti,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.95,
                });
            }
            if self.groovy_spel.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SSTI-020".into(),
                    category: crate::scoring::ThreatCategory::Ssti,
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
    fn test_jinja_config_access_detected() {
        let detector = SstiDetector::new();
        let threats = detector.scan(&make_texts("{{config}}"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_python_object_access_detected() {
        let detector = SstiDetector::new();
        let threats = detector.scan(&make_texts("{{ ''.__class__.__mro__[1].__subclasses__() }}"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_pickle_detected() {
        let detector = SstiDetector::new();
        let threats = detector.scan(&make_texts("__import__('os').system('id')"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_jinja_template_passes() {
        let detector = SstiDetector::new();
        let threats = detector.scan(&make_texts("Hello {{ name }}! Welcome to our site."));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_groovy_spel_detected() {
        let detector = SstiDetector::new();
        let threats = detector.scan(&make_texts("#{''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}"));
        assert!(!threats.is_empty());
    }
}
