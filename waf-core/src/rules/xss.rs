//! XSS (Cross-Site Scripting) detection — reflected, stored, and DOM-based patterns.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct XssDetector {
    event_handlers: Regex,
    script_tags: Regex,
    data_uri_scheme: Regex,
    vector_elements: Regex,
    template_expr: Regex,
}

impl XssDetector {
    pub fn new() -> Self {
        Self {
            event_handlers: compile_regex(
                r"\bon(?:load|error|mouseover|mouseout|mouseenter|mouseleave|click|dblclick|mousedown|mouseup|mousemove|keydown|keyup|keypress|focus|blur|change|submit|reset|select|abort|beforeunload|hashchange|message|offline|online|pagehide|pageshow|popstate|resize|scroll|storage|unload)",
            ),
            script_tags: compile_regex(r"<\s*script(?:\s+[^>]*)?>|<\s*/\s*script\s*>|%3[Cc]\s*script"),
            data_uri_scheme: compile_regex(r"(?:javascript|vbscript|data)\s*:"),
            vector_elements: compile_regex(
                r#"<\s*(?:img|svg|iframe|object|embed|video|audio|source|math|input|form|body|details|marquee|animate)\b[^>]*(?:on\w+|src\s*=\s*["']?\s*(?:javascript|data))"#,
            ),
            template_expr: compile_regex(
                r"\{\{(?:.*?)(?:constructor|prototype|__proto__|call|apply|bind)",
            ),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();

        for (location, text) in texts {
            if self.script_tags.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "XSS-001".into(),
                    category: crate::scoring::ThreatCategory::Xss,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.95,
                });
            }
            if self.event_handlers.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "XSS-002".into(),
                    category: crate::scoring::ThreatCategory::Xss,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.85,
                });
            }
            if self.data_uri_scheme.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "XSS-003".into(),
                    category: crate::scoring::ThreatCategory::Xss,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.80,
                });
            }
            if self.vector_elements.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "XSS-004".into(),
                    category: crate::scoring::ThreatCategory::Xss,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.75,
                });
            }
            if self.template_expr.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "XSS-005".into(),
                    category: crate::scoring::ThreatCategory::Xss,
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

    #[allow(dead_code)]
    fn make_query_text(query: &str) -> Vec<(String, String)> {
        vec![("query".into(), query.to_string())]
    }

    #[test]
    fn test_script_tag_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<script>alert('xss')</script>"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_event_handler_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<img onerror=alert(1) src=x>"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_data_uri_scheme_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<a href=javascript:alert(1)>click</a>"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_vector_element_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<iframe src=javascript:alert(1)></iframe>"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_template_expr_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("{{constructor.constructor('return this')}}"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_encoded_script_tag_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("%3Cscript%3Ealert(1)%3C/script%3E"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_html_passes() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<div class=\"container\"><h1>Hello</h1></div>"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_normal_text_passes() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("Hello world, this is a normal comment."));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_case_insensitive_detection() {
        let detector = XssDetector::new();
        let threats_upper = detector.scan(&make_texts("<SCRIPT>alert(1)</SCRIPT>"));
        let threats_lower = detector.scan(&make_texts("<script>alert(1)</script>"));
        assert!(!threats_upper.is_empty());
        assert!(!threats_lower.is_empty());
    }

    #[test]
    fn test_onclick_handler_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<button onclick=alert('clicked')>Click me</button>"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_svg_xss_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<svg onload=alert(1)>") );
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_vbscript_detected() {
        let detector = XssDetector::new();
        let threats = detector.scan(&make_texts("<a href=vbscript:msgbox(1)>click</a>"));
        assert!(!threats.is_empty());
    }
}
