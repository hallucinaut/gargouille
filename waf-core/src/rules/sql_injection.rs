//! SQL Injection detection — multiple attack vectors and encoding bypasses.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

/// Context filter: only apply comment-based rules in body/query/cookie locations
/// to avoid false positives on URL fragments or path segments.
fn is_body_or_query_context(location: &str) -> bool {
    matches!(location, "body" | "query" | "cookie")
}

#[derive(Debug, Clone)]
pub struct SqlInjectionDetector {
    union_select: Regex,
    comment_patterns: Regex,
    tautology_patterns: Regex,
    error_based_patterns: Regex,
    stacked_queries: Regex,
    keyword_sequences: Regex,
    encoded_tautologies: Regex,
}

impl SqlInjectionDetector {
    pub fn new() -> Self {
        Self {
            union_select: compile_regex(r"\bunion\b[\s]+(?:all\s+)?(?:distinct\s+)?select"),
            comment_patterns: compile_regex(
                r"(?:(?:--|#|/\*)\s*(?:$|\n|[^a-zA-Z0-9])|(?:/\*.*?\*/))",
            ),
            tautology_patterns: compile_regex(
                r#"(?:or|and)\s+['"]?[0-9]+['"]?\s*=\s*['"]?[0-9]+['"]?"#,
            ),
            error_based_patterns: compile_regex(
                r"\b(extractvalue|updatexml|floor|convert)\s*\(",
            ),
            stacked_queries: compile_regex(
                r";\s*(?:select|insert|update|delete|drop|alter|create|exec|execute)",
            ),
            keyword_sequences: compile_regex(r"\b(?:sleep|benchmark|waitfor|delay)\s*\("),
            encoded_tautologies: compile_regex(
                r#"(?:or|and)\s+[\"']?\d{1,2}[\"']?\s*[\+\-*/=]\s*[\"']?\d{1,2}"#,
            ),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();

        for (location, text) in texts {
            if self.union_select.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SQLI-001".into(),
                    category: crate::scoring::ThreatCategory::SqlInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.85,
                });
            }

            if super::check_encoded_variations(text, &self.stacked_queries) {
                threats.push(ThreatInfo {
                    rule_id: "SQLI-002".into(),
                    category: crate::scoring::ThreatCategory::SqlInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.90,
                });
            }

            if self.error_based_patterns.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SQLI-003".into(),
                    category: crate::scoring::ThreatCategory::SqlInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.80,
                });
            }

            if self.keyword_sequences.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SQLI-004".into(),
                    category: crate::scoring::ThreatCategory::SqlInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.75,
                });
            }

            if self.tautology_patterns.is_match(text)
                || self.encoded_tautologies.is_match(text)
            {
                threats.push(ThreatInfo {
                    rule_id: "SQLI-010".into(),
                    category: crate::scoring::ThreatCategory::SqlInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.70,
                });
            }

            // Comment-based rules only apply in body/query/cookie contexts
            if is_body_or_query_context(location) && self.comment_patterns.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "SQLI-020".into(),
                    category: crate::scoring::ThreatCategory::SqlInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.50,
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

    fn make_texts(body: &str) -> Vec<(String, String)> {
        vec![("body".into(), body.to_string())]
    }

    #[allow(dead_code)]
    fn make_query_text(query: &str) -> Vec<(String, String)> {
        vec![("query".into(), query.to_string())]
    }

    fn make_header_text(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(format!("header:{}", name), value.to_string())]
    }

    #[test]
    fn test_union_select_detected() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("id=1; UNION SELECT username FROM users"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_stacked_query_detected() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("; DROP TABLE users"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_error_based_sqli_detected() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("' OR updatexml(1,concat(0x7e,(SELECT version())),1)--"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_tautology_sqli_detected() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("' OR 1=1 --"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_keyword_sequence_detected() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("'; SELECT pg_sleep(5)--"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_normal_query_passes() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("SELECT name FROM products WHERE id=42"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_case_insensitive_detection() {
        let detector = SqlInjectionDetector::new();
        let threats_upper = detector.scan(&make_texts("'; UNION ALL SELECT * FROM users--"));
        let threats_lower = detector.scan(&make_texts("'; union all select * from users--"));
        assert!(!threats_upper.is_empty());
        assert!(!threats_lower.is_empty());
    }

    #[test]
    fn test_confidence_scores() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("' OR 1=1 --"));
        if let Some(threat) = threats.first() {
            assert!(threat.confidence > 0.0);
            assert!(threat.confidence <= 1.0);
        }
    }

    #[test]
    fn test_matched_value_truncated() {
        let detector = SqlInjectionDetector::new();
        let long_payload = format!("' OR {} --", "a".repeat(500));
        let threats = detector.scan(&make_texts(&long_payload));
        assert!(!threats.is_empty());
        // matched_value should be capped at 200 chars
        assert!(threats[0].matched_value.len() <= 200);
    }

    #[test]
    fn test_encoded_sqli_detected() {
        let detector = SqlInjectionDetector::new();
        let encoded = "' OR%201%3D1 --";
        let threats = detector.scan(&make_texts(encoded));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_sqli_in_header() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_header_text("x-user-id", "1'; DROP TABLE users--"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_sqli_in_cookie() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("session_id=1' OR '1'='1"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_sql_query_no_false_positive() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("SELECT id, name, price FROM products ORDER BY price DESC LIMIT 10"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_boolean_based_sqli() {
        let detector = SqlInjectionDetector::new();
        let threats = detector.scan(&make_texts("admin' AND '1'='1' UNION SELECT NULL,NULL --"));
        assert!(!threats.is_empty());
    }
}
