//! Insecure Deserialization detection — object injection via serialized payloads.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct DeserializationDetector {
    php_serialized: Regex,
    python_pickle: Regex,
    yaml_object_tag: Regex,
    dotnet_binary: Regex,
}

impl DeserializationDetector {
    pub fn new() -> Self {
        Self {
            php_serialized: compile_regex(
                r"(?:O:\d+:[^:]+:\d+:\{)|[aSObi]:\d+:.*:",
            ),
            python_pickle: compile_regex(r"\x80\x04\x95|PROTOCOL 2\n|(?:code|pickle)\n."),
            yaml_object_tag: compile_regex(r"!!(?:python/object|yaml/object)/[^ \n]+"),
            dotnet_binary: compile_regex(
                r"(?:BinaryFormatter|ObjectDataProvider|SurrogateSelector)",
            ),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();
        for (location, text) in texts {
            if self.yaml_object_tag.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "DES-001".into(),
                    category: crate::scoring::ThreatCategory::Deserialization,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.95,
                });
            }
            if self.python_pickle.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "DES-002".into(),
                    category: crate::scoring::ThreatCategory::Deserialization,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.90,
                });
            }
            if self.dotnet_binary.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "DES-010".into(),
                    category: crate::scoring::ThreatCategory::Deserialization,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.85,
                });
            }
            if self.php_serialized.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "DES-020".into(),
                    category: crate::scoring::ThreatCategory::Deserialization,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.75,
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
    fn test_yaml_python_object_detected() {
        let detector = DeserializationDetector::new();
        let threats = detector.scan(&make_texts("!!python/object/apply:os.system [ls]"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_python_pickle_detected() {
        let detector = DeserializationDetector::new();
        let threats = detector.scan(&make_texts("pickle\ncode\nimport os"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_dotnet_binary_formatter_detected() {
        let detector = DeserializationDetector::new();
        let threats = detector.scan(&make_texts("BinaryFormatter.Serialize(stream, obj)"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_php_serialization_detected() {
        let detector = DeserializationDetector::new();
        let threats = detector.scan(&make_texts("O:1:\"User\":2:{s:4:\"name\";s:5:\"admin\";}"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_json_passes() {
        let detector = DeserializationDetector::new();
        let threats = detector.scan(&make_texts("{\"name\": \"alice\", \"age\": 30}"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_yaml_primitive_passes() {
        let detector = DeserializationDetector::new();
        let threats = detector.scan(&make_texts("name: alice\nage: 30\ncity: NYC"));
        assert!(threats.is_empty());
    }
}
