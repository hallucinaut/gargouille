//! Command Injection detection — OS command execution via user input.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

#[derive(Debug, Clone)]
pub struct CmdiDetector {
    pipe_chains: Regex,
    subshell_exec: Regex,
    dangerous_commands: Regex,
    env_abuse: Regex,
    nop_tricks: Regex,
}

impl CmdiDetector {
    pub fn new() -> Self {
        Self {
            pipe_chains: compile_regex(
                r"[;|`$]\s*(?:ls|cat|tac|head|tail|grep|sed|awk|find|xargs|wget|curl|nc|python|perl|ruby|php|node|bash|sh|zsh|chmod|chown|kill|ps|netstat|ifconfig|ipconfig|whoami|id)",
            ),
            subshell_exec: compile_regex(r"\$\(|`[^`]+`|\$\(eval\b"),
            dangerous_commands: compile_regex(
                r"(?:;|\||&&|\|\|)\s*(?:rm\s+-[rf]+\s*/|dd\s+if=|mkfs|fdisk|format|reboot|shutdown|init\b.*0|poweroff|halt)",
            ),
            env_abuse: compile_regex(r"(?:(?:env|setx|set)\s+[^=]+=.{5,})|(?:PATH\s*=)"),
            nop_tricks: compile_regex(r"(?:%3[Bb]|\x3B)\s*(?:cat|ls|id|whoami|uname)"),
        }
    }

    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();
        for (location, text) in texts {
            if self.pipe_chains.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "CMDI-001".into(),
                    category: crate::scoring::ThreatCategory::CommandInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.85,
                });
            }
            if self.subshell_exec.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "CMDI-002".into(),
                    category: crate::scoring::ThreatCategory::CommandInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.80,
                });
            }
            if self.dangerous_commands.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "CMDI-003".into(),
                    category: crate::scoring::ThreatCategory::CommandInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.95,
                });
            }
            if self.env_abuse.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "CMDI-010".into(),
                    category: crate::scoring::ThreatCategory::CommandInjection,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.65,
                });
            }
            if self.nop_tricks.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "CMDI-020".into(),
                    category: crate::scoring::ThreatCategory::CommandInjection,
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
    fn test_pipe_chain_detected() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("cat /etc/passwd | grep root"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_subshell_exec_detected() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("$(whoami)"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_dangerous_command_rm_rf_detected() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("; rm -rf /"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_backtick_exec_detected() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("`id`"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_semicolon_command_injection() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("; cat /etc/shadow"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_clean_text_passes() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("This is a safe command: cat logs.txt"));
        assert!(threats.is_empty());
    }

    #[test]
    fn test_encoded_cmdi_detected() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("%3B cat /etc/passwd"));
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_and_chain_detected() {
        let detector = CmdiDetector::new();
        let threats = detector.scan(&make_texts("&& rm -rf /*"));
        assert!(!threats.is_empty());
    }
}
