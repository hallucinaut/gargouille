//! Multi-signal risk scoring engine — accumulates evidence across all rule detectors
//! and produces a single threat score (0–100) plus an action decision.

use crate::config::ScoringConfig;
use serde::Serialize;
use std::fmt;

// ──────────────── Threat Info ────────────────────────────

/// A single detected threat with severity and matching evidence.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatInfo {
    pub rule_id: String,
    pub category: ThreatCategory,
    pub matched_value: String,
    pub location: ThreatLocation,
    pub confidence: f32,        // 0.0 – 1.0
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ThreatCategory {
    SqlInjection,
    Xss,
    CommandInjection,
    LfiRfi,
    Ssti,
    Ssrf,
    Deserialization,
    HeaderInjection,
    PathTraversal,
    ProtocolViolation,
    BotChallenge,
    RateLimited,
    IpBlocklisted,
}

#[derive(Debug, Clone, Serialize)]
pub enum ThreatLocation {
    Uri,
    QueryString,
    Body,
    Headers,
    Cookie,
    RemoteAddr,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqlInjection => write!(f, "SQL Injection"),
            Self::Xss => write!(f, "Cross-Site Scripting (XSS)"),
            Self::CommandInjection => write!(f, "Command Injection (OS Command)"),
            Self::LfiRfi => write!(f, "Local/Remote File Inclusion"),
            Self::Ssti => write!(f, "Server-Side Template Injection"),
            Self::Ssrf => write!(f, "Server-Side Request Forgery"),
            Self::Deserialization => write!(f, "Insecure Deserialization"),
            Self::HeaderInjection => write!(f, "Header Injection"),
            Self::PathTraversal => write!(f, "Path Traversal"),
            Self::ProtocolViolation => write!(f, "HTTP Protocol Violation"),
            Self::BotChallenge => write!(f, "Bot Challenge Failed"),
            Self::RateLimited => write!(f, "Rate Limit Exceeded"),
            Self::IpBlocklisted => write!(f, "IP Blocklisted"),
        }
    }
}

// ──────────────── Score & Decision ───────────────────────

/// Final evaluation result.
#[derive(Debug, Clone)]
pub struct ThreatScore {
    pub total_score: u32,
    pub action: Action,
    pub threats: Vec<ThreatInfo>,
}

impl ThreatScore {
    pub fn is_blocked(&self) -> bool {
        matches!(self.action, Action::Block(_))
    }

    pub fn is_passed(&self) -> bool {
        matches!(self.action, Action::Allow)
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    Allow,
    Block(BlockingReason),
    Challenge,
    RateLimit,
}

#[derive(Debug, Clone)]
pub enum BlockingReason {
    ThreatScoreExceeded { score: u32, threshold: u32 },
    DirectBlock { category: ThreatCategory },
    IpBlocklisted,
}

impl fmt::Display for BlockingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreatScoreExceeded { score, threshold } => {
                write!(f, "Threat score {score} exceeds threshold {threshold}")
            }
            Self::DirectBlock { category } => write!(f, "Blocked: {category}"),
            Self::IpBlocklisted => write!(f, "IP address is blocklisted"),
        }
    }
}

// ──────────────── Scoring Engine ─────────────────────────

/// Accumulates scores from all detectors and produces a decision.
pub struct ScoringEngine {
    config: ScoringConfig,
}

const MAX_POSSIBLE_SCORE: u32 = 100;

impl ScoringEngine {
    pub fn new(config: ScoringConfig) -> Self {
        Self { config }
    }

    /// Access the scoring configuration.
    pub fn config(&self) -> &ScoringConfig {
        &self.config
    }

    /// Returns true when the configured threshold is within the reachable score range.
    /// When false, the scoring engine can never produce a block, so direct-block
    /// overrides must also be suppressed to honor pass-all policy.
    pub fn is_threshold_reachable(&self) -> bool {
        self.config.threat_threshold <= MAX_POSSIBLE_SCORE
    }

    /// Run the scoring pipeline. Each detector contributes weight points for its findings.
    pub fn evaluate(
        &self,
        sql_threats: &[ThreatInfo],
        xss_threats: &[ThreatInfo],
        cmdi_threats: &[ThreatInfo],
        lfi_rfi_threats: &[ThreatInfo],
        ssti_threats: &[ThreatInfo],
        ssrf_threats: &[ThreatInfo],
        deserialization_threats: &[ThreatInfo],
        header_injection_threats: &[ThreatInfo],
        path_traversal_threats: &[ThreatInfo],
        protocol_violation_threats: &[ThreatInfo],
    ) -> ThreatScore {
        let mut total = 0u32;
        let mut threats = Vec::new();

        // Accumulate scores, each threat triggers its category weight (capped)
        macro_rules! add_category {
            ($threats:expr, $weight:expr) => {{
                let n = $threats.len().min(3); // max 3 hits per category to prevent score inflation
                total += $weight * n as u32;
                for t in &$threats[..n] {
                    threats.push(t.clone());
                }
            }};
        }

        add_category!(sql_threats, self.config.sql_injection_weight);
        add_category!(xss_threats, self.config.xss_weight);
        add_category!(cmdi_threats, self.config.command_injection_weight);
        add_category!(lfi_rfi_threats, self.config.lfi_rfi_weight);
        add_category!(ssti_threats, self.config.ssti_weight);
        add_category!(ssrf_threats, self.config.ssrf_weight);
        add_category!(deserialization_threats, self.config.deserialization_weight);
        add_category!(header_injection_threats, self.config.header_injection_weight);
        add_category!(path_traversal_threats, self.config.path_traversal_weight);
        add_category!(protocol_violation_threats, self.config.protocol_violation_weight);

        // Cap total at 100
        total = total.min(100);

        let threshold = self.config.threat_threshold;
        let action = if total >= threshold {
            Action::Block(BlockingReason::ThreatScoreExceeded { score: total, threshold })
        } else {
            Action::Allow
        };

        ThreatScore { total_score: total, action, threats }
    }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScoringConfig;

    fn make_threat(category: ThreatCategory) -> ThreatInfo {
        ThreatInfo {
            rule_id: "TEST-001".into(),
            category,
            matched_value: "test-payload".into(),
            location: ThreatLocation::Body,
            confidence: 0.85,
        }
    }

    fn make_config() -> ScoringConfig {
        ScoringConfig {
            threat_threshold: 50,
            sql_injection_weight: 30,
            xss_weight: 25,
            command_injection_weight: 35,
            lfi_rfi_weight: 30,
            ssti_weight: 30,
            ssrf_weight: 25,
            deserialization_weight: 35,
            header_injection_weight: 20,
            path_traversal_weight: 20,
            protocol_violation_weight: 15,
            anomaly_score: 10,
            high_confidence_threshold: 0.90,
        }
    }

    #[test]
    fn test_no_threats_passes() {
        let engine = ScoringEngine::new(make_config());
        let score = engine.evaluate(
            &[], &[], &[], &[], &[], &[], &[], &[], &[], &[],
        );
        assert_eq!(score.total_score, 0);
        assert!(score.is_passed());
    }

    #[test]
    fn test_single_sqli_below_threshold() {
        let engine = ScoringEngine::new(make_config());
        let threats = vec![make_threat(ThreatCategory::SqlInjection)];
        let score = engine.evaluate(&threats, &[], &[], &[], &[], &[], &[], &[], &[], &[]);
        assert_eq!(score.total_score, 30);
        // Single SQLi (30 points) is below threshold (50), so request passes
        assert!(score.is_passed());
    }

    #[test]
    fn test_sqli_capped_at_3_hits() {
        let engine = ScoringEngine::new(make_config());
        // 5 SQL injection threats — should only count the first 3
        let threats: Vec<ThreatInfo> = (0..5).map(|i| {
            ThreatInfo {
                rule_id: format!("SQLI-{:03}", i),
                category: ThreatCategory::SqlInjection,
                matched_value: "union select".into(),
                location: ThreatLocation::Body,
                confidence: 0.85,
            }
        }).collect();
        let score = engine.evaluate(&threats, &[], &[], &[], &[], &[], &[], &[], &[], &[]);
        assert_eq!(score.total_score, 90); // 30 * 3 = 90
        assert_eq!(score.threats.len(), 3);
    }

    #[test]
    fn test_multiple_categories_accumulate() {
        let engine = ScoringEngine::new(make_config());
        let sqli = vec![make_threat(ThreatCategory::SqlInjection)];
        let xss = vec![make_threat(ThreatCategory::Xss)];
        let score = engine.evaluate(&sqli, &xss, &[], &[], &[], &[], &[], &[], &[], &[]);
        assert_eq!(score.total_score, 55); // 30 + 25
    }

    #[test]
    fn test_total_capped_at_100() {
        let engine = ScoringEngine::new(make_config());
        // Maximum possible score: 30+25+35+30+30+25+35+20+20+15 = 265
        let sqli = vec![make_threat(ThreatCategory::SqlInjection)];
        let xss = vec![make_threat(ThreatCategory::Xss)];
        let cmdi = vec![make_threat(ThreatCategory::CommandInjection)];
        let lfi = vec![make_threat(ThreatCategory::LfiRfi)];
        let ssti = vec![make_threat(ThreatCategory::Ssti)];
        let ssrf = vec![make_threat(ThreatCategory::Ssrf)];
        let deser = vec![make_threat(ThreatCategory::Deserialization)];
        let header = vec![make_threat(ThreatCategory::HeaderInjection)];
        let pt = vec![make_threat(ThreatCategory::PathTraversal)];
        let proto = vec![make_threat(ThreatCategory::ProtocolViolation)];
        let score = engine.evaluate(&sqli, &xss, &cmdi, &lfi, &ssti, &ssrf, &deser, &header, &pt, &proto);
        assert_eq!(score.total_score, 100); // capped
    }

    #[test]
    fn test_threshold_decision() {
        let mut config = make_config();
        config.threat_threshold = 30;
        let engine = ScoringEngine::new(config);
        let threats = vec![make_threat(ThreatCategory::SqlInjection)];
        let score = engine.evaluate(&threats, &[], &[], &[], &[], &[], &[], &[], &[], &[]);
        assert!(!score.is_passed());
        match score.action {
            Action::Block(_) => {},
            _ => panic!("Expected Block action"),
        }
    }

    #[test]
    fn test_below_threshold_allows() {
        let mut config = make_config();
        config.threat_threshold = 40;
        let engine = ScoringEngine::new(config);
        let threats = vec![make_threat(ThreatCategory::SqlInjection)];
        let score = engine.evaluate(&threats, &[], &[], &[], &[], &[], &[], &[], &[], &[]);
        assert!(score.is_passed());
    }

    #[test]
    fn test_header_injection_low_weight() {
        let engine = ScoringEngine::new(make_config());
        let threats = vec![make_threat(ThreatCategory::HeaderInjection)];
        let score = engine.evaluate(&[], &[], &[], &[], &[], &[], &[], &threats, &[], &[]);
        assert_eq!(score.total_score, 20);
        assert!(score.is_passed()); // 20 < 50 threshold
    }

    #[test]
    fn test_protocol_violation_weight() {
        let engine = ScoringEngine::new(make_config());
        let threats = vec![make_threat(ThreatCategory::ProtocolViolation)];
        let score = engine.evaluate(&[], &[], &[], &[], &[], &[], &[], &[], &[], &threats);
        assert_eq!(score.total_score, 15);
    }

    #[test]
    fn test_threat_display() {
        let cat = ThreatCategory::SqlInjection;
        assert_eq!(format!("{}", cat), "SQL Injection");
        let cat = ThreatCategory::Xss;
        assert_eq!(format!("{}", cat), "Cross-Site Scripting (XSS)");
        let cat = ThreatCategory::Deserialization;
        assert_eq!(format!("{}", cat), "Insecure Deserialization");
    }

    #[test]
    fn test_blocking_reason_display() {
        let reason = BlockingReason::ThreatScoreExceeded { score: 80, threshold: 50 };
        assert!(format!("{}", reason).contains("80"));
        assert!(format!("{}", reason).contains("50"));

        let reason = BlockingReason::IpBlocklisted;
        assert_eq!(format!("{}", reason), "IP address is blocklisted");
    }

    #[test]
    fn test_threat_location_display() {
        let loc = ThreatLocation::Uri;
        let _ = loc;
        let loc = ThreatLocation::QueryString;
        let _ = loc;
        let loc = ThreatLocation::Headers;
        let _ = loc;
        let loc = ThreatLocation::Cookie;
        let _ = loc;
    }
}
