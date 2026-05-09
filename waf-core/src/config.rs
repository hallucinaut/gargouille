//! WAF configuration — loaded from TOML with validation.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main configuration struct.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WafConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub waf: WafEngineConfig,
    #[serde(default)]
    pub scoring: ScoringConfig,
    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,
    #[serde(default)]
    pub geo_ip: GeoIpConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tls_inspector: TlsInspectorConfig,
    #[serde(default)]
    pub bot_protection: BotProtectionConfig,
    #[serde(default)]
    pub response_headers: ResponseHeadersConfig,
}

// ─── Server ──────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_reverse_proxy_port")]
    pub reverse_proxy_port: u16,
    #[serde(default = "default_upstream_host")]
    pub upstream_host: String,
    #[serde(default = "default_upstream_port")]
    pub upstream_port: u16,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(default)]
    pub tls_cert: String,
    #[serde(default)]
    pub tls_key: String,
}

// ─── WAF Engine ──────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct WafEngineConfig {
    #[serde(default = "default_action")]
    pub default_action: ThreatAction,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    #[serde(default)]
    pub strict_mode: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThreatAction {
    #[default]
    Block,
    Challenge,
    Log,
    RateLimit,
    Scan,
}

// ─── Scoring ─────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ScoringConfig {
    #[serde(default = "default_threat_threshold")]
    pub threat_threshold: u32,
    #[serde(default = "default_sql_injection_weight")]
    pub sql_injection_weight: u32,
    #[serde(default = "default_xss_weight")]
    pub xss_weight: u32,
    #[serde(default = "default_command_injection_weight")]
    pub command_injection_weight: u32,
    #[serde(default = "default_lfi_rfi_weight")]
    pub lfi_rfi_weight: u32,
    #[serde(default = "default_ssti_weight")]
    pub ssti_weight: u32,
    #[serde(default = "default_ssrf_weight")]
    pub ssrf_weight: u32,
    #[serde(default = "default_deserialization_weight")]
    pub deserialization_weight: u32,
    #[serde(default = "default_header_injection_weight")]
    pub header_injection_weight: u32,
    #[serde(default = "default_path_traversal_weight")]
    pub path_traversal_weight: u32,
    #[serde(default = "default_protocol_violation_weight")]
    pub protocol_violation_weight: u32,
    #[serde(default = "default_anomaly_score")]
    pub anomaly_score: u32,
    /// Minimum confidence required for direct-block override.
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f32,
}

// ─── Rate Limiting ───────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_requests_per_window")]
    pub requests_per_window: u64,
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
    #[serde(default = "default_burst_allowance")]
    pub burst_allowance: u32,
    #[serde(default)]
    pub endpoint_limits: HashMap<String, u64>,
    #[serde(default)]
    pub block: RateLimitBlockConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RateLimitBlockConfig {
    #[serde(default = "default_block_duration")]
    pub duration_minutes: u64,
    #[serde(default)]
    pub auto_unblock: bool,
}

// ─── GeoIP / Blocklist ──────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub db_path: String,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    #[serde(default = "default_min_reputation")]
    pub min_reputation_score: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_db_path")]
    pub database_path: String,
}

// ─── Logging & Metrics ──────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default)]
    pub log_file: String,
    #[serde(default)]
    pub log_blocked: bool,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

// ─── TLS / Bot Protection ────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TlsInspectorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub deep_packet_inspection: bool,
    #[serde(default = "default_min_tls")]
    pub min_tls_version: String,
    #[serde(default)]
    pub cipher_suites_blocked: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct BotProtectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub block_bad_bots: bool,
    #[serde(default = "default_captcha_threshold")]
    pub captcha_threshold: u32,
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ResponseHeadersConfig {
    pub x_frame_options: String,
    pub x_content_type_options: String,
    pub x_xss_protection: String,
    pub content_security_policy: String,
    pub referrer_policy: String,
    pub permissions_policy: String,
    pub strict_transport_security: String,
}

// ──────────────────── Helpers ────────────────────────────

fn default_listen_addr() -> String { "0.0.0.0".into() }
fn default_listen_port() -> u16 { 8443 }
fn default_reverse_proxy_port() -> u16 { 8080 }
fn default_upstream_host() -> String { "127.0.0.1".into() }
fn default_upstream_port() -> u16 { 3000 }
fn default_action() -> ThreatAction { ThreatAction::Block }
fn default_max_body_size() -> usize { 10_485_760 } // 10 MB
fn default_upstream_timeout_ms() -> u64 { 30_000 }
fn default_threat_threshold() -> u32 { 50 }
fn default_sql_injection_weight() -> u32 { 30 }
fn default_xss_weight() -> u32 { 25 }
fn default_command_injection_weight() -> u32 { 35 }
fn default_lfi_rfi_weight() -> u32 { 30 }
fn default_ssti_weight() -> u32 { 30 }
fn default_ssrf_weight() -> u32 { 25 }
fn default_deserialization_weight() -> u32 { 35 }
fn default_header_injection_weight() -> u32 { 20 }
fn default_path_traversal_weight() -> u32 { 20 }
fn default_protocol_violation_weight() -> u32 { 15 }
fn default_anomaly_score() -> u32 { 10 }
fn default_requests_per_window() -> u64 { 100 }
fn default_window_seconds() -> u64 { 60 }
fn default_burst_allowance() -> u32 { 20 }
fn default_block_duration() -> u64 { 60 }
fn default_min_reputation() -> u32 { 40 }
fn default_db_path() -> String { "database/gargouille.db".into() }
fn default_log_level() -> String { "info".into() }
fn default_log_format() -> String { "json".into() }
fn default_sample_rate() -> f64 { 1.0 }
fn default_metrics_port() -> u16 { 9090 }
fn default_metrics_path() -> String { "/metrics".into() }
fn default_min_tls() -> String { "TLS_1_2".into() }
fn default_captcha_threshold() -> u32 { 5 }
fn default_challenge_type() -> String { "js_challenge".into() }
fn default_high_confidence_threshold() -> f32 { 0.90 }
fn clamp_weight(val: u32) -> u32 {
    val.clamp(1, 100)
}
fn clamp_threshold(val: u32) -> u32 {
    if val > 100 {
        eprintln!("⚠ threat_threshold {} exceeds maximum (100), clamped to 100", val);
        100
    } else {
        val
    }
}

// ──────────────────── Load / Validate ────────────────────

impl WafConfig {
    /// Load config from a TOML file. Falls back to defaults for missing keys.
    pub fn load(path: &PathBuf) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content).unwrap_or_else(|e| {
            eprintln!("⚠ Config parse error: {e}, using defaults");
            Self::default()
        }))
    }

    /// Validate the config and return any warnings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.server.listen_port == 0 {
            warnings.push("listen_port is 0, will use default".into());
        }
        if self.waf.max_body_size > 100 * 1024 * 1024 {
            warnings.push(
                "max_body_size exceeds 100MB — consider lowering for DoS protection".into(),
            );
        }
        let total_weight = self.scoring.sql_injection_weight
            + self.scoring.xss_weight
            + self.scoring.command_injection_weight
            + self.scoring.lfi_rfi_weight
            + self.scoring.ssti_weight
            + self.scoring.ssrf_weight
            + self.scoring.deserialization_weight
            + self.scoring.header_injection_weight
            + self.scoring.path_traversal_weight
            + self.scoring.protocol_violation_weight;
        if total_weight < 10 {
            warnings.push(
                "Sum of all scoring weights is below 10 — WAF may fail to detect threats".into(),
            );
        }
        if self.server.tls_enabled && (self.server.tls_cert.is_empty() || self.server.tls_key.is_empty()) {
            warnings.push("TLS enabled but tls_cert or tls_key is empty".into());
        }
        if self.metrics.enabled && self.metrics.port == 0 {
            warnings.push("Metrics enabled but port is 0".into());
        }
        warnings
    }

    /// Post-process config to apply safe defaults for out-of-range values.
    pub fn sanitize(&mut self) {
        let s = &mut self.scoring;
        s.sql_injection_weight = clamp_weight(s.sql_injection_weight);
        s.xss_weight = clamp_weight(s.xss_weight);
        s.command_injection_weight = clamp_weight(s.command_injection_weight);
        s.lfi_rfi_weight = clamp_weight(s.lfi_rfi_weight);
        s.ssti_weight = clamp_weight(s.ssti_weight);
        s.ssrf_weight = clamp_weight(s.ssrf_weight);
        s.deserialization_weight = clamp_weight(s.deserialization_weight);
        s.header_injection_weight = clamp_weight(s.header_injection_weight);
        s.path_traversal_weight = clamp_weight(s.path_traversal_weight);
        s.protocol_violation_weight = clamp_weight(s.protocol_violation_weight);
        s.threat_threshold = clamp_threshold(s.threat_threshold);
        if s.high_confidence_threshold < 0.1 || s.high_confidence_threshold > 1.0 {
            eprintln!("⚠ high_confidence_threshold out of range, resetting to 0.90");
            s.high_confidence_threshold = 0.90;
        }
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen_addr: default_listen_addr(),
                listen_port: default_listen_port(),
                reverse_proxy_port: default_reverse_proxy_port(),
                upstream_host: default_upstream_host(),
                upstream_port: default_upstream_port(),
                tls_enabled: true,
                tls_cert: "certs/server.crt".into(),
                tls_key: "certs/server.key".into(),
            },
            waf: WafEngineConfig {
                default_action: default_action(),
                max_body_size: default_max_body_size(),
                upstream_timeout_ms: default_upstream_timeout_ms(),
                strict_mode: true,
            },
            scoring: ScoringConfig {
                threat_threshold: default_threat_threshold(),
                sql_injection_weight: default_sql_injection_weight(),
                xss_weight: default_xss_weight(),
                command_injection_weight: default_command_injection_weight(),
                lfi_rfi_weight: default_lfi_rfi_weight(),
                ssti_weight: default_ssti_weight(),
                ssrf_weight: default_ssrf_weight(),
                deserialization_weight: default_deserialization_weight(),
                header_injection_weight: default_header_injection_weight(),
                path_traversal_weight: default_path_traversal_weight(),
                protocol_violation_weight: default_protocol_violation_weight(),
                anomaly_score: default_anomaly_score(),
                high_confidence_threshold: default_high_confidence_threshold(),
            },
            rate_limiting: RateLimitingConfig {
                enabled: true,
                requests_per_window: default_requests_per_window(),
                window_seconds: default_window_seconds(),
                burst_allowance: default_burst_allowance(),
                endpoint_limits: HashMap::new(),
                block: RateLimitBlockConfig {
                    duration_minutes: default_block_duration(),
                    auto_unblock: true,
                },
            },
            geo_ip: GeoIpConfig {
                enabled: false, // opt-in, needs a DB
                db_path: "database/GeoLite2-Country.mmdb".into(),
                blocked_countries: Vec::new(),
                min_reputation_score: default_min_reputation(),
            },
            blocklist: BlocklistConfig {
                enabled: true,
                database_path: default_db_path(),
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
                log_file: "logs/gargouille.log".into(),
                log_blocked: true,
                sample_rate: default_sample_rate(),
            },
            metrics: MetricsConfig {
                enabled: true,
                port: default_metrics_port(),
                path: default_metrics_path(),
            },
            tls_inspector: TlsInspectorConfig {
                enabled: false,
                deep_packet_inspection: false,
                min_tls_version: default_min_tls(),
                cipher_suites_blocked: Vec::new(),
            },
            bot_protection: BotProtectionConfig {
                enabled: true,
                block_bad_bots: true,
                captcha_threshold: default_captcha_threshold(),
                challenge_type: default_challenge_type(),
            },
            response_headers: ResponseHeadersConfig {
                x_frame_options: "DENY".into(),
                x_content_type_options: "nosniff".into(),
                x_xss_protection: "0".into(),
                content_security_policy: "default-src 'self'; script-src 'self'".into(),
                referrer_policy: "strict-origin-when-cross-origin".into(),
                permissions_policy: "camera=(), microphone=(), geolocation=()".into(),
                strict_transport_security: "max-age=31536000; includeSubDomains".into(),
            },
        }
    }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        let config = WafConfig::default();
        assert_eq!(config.server.listen_addr, "0.0.0.0");
        assert_eq!(config.server.listen_port, 8443);
        assert_eq!(config.waf.max_body_size, 10_485_760);
        assert!(config.waf.strict_mode);
    }

    #[test]
    fn test_default_scoring_weights() {
        let config = WafConfig::default();
        assert_eq!(config.scoring.threat_threshold, 50);
        assert_eq!(config.scoring.sql_injection_weight, 30);
        assert_eq!(config.scoring.xss_weight, 25);
        assert_eq!(config.scoring.command_injection_weight, 35);
    }

    #[test]
    fn test_default_rate_limiting() {
        let config = WafConfig::default();
        assert!(config.rate_limiting.enabled);
        assert_eq!(config.rate_limiting.requests_per_window, 100);
        assert_eq!(config.rate_limiting.window_seconds, 60);
    }

    #[test]
    fn test_validate_no_warnings_on_default() {
        let config = WafConfig::default();
        let warnings = config.validate();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_large_body_warning() {
        let mut config = WafConfig::default();
        config.waf.max_body_size = 200 * 1024 * 1024; // 200MB
        let warnings = config.validate();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("100MB"));
    }

    #[test]
    fn test_validate_zero_port_warning() {
        let mut config = WafConfig::default();
        config.server.listen_port = 0;
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("listen_port"));
    }

    #[test]
    fn test_load_default_config_file() {
        let path = std::path::PathBuf::from("../../config/default.toml");
        if path.exists() {
            let config = WafConfig::load(&path).unwrap();
            assert_eq!(config.waf.default_action, ThreatAction::Block);
            assert_eq!(config.scoring.threat_threshold, 50);
        }
    }

    #[test]
    fn test_toml_deserialization() {
        let toml_str = r#"
[server]
listen_addr = "127.0.0.1"
listen_port = 9090

[waf]
default_action = "Log"
max_body_size = 5242880

[scoring]
threat_threshold = 60
sql_injection_weight = 40
"#;
        let config: WafConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_addr, "127.0.0.1");
        assert_eq!(config.server.listen_port, 9090);
        assert!(matches!(config.waf.default_action, ThreatAction::Log));
        assert_eq!(config.waf.max_body_size, 5_242_880);
        assert_eq!(config.scoring.threat_threshold, 60);
    }

    #[test]
    fn test_deserialization_partial_config() {
        let toml_str = r#"
[waf]
default_action = "Challenge"
"#;
        let config: WafConfig = toml::from_str(toml_str).unwrap();
        assert!(matches!(config.waf.default_action, ThreatAction::Challenge));
        // Config loaded successfully with partial TOML
    }

    #[test]
    fn test_json_schema_generation() {
        let schema: schemars::Schema = schemars::schema_for!(WafConfig);
        // Convert to JSON and verify it's a valid object (not just true/false)
        let json_value: serde_json::Value = schema.into();
        assert!(json_value.is_object());
    }

    #[test]
    fn test_response_headers_defaults() {
        let config = WafConfig::default();
        assert_eq!(config.response_headers.x_frame_options, "DENY");
        assert_eq!(config.response_headers.x_content_type_options, "nosniff");
        assert!(!config.response_headers.content_security_policy.is_empty());
    }

    #[test]
    fn test_bot_protection_defaults() {
        let config = WafConfig::default();
        assert!(config.bot_protection.enabled);
        assert_eq!(config.bot_protection.captcha_threshold, 5);
    }
}
