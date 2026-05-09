// ╔══════════════════════════════════════════════════╗
// ║  Gargouille WAF — High-Level Firewall Interface    ║
// ╚══════════════════════════════════════════════════╝

//! The public API for the WAF. Takes an `HttpRequest` and returns a decision.
//! Coordinates between the rule engine, rate limiter, database (blocklist/audit),
//! and metrics — all of which are optional features.
//!
//! Thread-safety: mutable state uses `std::sync::Mutex` so that
//! `evaluate()` takes `&self` and can be shared via `Arc` across async tasks.

use crate::config::*;
use std::sync::Mutex;

#[cfg(feature = "sqlite")]
use crate::database::{WafDatabase, ThreatEntry};
use crate::engine::RuleEngine;
use crate::parser::HttpRequest;
use crate::rate_limit::RateLimiter;
use crate::scoring::{Action, BlockingReason};
#[cfg(feature = "prometheus")]
use crate::metrics::WafMetrics;

/// The main WAF service — holds all components and evaluates incoming requests.
pub struct GargouilleWaf {
    engine: RuleEngine,
    rate_limiter: Mutex<RateLimiter>,
    #[cfg(feature = "sqlite")]
    database: Mutex<Option<WafDatabase>>,
    #[cfg(feature = "prometheus")]
    metrics: Option<WafMetrics>,
    config: WafConfig,
}

impl GargouilleWaf {
    /// Create a new WAF instance from configuration.
    pub fn new(config: WafConfig) -> Self {
        let engine = RuleEngine::new(
            config.waf.clone(),
            config.scoring.clone(),
        );
        let rate_limiter = RateLimiter::new(
            config.rate_limiting.requests_per_window,
            config.rate_limiting.window_seconds,
            config.rate_limiting.burst_allowance,
        );

        Self {
            engine,
            rate_limiter: Mutex::new(rate_limiter),
            #[cfg(feature = "sqlite")]
            database: Mutex::new(Self::open_database(&config)),
            #[cfg(feature = "prometheus")]
            metrics: Self::make_metrics(&config),
            config,
        }
    }

    /// Evaluate a request and return the final decision.
    pub fn evaluate(&self, request: &HttpRequest) -> Decision {
        // Record total requests in metrics
        #[cfg(feature = "prometheus")]
        if let Some(metrics) = &self.metrics {
            metrics.record_request();
        }

        let ip_str = request.remote_addr.ip().to_string();

        // 1. Check per-endpoint rate limits first (cheap operation)
        if self.config.rate_limiting.enabled && !self.config.rate_limiting.endpoint_limits.is_empty() {
            for (endpoint, limit) in &self.config.rate_limiting.endpoint_limits {
                let ep_normalized = endpoint.trim_start_matches('/');
                let path_normalized = request.path.trim_start_matches('/');
                let is_match = if *endpoint == "/" {
                    true
                } else {
                    path_normalized == ep_normalized || path_normalized.starts_with(&format!("{}/", ep_normalized))
                };
                if is_match {
                    // Per-endpoint limit check — use the configured limit directly
                    let effective_limit = *limit + self.config.rate_limiting.burst_allowance as u64;
                    let mut limiter = self.rate_limiter.lock().unwrap();
                    let (_allowed, count) = limiter.check_endpoint(&ip_str, endpoint);
                    drop(limiter);
                    if count > effective_limit {
                        #[cfg(feature = "prometheus")]
                        if let Some(metrics) = &self.metrics {
                            metrics.record_blocked(0);
                        }
                        self.audit_log_with_score(request, &format!("Endpoint rate limited: {} ({}/req)", endpoint, limit), 0, &[]);
                        return Decision::RateLimited;
                    }
                }
            }
        }

        // 2. Check general rate limiting
        if self.config.rate_limiting.enabled {
            let mut limiter = self.rate_limiter.lock().unwrap();
            let (allowed, count) = limiter.check(&ip_str);
            drop(limiter);
            if !allowed {
                #[cfg(feature = "prometheus")]
                if let Some(metrics) = &self.metrics {
                    metrics.record_blocked(0);
                }
                self.audit_log_with_score(request, &format!("Rate limited at {} req/window", count), 0, &[]);
                return Decision::RateLimited;
            }
        }

        // 2. Check blocklist (cheap lookup)
        #[cfg(feature = "sqlite")]
        if self.config.blocklist.enabled {
            if let Some(db) = self.database.lock().unwrap().as_ref() {
                if let Some(reason) = db.is_ip_blocked(&ip_str) {
                    #[cfg(feature = "prometheus")]
                    if let Some(metrics) = &self.metrics {
                        metrics.record_blocked(0);
                    }
                    self.audit_log_with_score(request, &format!("IP blocked: {}", reason), 0, &[]);
                    return Decision::Blocked(BlockingReason::IpBlocklisted);
                }
            }
        }

        // 3. Enforce body size limit before expensive scanning (DoS protection)
        let max_body = self.config.waf.max_body_size;
        if max_body > 0 && request.body.len() > max_body {
            #[cfg(feature = "prometheus")]
            if let Some(metrics) = &self.metrics {
                metrics.record_blocked(0);
            }
            self.audit_log_with_score(
                request,
                &format!("Body size {} exceeds limit of {} bytes", request.body.len(), max_body),
                0,
                &["BODY-SIZE".into()],
            );
            return Decision::Blocked(BlockingReason::ThreatScoreExceeded {
                score: 100, // Maximum — always blocks oversized bodies
                threshold: self.config.scoring.threat_threshold,
            });
        }

        // 4. Run the rule engine (expensive — all detectors)
        let score = self.engine.evaluate(request);

        // 5. Record metrics
        #[cfg(feature = "prometheus")]
        if let Some(metrics) = &self.metrics {
            for t in &score.threats {
                let category = match &t.category {
                    crate::scoring::ThreatCategory::SqlInjection => "sql_injection",
                    crate::scoring::ThreatCategory::Xss => "xss",
                    crate::scoring::ThreatCategory::CommandInjection => "command_injection",
                    crate::scoring::ThreatCategory::LfiRfi => "lfi_rfi",
                    crate::scoring::ThreatCategory::Ssti => "ssti",
                    crate::scoring::ThreatCategory::Ssrf => "ssrf",
                    crate::scoring::ThreatCategory::Deserialization => "deserialization",
                    crate::scoring::ThreatCategory::HeaderInjection => "header_injection",
                    crate::scoring::ThreatCategory::PathTraversal => "path_traversal",
                    _ => "other",
                };
                metrics.record_threat(category);
            }

            match &score.action {
                Action::Block(_) => {
                    metrics.record_blocked(score.total_score);
                }
                Action::Challenge => {
                    metrics.record_challenged();
                }
                Action::Allow | Action::RateLimit => {
                    metrics.record_allowed();
                }
            }
        }

        // 6. Audit log if blocked (with full threat details)
        let block_reason = match score.action.clone() {
            Action::Block(ref r) => Some(r.clone()),
            _ => None,
        };

        if let Some(reason) = &block_reason {
            let rule_ids: Vec<String> = score.threats.iter()
                .map(|t| t.rule_id.clone())
                .collect();
            self.audit_log_with_score(request, &format!("{}", reason), score.total_score, &rule_ids);

            // Auto-block IP for threat-score violations (requires DB)
            #[cfg(feature = "sqlite")]
            if matches!(reason, BlockingReason::ThreatScoreExceeded { .. })
                && self.config.rate_limiting.block.auto_unblock
            {
                let db_expiry_minutes = self.config.rate_limiting.block.duration_minutes;
                let mut db_guard = self.database.lock().unwrap();
                if let Some(db) = db_guard.as_mut() {
                    let _ = db.add_to_blocklist(
                        &ip_str,
                        &format!("Threat score {} exceeded (auto-block {}min)", score.total_score, db_expiry_minutes),
                        true,
                    );
                }
            }
        }

        // Convert internal decision to public type
        match score.action {
            Action::Allow => Decision::Pass,
            Action::Block(reason) => Decision::Blocked(reason),
            Action::Challenge => Decision::Challenge,
            Action::RateLimit => Decision::RateLimited,
        }
    }

    // ── Feature-gated public helpers ────────────────────────

    /// Get recent audit log entries. Only available with the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    pub fn get_recent_threats(&self, limit: i64) -> Option<Vec<ThreatEntry>> {
        self.database.lock().unwrap().as_ref()
            .map(|db| db.get_recent_threats(limit).unwrap_or_default())
    }

    /// Add an IP to the blocklist manually. Only available with the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    pub fn block_ip(&self, ip: &str, reason: &str) -> bool {
        self.database.lock().unwrap().as_ref()
            .map(|db| db.add_to_blocklist(ip, reason, true).is_ok()).unwrap_or(false)
    }

    /// Remove an IP from the blocklist. Only available with the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    pub fn unblock_ip(&self, ip: &str) -> bool {
        self.database.lock().unwrap().as_ref()
            .map(|db| db.remove_from_blocklist(ip).is_ok()).unwrap_or(false)
    }

    /// Add an IP to the whitelist. Only available with the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    pub fn whitelist_ip(&self, ip: &str, reason: &str) -> bool {
        self.database.lock().unwrap().as_ref()
            .map(|db| db.add_to_whitelist(ip, reason).is_ok()).unwrap_or(false)
    }

    /// Render current Prometheus metrics text. Only available with the `prometheus` feature.
    #[cfg(feature = "prometheus")]
    pub fn render_metrics(&self) -> String {
        self.metrics.as_ref().map(|m| m.render_metrics()).unwrap_or_default()
    }

    /// Access the WAF configuration. For runtime updates, create a new instance with `GargouilleWaf::new()`.
    pub fn config(&self) -> &WafConfig {
        &self.config
    }

    // ── Private helpers ─────────────────────────────────────

    /// Open database connection for blocklist/audit-log storage.
    #[cfg(feature = "sqlite")]
    fn open_database(config: &WafConfig) -> Option<WafDatabase> {
        let db_path = config.blocklist.database_path.clone();
        if !config.blocklist.enabled || db_path.is_empty() {
            return None;
        }
        match WafDatabase::open(&db_path) {
            Ok(db) => Some(db),
            Err(e) => {
                eprintln!("Warning: Failed to open database at '{}': {}", db_path, e);
                None
            }
        }
    }

    /// Create metrics collector if enabled in config.
    #[cfg(feature = "prometheus")]
    fn make_metrics(config: &WafConfig) -> Option<WafMetrics> {
        if config.metrics.enabled {
            Some(WafMetrics::new())
        } else {
            None
        }
    }

    /// Audit-log helper that records full threat details including score and rule IDs.
    fn audit_log_with_score(
        &self,
        request: &HttpRequest,
        _reason: &str,
        threat_score: u32,
        rule_ids: &[String],
    ) {
        #[cfg(feature = "sqlite")]
        if self.config.logging.log_blocked {
            let guard = self.database.lock().unwrap();
            let _ = guard.as_ref().and_then(|db| {
                db.log_threat(
                    &request.remote_addr.ip().to_string(),
                    &request.path,
                    threat_score,
                    "blocked",
                    rule_ids,
                )
                .ok()
            });
        }
    }
}

/// Decision made after WAF evaluation.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Request passes — forwarded to upstream.
    Pass,
    /// Request is blocked with a reason.
    Blocked(BlockingReason),
    /// Client must complete a challenge (JS/CAPTCHA).
    Challenge,
    /// Client has exceeded rate limits.
    RateLimited,
}
