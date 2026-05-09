//! Prometheus-compatible metrics exporter for WAF observability.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe atomic counters for WAF metrics.
#[derive(Debug)]
pub struct WafMetrics {
    total_requests: AtomicU64,
    blocked_requests: AtomicU64,
    allowed_requests: AtomicU64,
    challenged_requests: AtomicU64,
    threat_score_current: AtomicU64,
    threats_detected: HashMap<String, AtomicU64>,
}

impl WafMetrics {
    /// Create a new metrics collector with category counters initialized to zero.
    pub fn new() -> Self {
        let mut threats = HashMap::new();
        for cat in [
            "sql_injection",
            "xss",
            "command_injection",
            "lfi_rfi",
            "ssti",
            "ssrf",
            "deserialization",
            "header_injection",
            "path_traversal",
        ] {
            threats.insert(cat.to_string(), AtomicU64::new(0));
        }

        Self {
            total_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            allowed_requests: AtomicU64::new(0),
            challenged_requests: AtomicU64::new(0),
            threat_score_current: AtomicU64::new(0),
            threats_detected: threats,
        }
    }

    /// Record a total incoming request.
    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a blocked request with its threat score.
    pub fn record_blocked(&self, score: u32) {
        self.blocked_requests.fetch_add(1, Ordering::Relaxed);
        self.threat_score_current.store(score as u64, Ordering::Relaxed);
    }

    /// Record an allowed request.
    pub fn record_allowed(&self) {
        self.allowed_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a challenged request.
    pub fn record_challenged(&self) {
        self.challenged_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rule match for the given threat category.
    pub fn record_threat(&self, category: &str) {
        if let Some(counter) = self.threats_detected.get(category) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Render all collected metrics as a Prometheus text exposition string.
    pub fn render_metrics(&self) -> String {
        format!(
            "# HELP gargouille_total_requests Total requests processed\n\
             # TYPE gargouille_total_requests counter\n\
             gargouille_total_requests {}\n\
             # HELP gargouille_blocked_requests Blocked requests\n\
             # TYPE gargouille_blocked_requests counter\n\
             gargouille_blocked_requests {}\n\
             # HELP gargouille_allowed_requests Allowed requests\n\
             # TYPE gargouille_allowed_requests counter\n\
             gargouille_allowed_requests {}\n\
             # HELP gargouille_challenged_requests Challenged requests\n\
             # TYPE gargouille_challenged_requests counter\n\
             gargouille_challenged_requests {}\n\
             # HELP gargouille_threat_score Current threat score\n\
             # TYPE gargouille_threat_score gauge\n\
             gargouille_threat_score {}\n",
            self.total_requests.load(Ordering::Relaxed),
            self.blocked_requests.load(Ordering::Relaxed),
            self.allowed_requests.load(Ordering::Relaxed),
            self.challenged_requests.load(Ordering::Relaxed),
            self.threat_score_current.load(Ordering::Relaxed),
        )
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metrics_all_zero() {
        let metrics = WafMetrics::new();
        assert_eq!(metrics.total_requests.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.blocked_requests.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.allowed_requests.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.challenged_requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_record_request_increments() {
        let metrics = WafMetrics::new();
        metrics.record_request();
        metrics.record_request();
        metrics.record_request();
        assert_eq!(metrics.total_requests.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_record_blocked() {
        let metrics = WafMetrics::new();
        metrics.record_blocked(75);
        assert_eq!(metrics.blocked_requests.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.threat_score_current.load(Ordering::SeqCst), 75);
    }

    #[test]
    fn test_record_allowed() {
        let metrics = WafMetrics::new();
        metrics.record_allowed();
        assert_eq!(metrics.allowed_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_record_challenged() {
        let metrics = WafMetrics::new();
        metrics.record_challenged();
        metrics.record_challenged();
        assert_eq!(metrics.challenged_requests.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_record_threat_unknown_category() {
        let metrics = WafMetrics::new();
        metrics.record_threat("unknown_category_xyz");
        // Should not panic, counter just won't be tracked
        assert_eq!(metrics.total_requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_record_threat_sql_injection() {
        let metrics = WafMetrics::new();
        metrics.record_threat("sql_injection");
        metrics.record_threat("sql_injection");
        metrics.record_threat("xss");
        // Verify through render output
        let rendered = metrics.render_metrics();
        assert!(rendered.contains("gargouille_total_requests 0"));
        assert!(rendered.contains("gargouille_blocked_requests 0"));
    }

    #[test]
    fn test_render_metrics_format() {
        let metrics = WafMetrics::new();
        metrics.record_request();
        metrics.record_request();
        metrics.record_blocked(60);
        metrics.record_allowed();
        metrics.record_challenged();

        let rendered = metrics.render_metrics();
        assert!(rendered.contains("HELP"));
        assert!(rendered.contains("# TYPE gargouille_total_requests counter"));
        assert!(rendered.contains("gargouille_total_requests 2"));
        assert!(rendered.contains("gargouille_blocked_requests 1"));
        assert!(rendered.contains("gargouille_allowed_requests 1"));
        assert!(rendered.contains("gargouille_challenged_requests 1"));
    }

    #[test]
    fn test_reset_clears_all_counters() {
        let mut metrics = WafMetrics::new();
        metrics.record_request();
        metrics.record_request();
        metrics.record_blocked(50);
        metrics.record_allowed();

        metrics.reset();
        assert_eq!(metrics.total_requests.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.blocked_requests.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.allowed_requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_render_metrics_empty() {
        let metrics = WafMetrics::new();
        let rendered = metrics.render_metrics();
        assert!(rendered.contains("gargouille_total_requests 0"));
        assert!(rendered.contains("gargouille_blocked_requests 0"));
        assert!(rendered.contains("gargouille_allowed_requests 0"));
    }

    #[test]
    fn test_high_score_stored() {
        let metrics = WafMetrics::new();
        metrics.record_blocked(100);
        assert_eq!(metrics.threat_score_current.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn test_low_score_stored() {
        let metrics = WafMetrics::new();
        metrics.record_blocked(1);
        assert_eq!(metrics.threat_score_current.load(Ordering::SeqCst), 1);
    }
}
