//! Allowlist service — checks if a request path is permitted.
//!
//! Operates in deny-by-default mode: every request is blocked UNLESS:
//! 1. The feature is disabled (default — pass through to upstream), OR
//! 2. The path matches an auto-whitelist entry, OR
//! 3. The path matches a configured allowed_path entry (exact or prefix).

use crate::allowlist_schema::{normalize_path_for_matching, validate_allowed_paths};
use crate::config::WafAllowlistConfig;
use crate::scoring::BlockingReason;
use std::sync::Mutex;

/// Result of an allowlist check.
#[derive(Debug)]
pub enum AllowlistResult {
    /// Path is allowed — request may proceed to upstream or WAF rule evaluation.
    Allowed,
    /// Path is blocked — return this reason to the caller.
    Blocked(BlockingReason),
}

/// Thread-safe allowlist service. Holds normalized entries for O(n) prefix matching.
pub struct AllowlistService {
    enabled: bool,
    entries: Mutex<Vec<String>>,
}

impl AllowlistService {
    /// Create a new allowlist service from config. Validates all paths upfront.
    pub fn new(config: &WafAllowlistConfig) -> Self {
        let (valid, errors) = validate_allowed_paths(&config.allowed_paths);
        for err in &errors {
            eprintln!("WARN: allowlist entry rejected: {}", err);
        }
        // Sort entries by length descending so longer prefixes match first
        let mut sorted = valid;
        sorted.sort_by(|a, b| b.len().cmp(&a.len()));
        Self {
            enabled: config.allowed,
            entries: Mutex::new(sorted),
        }
    }

    /// Check if a request is allowed by the allowlist policy.
    pub fn check_path(&self, uri: &str) -> AllowlistResult {
        // Feature disabled — pass everything through
        if !self.enabled {
            return AllowlistResult::Allowed;
        }

        // Normalize: strip query string and fragment to prevent bypass
        let path = normalize_path_for_matching(uri);

        // Auto-whitelist: admin endpoints are always permitted
        if Self::is_auto_whitelisted(path) {
            return AllowlistResult::Allowed;
        }

        // Check against configured allowed paths (prefix matching)
        let entries_guard = self.entries.lock().unwrap();
        for entry in entries_guard.iter() {
            if path == entry || path.starts_with(&format!("{}/", entry)) {
                return AllowlistResult::Allowed;
            }
        }

        // No match — deny
        AllowlistResult::Blocked(BlockingReason::AllowlistDenied {
            path: path.to_string(),
        })
    }

    /// Check if a path is auto-whitelisted (admin and metrics endpoints).
    fn is_auto_whitelisted(path: &str) -> bool {
        // Admin API endpoints — always accessible for WAF management
        path.starts_with("/admin") || path == "/admin"
            || path.starts_with("/metrics") || path == "/metrics"
    }

    /// Update the allowlist at runtime. Validates all entries before replacing.
    #[allow(dead_code)]
    pub fn update_entries(&self, new_paths: &[String]) -> Vec<String> {
        let (valid, errors) = validate_allowed_paths(new_paths);
        for err in &errors {
            eprintln!("WARN: allowlist entry rejected: {}", err);
        }
        let mut sorted = valid.clone();
        sorted.sort_by(|a, b| b.len().cmp(&a.len()));

        let mut entries = self.entries.lock().unwrap();
        *entries = sorted;

        // Return rejected paths for reporting
        let invalid: Vec<String> = new_paths.iter()
            .filter(|p| !valid.contains(p))
            .cloned()
            .collect();
        invalid
    }

    /// Get the current list of allowed paths.
    #[allow(dead_code)]
    pub fn get_entries(&self) -> Vec<String> {
        self.entries.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafAllowlistConfig;

    fn make_service(allowed: bool, paths: Vec<&str>) -> AllowlistService {
        let config = WafAllowlistConfig {
            allowed,
            allowed_paths: paths.into_iter().map(String::from).collect(),
        };
        AllowlistService::new(&config)
    }

    #[test]
    fn test_disabled_allows_everything() {
        let svc = make_service(false, vec!["/restricted"]);
        assert!(matches!(svc.check_path("/anything"), AllowlistResult::Allowed));
    }

    #[test]
    fn test_allowlisted_exact_match() {
        let svc = make_service(true, vec!["/api/health"]);
        assert!(matches!(svc.check_path("/api/health"), AllowlistResult::Allowed));
    }

    #[test]
    fn test_prefix_match() {
        let svc = make_service(true, vec!["/api"]);
        assert!(matches!(svc.check_path("/api"), AllowlistResult::Allowed));
        assert!(matches!(svc.check_path("/api/users"), AllowlistResult::Allowed));
        assert!(matches!(svc.check_path("/api/v1/data"), AllowlistResult::Allowed));
    }

    #[test]
    fn test_non_match_blocks() {
        let svc = make_service(true, vec!["/api/health"]);
        assert!(matches!(svc.check_path("/secret"), AllowlistResult::Blocked(_)));
    }

    #[test]
    fn test_admin_auto_whitelisted() {
        let svc = make_service(true, vec![]);
        assert!(matches!(svc.check_path("/admin/status"), AllowlistResult::Allowed));
        assert!(matches!(svc.check_path("/admin/block/10.0.0.1"), AllowlistResult::Allowed));
    }

    #[test]
    fn test_metrics_auto_whitelisted() {
        let svc = make_service(true, vec![]);
        assert!(matches!(svc.check_path("/metrics"), AllowlistResult::Allowed));
        assert!(matches!(svc.check_path("/metrics/path"), AllowlistResult::Allowed));
    }

    #[test]
    fn test_query_string_stripped_before_match() {
        let svc = make_service(true, vec!["/api"]);
        // Request /secret?redirect=/api should NOT match — the path is /secret
        assert!(matches!(svc.check_path("/secret?redirect=/api"), AllowlistResult::Blocked(_)));
    }

    #[test]
    fn test_empty_allowlist_blocks_all() {
        let svc = make_service(true, vec![]);
        assert!(matches!(svc.check_path("/"), AllowlistResult::Blocked(_)));
        assert!(matches!(svc.check_path("/api/health"), AllowlistResult::Blocked(_)));
    }

    #[test]
    fn test_update_entries_rejects_invalid() {
        let svc = make_service(true, vec!["/valid"]);
        // No leading slash should be rejected
        let rejected = svc.update_entries(&["no-slash".to_string(), "/also-valid".to_string()]);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0], "no-slash");
    }

    #[test]
    fn test_case_sensitive_match() {
        let svc = make_service(true, vec!["/API"]);
        assert!(matches!(svc.check_path("/api"), AllowlistResult::Blocked(_)));
        assert!(matches!(svc.check_path("/API"), AllowlistResult::Allowed));
    }

    #[test]
    fn test_rejects_traversal_in_config_entry() {
        let svc = make_service(true, vec!["/../etc/passwd"]);
        // Entry was rejected during construction (logged as WARN)
        assert!(matches!(svc.check_path("/../etc/passwd"), AllowlistResult::Blocked(_)));
    }
}
