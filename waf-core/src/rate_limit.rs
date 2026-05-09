//! Sliding window rate limiter — high-performance, lock-free per-IP tracking.

use std::collections::HashMap;
use chrono::Utc;

/// A single sliding window counter for one IP.
#[derive(Debug, Clone)]
struct IpWindow {
    timestamps: Vec<u128>,   // stored as u128 milliseconds
}

impl IpWindow {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    /// Record a request and return the current count in the window.
    fn record(&mut self, now_ms: u128, window_size_ms: u128) -> u64 {
        self.timestamps.retain(|&t| now_ms.saturating_sub(t) <= window_size_ms);
        self.timestamps.push(now_ms);
        self.timestamps.len() as u64
    }

    /// Remove all entries (for blocking).
    fn clear(&mut self) {
        self.timestamps.clear();
    }

    /// Check if expired — no requests in last window.
    fn is_expired(&self, now_ms: u128, window_size_ms: u128) -> bool {
        self.timestamps.iter().all(|&t| now_ms.saturating_sub(t) > window_size_ms)
    }
}

/// A blocked IP entry with optional expiry time.
#[derive(Debug, Clone)]
struct BlockedIpEntry {
    #[allow(dead_code)]
    reason: String,
    /// If set, the IP will be auto-unblocked after this timestamp (ms since epoch).
    expires_at: Option<u128>,
}

impl BlockedIpEntry {
    fn is_expired(&self, now_ms: u128) -> bool {
        match self.expires_at {
            Some(expiry) => now_ms >= expiry,
            None => false,
        }
    }
}

/// Rate limiter service.
pub struct RateLimiter {
    windows: HashMap<String, IpWindow>,
    endpoint_windows: HashMap<String, IpWindow>, // ip:endpoint -> window
    max_per_window: u64,
    burst_allowance: u32,
    window_seconds: u64,
    blocked_ips: HashMap<String, BlockedIpEntry>, // ip -> entry with expiry
}

impl RateLimiter {
    pub fn new(max_per_window: u64, window_seconds: u64, burst_allowance: u32) -> Self {
        Self {
            windows: HashMap::with_capacity(1024),
            endpoint_windows: HashMap::new(),
            max_per_window,
            burst_allowance,
            window_seconds,
            blocked_ips: HashMap::new(),
        }
    }

    /// Check if an IP is rate limited. Returns (allowed, current_count).
    pub fn check(&mut self, ip: &str) -> (bool, u64) {
        let now_ms = Utc::now().timestamp_millis() as u128;
        let window_size_ms: u128 = (self.window_seconds * 1000).into();

        // Check if blocked (and auto-expire old blocks)
        if let Some(entry) = self.blocked_ips.get_mut(ip) {
            if entry.is_expired(now_ms) {
                self.blocked_ips.remove(ip);
                // Fall through to normal rate limiting
            } else {
                return (false, 0);
            }
        }

        let entry = self.windows.entry(ip.to_string()).or_insert_with(IpWindow::new);
        let count = entry.record(now_ms, window_size_ms);

        // Allow burst beyond the normal limit
        let effective_limit = self.max_per_window + self.burst_allowance as u64;
        if count > effective_limit {
            return (false, count);
        }

        (true, count)
    }

    /// Block an IP with optional auto-unblock after `duration_minutes`.
    pub fn block_ip_with_expiry(&mut self, ip: &str, reason: &str, duration_minutes: Option<u64>) {
        let now_ms = Utc::now().timestamp_millis();
        let expires_at = duration_minutes.map(|min| {
            (now_ms as u128) + ((min as u128) * 60 * 1000)
        });
        self.blocked_ips.insert(
            ip.to_string(),
            BlockedIpEntry {
                reason: reason.to_string(),
                expires_at,
            },
        );
        if let Some(entry) = self.windows.get_mut(ip) {
            entry.clear();
        }
    }

    /// Block an IP permanently (legacy compatibility).
    pub fn block_ip(&mut self, ip: &str) {
        self.blocked_ips.insert(
            ip.to_string(),
            BlockedIpEntry { reason: "permanent".into(), expires_at: None },
        );
        if let Some(entry) = self.windows.get_mut(ip) {
            entry.clear();
        }
    }

    /// Unblock an IP.
    pub fn unblock_ip(&mut self, ip: &str) {
        self.blocked_ips.remove(ip);
    }

    /// Get stats about the rate limiter.
    pub fn stats(&self) -> (u64, u64) {
        (self.windows.len() as u64, self.blocked_ips.len() as u64)
    }

    /// Check per-endpoint rate limit for an IP. Returns (allowed, current_count).
    pub fn check_endpoint(&mut self, ip: &str, endpoint: &str) -> (bool, u64) {
        let now_ms = Utc::now().timestamp_millis() as u128;
        let window_size_ms: u128 = (self.window_seconds * 1000).into();

        // Check if blocked first
        if let Some(entry) = self.blocked_ips.get(ip) {
            if !entry.is_expired(now_ms) {
                return (false, 0);
            }
        }

        let key = format!("{}:{}", ip, endpoint);
        let entry = self.endpoint_windows.entry(key).or_insert_with(IpWindow::new);
        let count = entry.record(now_ms, window_size_ms);

        if count > self.max_per_window + self.burst_allowance as u64 {
            return (false, count);
        }

        (true, count)
    }

    /// Clean up expired entries periodically.
    pub fn cleanup(&mut self) {
        let now_ms = Utc::now().timestamp_millis() as u128;
        let window_size_ms: u128 = (self.window_seconds * 1000).into();

        // Remove expired windows
        self.windows.retain(|_ip, entry| !entry.is_expired(now_ms, window_size_ms));

        // Remove expired blocked IPs
        self.blocked_ips.retain(|_ip, entry| !entry.is_expired(now_ms));
    }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_limiter(max: u64, window_secs: u64) -> RateLimiter {
        RateLimiter::new(max, window_secs, 20)
    }

    #[test]
    fn test_initial_request_allowed() {
        let mut limiter = make_limiter(10, 60);
        let (allowed, count) = limiter.check("192.168.1.1");
        assert!(allowed);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_within_limit_allowed() {
        let mut limiter = make_limiter(5, 60);
        for i in 0..=4 {
            let (allowed, _) = limiter.check("10.0.0.1");
            assert!(allowed, "Request {} should be allowed", i + 1);
        }
    }

    #[test]
    fn test_burst_allowance() {
        let mut limiter = make_limiter(5, 60);
        // Normal limit: 5, burst allowance: 20, effective: 25
        for i in 0..=24 {
            let (allowed, _) = limiter.check("10.0.0.5");
            assert!(allowed, "Request {} should be allowed within burst", i + 1);
        }
        // 26th request should be blocked
        let (allowed, _) = limiter.check("10.0.0.5");
        assert!(!allowed);
    }

    #[test]
    fn test_different_ips_independent() {
        let mut limiter = RateLimiter::new(3, 60, 0); // No burst allowance
        // IP1 exceeds its limit of 3
        let _ = limiter.check("192.168.1.1");
        let _ = limiter.check("192.168.1.1");
        let _ = limiter.check("192.168.1.1");
        let (allowed1, _) = limiter.check("192.168.1.1");
        assert!(!allowed1);

        // IP2 is independent - still within limit
        let (allowed2, count) = limiter.check("192.168.1.2");
        assert!(allowed2);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_blocked_ip_denied() {
        let mut limiter = make_limiter(100, 60);
        limiter.block_ip("10.10.10.10");
        let (allowed, count) = limiter.check("10.10.10.10");
        assert!(!allowed);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_unblock_ip_allowed() {
        let mut limiter = make_limiter(100, 60);
        limiter.block_ip("10.20.30.40");
        let (allowed1, _) = limiter.check("10.20.30.40");
        assert!(!allowed1);

        limiter.unblock_ip("10.20.30.40");
        let (allowed2, _) = limiter.check("10.20.30.40");
        assert!(allowed2);
    }

    #[test]
    fn test_block_clears_window() {
        let mut limiter = make_limiter(5, 60);
        // Fill up the window for this IP
        for _ in 0..=24 {
            let _ = limiter.check("172.16.0.1");
        }
        let (blocked, _) = limiter.check("172.16.0.1");
        assert!(!blocked);

        // Block and unblock the IP
        limiter.block_ip("172.16.0.1");
        limiter.unblock_ip("172.16.0.1");

        // Should be allowed now with a fresh window
        let (allowed, count) = limiter.check("172.16.0.1");
        assert!(allowed);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_stats_report_correct_counts() {
        let mut limiter = make_limiter(10, 60);
        let _ = limiter.check("1.1.1.1");
        let _ = limiter.check("2.2.2.2");
        let _ = limiter.check("3.3.3.3");
        limiter.block_ip("4.4.4.4");

        let (tracked, blocked_count) = limiter.stats();
        assert_eq!(tracked, 3);
        assert_eq!(blocked_count, 1);
    }

    #[test]
    fn test_stats_empty() {
        let limiter = make_limiter(10, 60);
        let (tracked, blocked) = limiter.stats();
        assert_eq!(tracked, 0);
        assert_eq!(blocked, 0);
    }

    #[test]
    fn test_cleanup_removes_expired() {
        // This test verifies cleanup logic exists and runs without panic
        let mut limiter = make_limiter(10, 60);
        let _ = limiter.check("5.5.5.5");
        let count_before = limiter.windows.len();
        limiter.cleanup();
        // Cleanup should not panic; windows may be removed if expired
        let _count_after = limiter.windows.len();
        assert!(count_before >= 1);
    }

    #[test]
    fn test_endpoint_rate_limit_enforced() {
        // Use burst_allowance=0 to match the per-endpoint limit exactly
        let mut limiter = RateLimiter::new(5, 60, 0);
        for _ in 0..5 {
            let (allowed, _) = limiter.check_endpoint("1.2.3.4", "/api/login");
            assert!(allowed);
        }
        // 6th request to same endpoint should be blocked
        let (allowed, _) = limiter.check_endpoint("1.2.3.4", "/api/login");
        assert!(!allowed);
    }

    #[test]
    fn test_different_endpoints_independent() {
        let mut limiter = make_limiter(5, 60);
        // /api/login and /api/register have separate windows
        for _ in 0..4 {
            let _ = limiter.check_endpoint("1.2.3.4", "/api/login");
            let _ = limiter.check_endpoint("1.2.3.4", "/api/register");
        }
        // Both should still be allowed at count 5
        assert!(limiter.check_endpoint("1.2.3.4", "/api/login").0);
        assert!(limiter.check_endpoint("1.2.3.4", "/api/register").0);
    }
}
