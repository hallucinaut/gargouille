//! Persistent storage using SQLite — blocklists, rule storage, audit logs.
//! Uses the rusqlite crate with connection pooling via a simple mutex wrapper.

use rusqlite::{Connection, Result, params};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Validate that an IP string is a valid IPv4 or IPv6 address.
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<Ipv6Addr>().is_ok()
}

/// Extract client IP from X-Forwarded-For header if present and valid.
pub fn extract_client_ip(remote_addr: SocketAddr, forwarded_for: Option<&[String]>) -> String {
    if let Some(ff) = forwarded_for {
        if let Some(first) = ff.first() {
            if is_valid_ip(first) {
                return first.to_string();
            }
        }
    }
    remote_addr.ip().to_string()
}

/// Validate IP format (IPv4 or IPv6).
pub fn validate_ip(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().is_ok() || ip.parse::<std::net::Ipv6Addr>().is_ok()
}
// ──────────────── Schema ─────────────────────────────────

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS blocklist_ips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT UNIQUE NOT NULL,
    reason      TEXT DEFAULT 'security',
    blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME,
    auto_unblock INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_blocklist_ip ON blocklist_ips(ip);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip          TEXT NOT NULL,
    path        TEXT,
    threat_score INTEGER DEFAULT 0,
    action      TEXT DEFAULT 'log',
    rule_ids    TEXT DEFAULT '',
    details     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ip ON audit_log(ip);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

CREATE TABLE IF NOT EXISTS waf_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    severity    TEXT DEFAULT 'medium',
    action      TEXT DEFAULT 'block',
    enabled     INTEGER DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT UNIQUE NOT NULL,
    reason      TEXT DEFAULT 'trusted',
    added_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
"#;

// ──────────────── Database Service ───────────────────────

#[derive(Debug)]
pub struct WafDatabase {
    conn: Connection,
}

impl WafDatabase {
    /// Open or create the database at the given path.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    // ── Blocklist operations ────────────────────────────

    /// Check if an IP is blocklisted. Returns Some(reason) if found.
    pub fn is_ip_blocked(&self, ip: &str) -> Option<String> {
        let mut stmt = self.conn.prepare(
            "SELECT reason FROM blocklist_ips WHERE ip = ?1 AND (expires_at IS NULL OR expires_at > datetime('now'))"
        ).ok()?;

        stmt.query_row([ip], |row| row.get::<_, String>(0)).ok()
    }

    /// Add an IP to the blocklist. Validates IP format before insertion.
    pub fn add_to_blocklist(&self, ip: &str, reason: &str, auto_unblock: bool) -> Result<()> {
        if !is_valid_ip(ip) {
            eprintln!("⚠ Skipped blocklist insert: invalid IP address {}", ip);
            return Ok(());
        }
        if auto_unblock {
            self.conn.execute(
                "INSERT OR IGNORE INTO blocklist_ips (ip, reason, expires_at, auto_unblock) VALUES (?1, ?2, datetime('now', '+60 minutes'), 1)",
                params![ip, reason],
            )?;
        } else {
            self.conn.execute(
                "INSERT OR IGNORE INTO blocklist_ips (ip, reason, expires_at, auto_unblock) VALUES (?1, ?2, NULL, 0)",
                params![ip, reason],
            )?;
        }
        Ok(())
    }

    /// Remove an IP from the blocklist.
    pub fn remove_from_blocklist(&self, ip: &str) -> Result<usize> {
        self.conn.execute("DELETE FROM blocklist_ips WHERE ip = ?1", [ip])
    }

    // ── Audit logging ───────────────────────────────────

    /// Log a blocked request event with full threat details.
    pub fn log_threat(&self, ip: &str, path: &str, threat_score: u32, action: &str, rule_ids: &[String]) -> Result<()> {
        let rule_id_str = rule_ids.join(",");
        self.conn.execute(
            "INSERT INTO audit_log (ip, path, threat_score, action, rule_ids) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip, path, threat_score as i64, action, rule_id_str],
        )?;
        Ok(())
    }

    /// Get recent threats (last N entries).
    pub fn get_recent_threats(&self, limit: usize) -> Result<Vec<ThreatEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, path, threat_score, action, rule_ids, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?1"
        )?;

        let mut entries = Vec::new();
        for entry_result in stmt.query_map([limit], |row| {
            Ok(ThreatEntry {
                ip: row.get::<_, String>(0).unwrap_or_default(),
                path: row.get::<_, String>(1).unwrap_or_default(),
                threat_score: row.get::<_, u32>(2).unwrap_or_default(),
                action: row.get::<_, String>(3).unwrap_or_default(),
                rule_ids: row.get::<_, String>(4).unwrap_or_default(),
                timestamp: row.get::<_, String>(5).unwrap_or_default(),
            })
        })?
        {
            entries.push(entry_result?);
        }

        Ok(entries)
    }

    // ── Whitelist ───────────────────────────────────────

    pub fn is_ip_whitelisted(&self, ip: &str) -> bool {
        self.conn.query_row(
            "SELECT COUNT(*) FROM user_whitelist WHERE ip = ?1",
            [ip],
            |row| row.get::<_, u64>(0),
        )
        .map(|count| count > 0)
        .unwrap_or(false)
    }

    /// Add an IP to the whitelist. Validates IP format before insertion.
    pub fn add_to_whitelist(&self, ip: &str, reason: &str) -> Result<()> {
        if !is_valid_ip(ip) {
            eprintln!("⚠ Skipped blocklist insert: invalid IP address {}", ip);
            return Ok(());
        }
        self.conn.execute(
            "INSERT OR IGNORE INTO user_whitelist (ip, reason) VALUES (?1, ?2)",
            params![ip, reason],
        )?;
        Ok(())
    }

    // ── Stats ───────────────────────────────────────────

    pub fn get_blocklist_count(&self) -> Result<u64> {
        self.conn.query_row("SELECT COUNT(*) FROM blocklist_ips", [], |row| row.get(0))
    }

    pub fn get_audit_count(&self) -> Result<u64> {
        self.conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
    }
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;

    fn setup_test_db() -> WafDatabase {
        // Use in-memory SQLite for tests since /tmp may have permission issues
        WafDatabase::open(":memory:").expect("Failed to create test database")
    }

    #[test]
    fn test_database_schema_created() {
        let db = setup_test_db();
        let count = db.get_blocklist_count().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_add_and_check_blocklist() {
        let db = setup_test_db();
        let _ = db.add_to_blocklist("192.168.1.100", "test block", true);
        let reason = db.is_ip_blocked("192.168.1.100");
        assert!(reason.is_some());
    }

    #[test]
    fn test_blocklist_not_found() {
        let db = setup_test_db();
        let reason = db.is_ip_blocked("10.0.0.99");
        assert!(reason.is_none());
    }

    #[test]
    fn test_remove_from_blocklist() {
        let db = setup_test_db();
        let _ = db.add_to_blocklist("172.16.0.5", "temp block", false);
        assert!(db.is_ip_blocked("172.16.0.5").is_some());

        let removed = db.remove_from_blocklist("172.16.0.5").unwrap();
        assert_eq!(removed, 1);
        assert!(db.is_ip_blocked("172.16.0.5").is_none());
    }

    #[test]
    fn test_audit_log_threat() {
        let db = setup_test_db();
        let _ = db.log_threat("192.168.1.1", "/api/login", 75, "blocked", &["SQLI-001".into()]);
        let count = db.get_audit_count().unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_get_recent_threats() {
        let db = setup_test_db();
        let _ = db.log_threat("10.0.0.1", "/page", 30, "blocked", &["XSS-001".into()]);
        let _ = db.log_threat("10.0.0.2", "/api", 60, "blocked", &["CMDI-001".into()]);

        let threats = db.get_recent_threats(5).unwrap();
        assert_eq!(threats.len(), 2);
    }

    #[test]
    fn test_whitelist_ip() {
        let db = setup_test_db();
        assert!(db.add_to_whitelist("127.0.0.1", "localhost").is_ok());
        assert!(db.is_ip_whitelisted("127.0.0.1"));
        assert!(!db.is_ip_whitelisted("192.168.1.1"));
    }

    #[test]
    fn test_duplicate_blocklist_insert() {
        let db = setup_test_db();
        let _ = db.add_to_blocklist("10.10.10.10", "first reason", true);
        let _ = db.add_to_blocklist("10.10.10.10", "second reason", false);

        // Should still have only 1 entry due to UNIQUE constraint
        let count = db.get_blocklist_count().unwrap();
        assert_eq!(count, 1);
    }
}

/// An entry from the audit log.
#[derive(Debug)]
pub struct ThreatEntry {
    pub ip: String,
    pub path: String,
    pub threat_score: u32,
    pub action: String,
    pub rule_ids: String,
    pub timestamp: String,
}
