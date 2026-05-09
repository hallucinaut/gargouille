//! Admin auth service — business logic for admin access control.
//!
//! This layer performs authenticated admin operations. It assumes the schema
//! layer has already validated all input. It interacts with GargouilleWaf
//! to execute block/unblock/whitelist commands and returns results.

use super::types::*;
use super::schema::{AdminCommandValidator, AdminTokenValidation};
use crate::config::WafConfig;

/// Thread-safe admin authentication service.
#[derive(Clone)]
pub struct AdminAuthService {
    expected_token: String,
    path_prefix: String,
}

impl AdminAuthService {
    /// Create a new admin auth service from WAF config.
    pub fn new(config: &WafConfig) -> Self {
        let validator = AdminTokenValidation::new(config);
        let path_config = AdminPathConfig::new(config);

        Self {
            expected_token: validator.get_expected_token().to_string(),
            path_prefix: path_config.path_prefix(),
        }
    }

    /// Authenticate an admin request. Checks token AND validates the command path.
    pub fn authenticate(&self, token: &str, raw_path: &str) -> AuthResult {
        // Step 1: Validate authentication token
        if token.is_empty() || token.len() > 256 || !super::types::const_time_eq(&self.expected_token, token) {
            return AuthResult::fail(AdminAuthError("authentication required".into()));
        }

        // Step 2: Verify the request path uses our randomized admin prefix, not "/admin"
        if !raw_path.starts_with(&self.path_prefix) {
            return AuthResult::fail(AdminAuthError("authentication required".into()));
        }

        // Step 3: Extract and validate the command portion after the admin prefix
        let cmd_bytes = raw_path.as_bytes().get(self.path_prefix.len()..).unwrap_or(&[]);

        if cmd_bytes.is_empty() {
            return AuthResult::fail(AdminAuthError("authentication required".into()));
        }

        // Step 4: Validate command bytes and decode the action/IP
        match AdminCommandValidator::from_path(cmd_bytes) {
            Ok(command) => AuthResult::ok(command),
            Err(_) => AuthResult::fail(AdminAuthError("authentication required".into())),
        }
    }

    /// Get the randomized admin path prefix for route registration.
    pub fn get_path_prefix(&self) -> String {
        self.path_prefix.clone()
    }

    /// Check if a given path matches the configured admin prefix.
    pub fn is_admin_path(&self, raw_path: &str) -> bool {
        raw_path.starts_with(&self.path_prefix)
    }

    /// Get the token value to log at startup (for operator reference).
    pub fn get_log_token_value(&self) -> String {
        // Return partial token for logging (first 8 chars + "...")
        let token = &self.expected_token;
        if token.len() > 16 {
            format!("{}...", &token[0..16])
        } else {
            "token-set".into()
        }
    }
}

impl std::fmt::Debug for AdminAuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminAuthService")
            .field("path_prefix", &self.path_prefix)
            .field("expected_token_masked", &self.get_log_token_value())
            .finish()
    }
}

/// Service methods for executing validated admin commands.
/// These assume the command has been validated by AdminCommandValidator.
pub struct AdminCommandExecutor;

impl AdminCommandExecutor {
    /// Execute a block command on the WAF instance.
    pub fn execute_block(waf: &crate::GargouilleWaf, ip: &str, reason: &str) -> bool {
        #[cfg(feature = "sqlite")]
        return waf.block_ip(ip, reason);

        #[cfg(not(feature = "sqlite"))]
        {
            let _ = (waf, ip, reason);
            true
        }
    }

    /// Execute an unblock command on the WAF instance.
    pub fn execute_unblock(waf: &crate::GargouilleWaf, ip: &str) -> bool {
        #[cfg(feature = "sqlite")]
        return waf.unblock_ip(ip);

        #[cfg(not(feature = "sqlite"))]
        {
            let _ = (waf, ip);
            true
        }
    }

    /// Execute a whitelist command on the WAF instance.
    pub fn execute_whitelist(waf: &crate::GargouilleWaf, ip: &str, reason: &str) -> bool {
        #[cfg(feature = "sqlite")]
        return waf.whitelist_ip(ip, reason);

        #[cfg(not(feature = "sqlite"))]
        {
            let _ = (waf, ip, reason);
            true
        }
    }

    /// Execute a status query — returns JSON-serializable status data.
    pub fn execute_status() -> String {
        // Return minimal status info (no version leakage in non-test builds)
        let status = if cfg!(test) {
            let version = env!("CARGO_PKG_VERSION");
            format!(r#"{{"status":"running","version":"{}"}}"#, version)
        } else {
            r#"{"status":"running"}"#.to_string()
        };
        status
    }

    /// Execute a metrics query — returns the Prometheus text format.
    pub fn execute_metrics(waf: &crate::GargouilleWaf) -> String {
        waf.render_metrics()
    }
}

// ──────────────────── Tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafConfig;

    fn make_service() -> AdminAuthService {
        let config = WafConfig::default();
        AdminAuthService::new(&config)
    }

    #[test]
    fn test_auth_rejects_empty_token() {
        let service = make_service();
        // We can't test with the actual expected token here easily,
        // but we know empty will fail
        let result = service.authenticate("", "/status");
        assert!(!result.authorized);
    }

    #[test]
    fn test_auth_rejects_wrong_token() {
        let service = make_service();
        let result = service.authenticate("wrong-token", "/status");
        assert!(!result.authorized);
    }

    #[test]
    fn test_is_admin_path_rejects_old_admin_prefix() {
        let service = make_service();
        assert!(!service.is_admin_path("/admin/status"));
        assert!(!service.is_admin_path("/admin/block/10.0.0.1"));
    }

    #[test]
    fn test_log_token_value_hides_full_token() {
        let service = make_service();
        let log_value = service.get_log_token_value();
        // Should show partial token, not full 64-char hex string
        assert!(log_value.contains("..."), "Log value must truncate the token: {}", log_value);
    }
}
