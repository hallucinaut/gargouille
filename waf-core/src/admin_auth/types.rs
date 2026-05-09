//! Admin auth types — data structures for secure admin access control.

use std::fmt;

/// The path configuration used for generating unpredictable admin prefixes.
#[derive(Debug, Clone)]
pub struct AdminPathConfig {
    /// Secret seed used to derive the randomized path prefix.
    pub(crate) secret: String,
    /// Length of the path segment (excluding leading '/').
    pub(crate) path_length: u32,
}

/// Results from admin path token generation.
#[derive(Debug, Clone)]
pub enum TokenGenerationResult {
    /// A hex-encoded random token for use in X-Admin-Token header.
    GeneratedToken(String),
    /// A randomized path prefix (hex string) to prepend to all admin routes.
    GeneratedPathPrefix(String),
}

/// Validated admin commands that can be dispatched after auth passes.
#[derive(Debug, Clone)]
pub struct AdminCommand {
    /// The action to perform: block, unblock, whitelist, status, metrics.
    pub action: String,
    /// Optional target IP address (for block/unblock/whitelist).
    pub target_ip: Option<String>,
}

/// Error returned when admin authentication fails.
#[derive(Debug)]
pub struct AdminAuthError(pub String);

impl fmt::Display for AdminAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Constant-time comparison of two strings.
/// Prevents timing side-channel attacks on token validation.
pub fn const_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut diff = 0u8;
    for i in 0..a_bytes.len() {
        diff |= a_bytes[i] ^ b_bytes[i];
    }
    diff == 0
}

/// Results from authenticating an admin request.
#[derive(Debug)]
pub struct AuthResult {
    /// Whether authentication succeeded.
    pub authorized: bool,
    /// Optional parsed command (present only if authorized).
    pub command: Option<AdminCommand>,
}

impl AuthResult {
    /// Create a successful auth result with the parsed command.
    pub fn ok(command: AdminCommand) -> Self {
        Self { authorized: true, command: Some(command) }
    }

    /// Create a failed auth result with an error message.
    pub fn fail(reason: AdminAuthError) -> Self {
        Self { authorized: false, command: None }
    }
}
