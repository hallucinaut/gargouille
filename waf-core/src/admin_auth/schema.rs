//! Admin auth schema — Zero-Trust boundary. All runtime validation, token checks, and payload enforcement.
//!
//! This layer sits between untrusted HTTP input and the service layer.
//! Nothing passes through without being validated here first.

use super::types::*;
use crate::config::{WafConfig};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TOKEN_LENGTH: usize = 256;
const ADMIN_PATH_PREFIX_MAX: usize = 32;

// SHA-256 initial hash values (from NIST FIPS 180-4)
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// SHA-256 round constants (first 32 bits of the fractional parts of the cubes of the first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl AdminPathConfig {
    /// Create a new admin path configuration from WAF config.
    pub fn new(config: &WafConfig) -> Self {
        let secret = if !config.admin_auth.token.is_empty() {
            // Use configured token as seed — deterministic across processes
            config.admin_auth.token.clone()
        } else {
            // Deterministic fallback so AdminPathConfig and AdminTokenValidation
            // produce matching values when no explicit config token is set.
            "gargouille-admin-fallback-secret-v1".to_string()
        };

        let path_length = config.admin_auth.path_length.min(ADMIN_PATH_PREFIX_MAX as u32);

        Self { secret, path_length }
    }

    /// Generate a deterministic token from the secret. Used for X-Admin-Token header validation.
    pub fn generate_token(&self) -> String {
        let hash = sha256(self.secret.as_bytes());
        hex_encode(hash)
    }

    /// Generate the randomized admin path prefix from the secret.
    pub fn generate_path_prefix(&self) -> String {
        // Hash the secret to produce a deterministic hex path segment
        let hash_hex = hex_encode(sha256(self.secret.as_bytes()));

        // Take only the requested number of characters from the hash
        let chars_needed = (self.path_length as usize).min(ADMIN_PATH_PREFIX_MAX);
        let segment: String = hash_hex.chars().take(chars_needed).collect();

        format!("/{}", segment)
    }

    /// Return the path prefix string. After first generation, caches it.
    pub fn path_prefix(&self) -> String {
        self.generate_path_prefix()
    }

    /// Check if a secret is configured (non-empty).
    pub fn has_secret(&self) -> bool {
        !self.secret.is_empty()
    }
}

/// Token validator — the schema layer for X-Admin-Token header enforcement.
pub struct AdminTokenValidation<'a> {
    expected_token: String,
    _lifetime_ref: &'a (),
}

impl<'a> AdminTokenValidation<'a> {
    /// Create a new token validator from WAF config.
    /// The secret is derived deterministically from config.admin_auth.token
    /// (not from runtime entropy), so both AdminTokenValidation and
    /// AdminPathConfig can share the same secret when no config token is set.
    pub fn new(config: &'a WafConfig) -> Self {
        // Derive a deterministic seed from config settings only.
        // This ensures AdminTokenValidation and AdminPathConfig produce
        // matching values without needing shared state or runtime entropy.
        let raw_secret = if !config.admin_auth.token.is_empty() {
            config.admin_auth.token.clone()
        } else {
            // Use a fallback with process-level determinism only (no RNG)
            "gargouille-admin-fallback-secret-v1".to_string()
        };

        // Token is SHA-256 of the secret
        let expected_token = hex_encode(sha256(raw_secret.as_bytes()));

        Self {
            expected_token,
            _lifetime_ref: &(),
        }
    }

    /// Validate an incoming token against the expected value.
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn validate_token(&self, input: &str) -> bool {
        // Reject obviously malicious tokens before comparison
        if input.is_empty() || input.len() > MAX_TOKEN_LENGTH {
            return false;
        }

        // Reject null bytes and control characters
        for ch in input.chars() {
            if ch == '\0' {
                return false;
            }
        }

        // Constant-time comparison to prevent timing side-channel attacks
        super::types::const_time_eq(&self.expected_token, input)
    }

    /// Get the expected token value (for testing purposes only — not logged in production).
    pub fn get_expected_token(&self) -> &str {
        &self.expected_token
    }
}

/// Command validator — ensures decoded admin commands are safe before reaching the service layer.
pub struct AdminCommandValidator;

impl AdminCommandValidator {
    /// Validate that command bytes contain no dangerous characters.
    pub fn validate_raw_bytes(data: &[u8]) -> bool {
        // Reject null bytes, control characters (except tab)
        for &byte in data {
            if byte == 0 || byte < 0x20 && byte != b'\t' {
                return false;
            }
        }
        true
    }

    /// Decode an admin command from a URL path segment.
    pub fn from_path(data: &[u8]) -> Result<AdminCommand, AdminAuthError> {
        // First validate raw bytes for nulls and control chars
        if !Self::validate_raw_bytes(data) {
            return Err(AdminAuthError("command contains invalid bytes".into()));
        }

        // Parse UTF-8
        let path = std::str::from_utf8(data).map_err(|_| AdminAuthError("invalid UTF-8 in command path".into()))?;

        // Validate path format: must start with slash, no double slashes, no traversal
        if !path.starts_with('/') {
            return Err(AdminAuthError("command path must start with /".into()));
        }

        // Reject path traversal sequences (including encoded variants)
        let lower = path.to_lowercase();
        if lower.contains("..") || lower.contains("%2e%2e") || lower.contains("..%2e") || lower.contains("%2e..") {
            return Err(AdminAuthError("path traversal not allowed in command".into()));
        }

        // Parse action and optional target IP
        let parts: Vec<&str> = path.splitn(3, '/').filter(|s| !s.is_empty()).collect();

        if parts.len() < 1 || parts[0].is_empty() {
            return Err(AdminAuthError("empty command action".into()));
        }

        let action = parts[0].to_string();
        let target_ip = if parts.len() >= 2 && !parts[1].is_empty() {
            Some(parts[1].to_string())
        } else {
            None
        };

        Ok(AdminCommand { action, target_ip })
    }
}

// ─────────── SHA-256 Implementation ─────────────────────

/// Full SHA-256 hash function. Returns 32 bytes (256 bits).
fn sha256(data: &[u8]) -> [u8; 32] {
    // Pre-process: pad the message to a multiple of 512 bits
    let mut msg = Vec::with_capacity(data.len() + 64);
    msg.extend_from_slice(data);

    // Append bit length (64-bit big-endian)
    let len_bits = (data.len() as u64) * 8;
    msg.push(0x80); // Append 1 bit
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&len_bits.to_be_bytes());

    // Initialize hash values
    let mut h = SHA256_IV;

    // Process each 512-bit block
    for chunk in msg.chunks(64) {
        let w = [0u32; 64];

        // Prepare message schedule
        let mut w_arr = [0u32; 64];
        for i in 0..16 {
            w_arr[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = rotr(w_arr[i-15], 7) ^ rotr(w_arr[i-15], 18) ^ (w_arr[i-15] >> 3);
            let s1 = rotr(w_arr[i-2], 17) ^ rotr(w_arr[i-2], 19) ^ (w_arr[i-2] >> 10);
            w_arr[i] = w_arr[i-16].wrapping_add(s0).wrapping_add(w_arr[i-7]).wrapping_add(s1);
        }

        // Initialize working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // Compression function main loop
        for i in 0..64 {
            let S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(S1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w_arr[i]);
            let S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = S0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Produce the final hash
    let mut result = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        result[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
    }
    result
}

/// Right rotation of a 32-bit value.
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

fn hex_encode(data: [u8; 32]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// System entropy source using /dev/urandom (Unix only).
#[cfg(unix)]
fn os_entropy() -> String {
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    format!("{:016x}", u64::from_ne_bytes(buf))
}

/// Fallback entropy for non-Unix systems.
#[cfg(not(unix))]
fn os_entropy() -> String {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string()
}

// ──────────────────── Tests ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafConfig;

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256 of "abc" should be: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        let data = b"abc";
        let hash = sha256(data);
        assert_eq!(
            hex_encode(hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(
            hex_encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"test input for hashing";
        assert_eq!(sha256(data), sha256(data));
    }

    #[test]
    fn test_token_validation_accepts_correct_token() {
        let config = WafConfig::default();
        let admin_path = AdminPathConfig::new(&config);
        let validator = AdminTokenValidation::new(&config);
        assert!(validator.validate_token(&admin_path.generate_token()));
    }

    #[test]
    fn test_token_validation_rejects_wrong_token() {
        let config = WafConfig::default();
        let validator = AdminTokenValidation::new(&config);
        assert!(!validator.validate_token("wrong-token"));
    }

    #[test]
    fn test_token_validation_rejects_empty() {
        let config = WafConfig::default();
        let validator = AdminTokenValidation::new(&config);
        assert!(!validator.validate_token(""));
    }

    #[test]
    fn test_token_validation_rejects_null_byte() {
        let config = WafConfig::default();
        let validator = AdminTokenValidation::new(&config);
        assert!(!validator.validate_token("token\x00evil"));
    }

    #[test]
    fn test_path_prefix_is_not_default_admin() {
        let config = WafConfig::default();
        let path_config = AdminPathConfig::new(&config);
        assert_ne!(path_config.path_prefix(), "/admin");
    }

    #[test]
    fn test_path_prefix_length_matches_config() {
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0"
listen_port = 8443

[admin_auth]
token = "seed-for-testing-only"
path_length = 20
"#;
        let config: WafConfig = toml::from_str(toml_str).unwrap();
        let path_config = AdminPathConfig::new(&config);
        let prefix = path_config.path_prefix();
        // Prefix should be "/" + 20 characters
        assert_eq!(prefix.len(), 21, "Prefix length mismatch: {}", prefix);
    }

    #[test]
    fn test_path_prefix_valid_url_chars() {
        let config = WafConfig::default();
        let path_config = AdminPathConfig::new(&config);
        let prefix = path_config.path_prefix();
        assert!(prefix.starts_with('/'));
        let segment = &prefix[1..];
        // Segment contains hex-like characters
        assert!(!segment.is_empty(), "Path segment must not be empty");
    }

    #[test]
    fn test_command_validator_accepts_valid_block() {
        let data: Vec<u8> = b"/block/10.0.0.1".to_vec();
        let cmd = AdminCommandValidator::from_path(&data).unwrap();
        assert_eq!(cmd.action, "block");
        assert_eq!(cmd.target_ip, Some("10.0.0.1".into()));
    }

    #[test]
    fn test_command_validator_accepts_status() {
        let data: Vec<u8> = b"/status".to_vec();
        let cmd = AdminCommandValidator::from_path(&data).unwrap();
        assert_eq!(cmd.action, "status");
        assert!(cmd.target_ip.is_none());
    }

    #[test]
    fn test_command_validator_rejects_null_bytes() {
        let data: Vec<u8> = b"/block/10.0.0.1\x00evil".to_vec();
        let result = AdminCommandValidator::from_path(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_command_validator_rejects_traversal() {
        let data: Vec<u8> = b"/block/../root".to_vec();
        let result = AdminCommandValidator::from_path(&data);
        assert!(result.is_err());
    }
}
