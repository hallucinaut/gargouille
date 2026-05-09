//! Path allowlist schema — strict validation of allowed-path entries.
//!
//! Every entry in `allowed_paths` is validated before acceptance:
//! - Must start with `/`
//! - No query strings or fragments
//! - No path traversal sequences (`..`, `\\.`, `%2e%2e`)
//! - No null bytes or control characters
//! - Maximum 512 characters per entry

use std::fmt;

/// Result of validating a single allowlist path entry.
#[derive(Debug)]
pub enum ValidationOutcome {
    /// Path is valid and safe for the allowlist.
    Valid,
    /// Entry rejected — returns a blocking reason if we need to explain why.
    Rejected(AllowlistSchemaError),
}

/// Specific reason an allowlist path entry was rejected.
#[derive(Debug)]
pub enum AllowlistSchemaError {
    Empty,
    NoLeadingSlash,
    ContainsQuery,
    ContainsFragment,
    PathTraversal,
    NullByte,
    ControlCharacter,
    TooLong(usize),
}

impl fmt::Display for AllowlistSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "allowlist entry is empty"),
            Self::NoLeadingSlash => write!(f, "allowlist entry must start with '/'"),
            Self::ContainsQuery => write!(f, "allowlist entry must not contain query string (?)"),
            Self::ContainsFragment => write!(f, "allowlist entry must not contain fragment (#)"),
            Self::PathTraversal => write!(f, "allowlist entry contains path traversal sequences (../ or ..\\)"),
            Self::NullByte => write!(f, "allowlist entry contains null byte"),
            Self::ControlCharacter => write!(f, "allowlist entry contains control character"),
            Self::TooLong(len) => write!(f, "allowlist entry too long: {} bytes (max 512)", len),
        }
    }
}

/// Validate a single path string for allowlist inclusion.
pub fn validate_path_entry(path: &str) -> ValidationOutcome {
    if path.is_empty() {
        return ValidationOutcome::Rejected(AllowlistSchemaError::Empty);
    }
    if !path.starts_with('/') {
        return ValidationOutcome::Rejected(AllowlistSchemaError::NoLeadingSlash);
    }
    if path.len() > 512 {
        return ValidationOutcome::Rejected(AllowlistSchemaError::TooLong(path.len()));
    }
    // Reject control characters (except normal whitespace which shouldn't appear)
    for ch in path.chars() {
        if ch.is_control() {
            return ValidationOutcome::Rejected(AllowlistSchemaError::ControlCharacter);
        }
    }
    // Reject null bytes specifically
    if path.contains('\0') {
        return ValidationOutcome::Rejected(AllowlistSchemaError::NullByte);
    }
    // Reject query strings and fragments in allowed entries
    if path.contains('?') {
        return ValidationOutcome::Rejected(AllowlistSchemaError::ContainsQuery);
    }
    if path.contains('#') {
        return ValidationOutcome::Rejected(AllowlistSchemaError::ContainsFragment);
    }
    // Reject path traversal patterns
    if path.contains("..") || path.contains("\\..") {
        return ValidationOutcome::Rejected(AllowlistSchemaError::PathTraversal);
    }
    // Reject encoded traversal sequences (%2e%2e, %252e)
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e%2e") || lower.contains("%252e") {
        return ValidationOutcome::Rejected(AllowlistSchemaError::PathTraversal);
    }

    ValidationOutcome::Valid
}

/// Validate a batch of allowed paths. Returns the list of valid entries and any errors.
pub fn validate_allowed_paths(paths: &[String]) -> (Vec<String>, Vec<AllowlistSchemaError>) {
    let mut valid = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        match validate_path_entry(path) {
            ValidationOutcome::Valid => valid.push(path.clone()),
            ValidationOutcome::Rejected(err) => errors.push(err),
        }
    }
    (valid, errors)
}

/// Normalize a request path for allowlist matching. Strips query strings and fragments
/// to prevent bypass via URL parameters.
pub fn normalize_path_for_matching(uri: &str) -> &str {
    match uri.split_once('?') {
        Some((path, _)) => path,
        None => match uri.split_once('#') {
            Some((path, _)) => path,
            None => uri,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_paths() {
        assert!(matches!(validate_path_entry("/api"), ValidationOutcome::Valid));
        assert!(matches!(validate_path_entry("/api/health"), ValidationOutcome::Valid));
        assert!(matches!(validate_path_entry("/"), ValidationOutcome::Valid));
        assert!(matches!(validate_path_entry("/admin/status"), ValidationOutcome::Valid));
    }

    #[test]
    fn test_rejects_empty() {
        assert!(matches!(validate_path_entry(""), ValidationOutcome::Rejected(AllowlistSchemaError::Empty)));
    }

    #[test]
    fn test_rejects_no_leading_slash() {
        assert!(matches!(validate_path_entry("api"), ValidationOutcome::Rejected(AllowlistSchemaError::NoLeadingSlash)));
    }

    #[test]
    fn test_rejects_query_in_entry() {
        assert!(matches!(validate_path_entry("/api?page=1"), ValidationOutcome::Rejected(AllowlistSchemaError::ContainsQuery)));
    }

    #[test]
    fn test_rejects_fragment_in_entry() {
        assert!(matches!(validate_path_entry("/page#section"), ValidationOutcome::Rejected(AllowlistSchemaError::ContainsFragment)));
    }

    #[test]
    fn test_rejects_traversal_in_entry() {
        // Traversal with leading slash is caught by the traversal check
        assert!(matches!(validate_path_entry("/../etc/passwd"), ValidationOutcome::Rejected(AllowlistSchemaError::PathTraversal)));
    }

    #[test]
    fn test_rejects_traversal_without_leading_slash() {
        // Traversal without leading slash is caught first by the no-slash check
        assert!(matches!(validate_path_entry("../etc/passwd"), ValidationOutcome::Rejected(AllowlistSchemaError::NoLeadingSlash)));
    }

    #[test]
    fn test_rejects_encoded_traversal() {
        assert!(matches!(validate_path_entry("/%2e%2e/api"), ValidationOutcome::Rejected(AllowlistSchemaError::PathTraversal)));
    }

    #[test]
    fn test_normalize_strips_query() {
        assert_eq!(normalize_path_for_matching("/api/users?sort=name"), "/api/users");
        assert_eq!(normalize_path_for_matching("/page#top"), "/page");
        assert_eq!(normalize_path_for_matching("/clean/path"), "/clean/path");
    }
}
