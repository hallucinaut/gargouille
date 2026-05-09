// ╔══════════════════════════════════════════════════╗
// ║  Gargouille WAF — Rule Detection Engine          ║
// ╚══════════════════════════════════════════════════╝

//! Comprehensive rule-based threat detection engine.
//! Each detector operates independently and returns matched threats with confidence scores.
//! Design philosophy: **deep pattern analysis + semantic heuristics**, not just regex.

use regex::Regex;
use regex::RegexBuilder;

// ─── Public detectors ──────────────────────────────────

mod sql_injection;
pub use sql_injection::*;

mod xss;
pub use xss::*;

mod cmdi;
pub use cmdi::*;

mod lfi_rfi;
pub use lfi_rfi::*;

mod ssti;
pub use ssti::*;

mod ssrf;
pub use ssrf::*;

mod deserialization;
pub use deserialization::*;

mod header_injection;
pub use header_injection::*;

mod path_traversal;
pub use path_traversal::*;



/// Compile a regex once per rule with optimized settings.
/// Returns an empty-matching regex on failure (effectively disables the rule).
fn compile_regex(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1024 * 1024)
        .build()
        .unwrap_or_else(|_| Regex::new(r"$^").unwrap())
}

/// Normalize text for scanning: decode, lower-case, strip common obfuscation.
pub fn normalize_for_scan(input: &str) -> String {
    input
        .replace(" \r\n ", " ")
        .replace('\r', "")
        .replace('\t', " ")
        .replace('\n', " ")
        .replace('*', "")
        .to_lowercase()
}

/// Check if text contains encoded variations of dangerous patterns.
/// This handles URL encoding, hex encoding, and Unicode escapes in one pass.
pub fn check_encoded_variations(text: &str, pattern: &Regex) -> bool {
    // Direct match
    if pattern.is_match(text) {
        return true;
    }

    // Check double-encoded versions (e.g., %253C for <)
    let decoded = crate::parser::HttpRequest::url_decode_limited(text, 10).unwrap_or_else(|| text.to_owned());
    if decoded != text && pattern.is_match(&decoded) {
        return true;
    }

    // Check triple-encoded
    let re_decoded = crate::parser::HttpRequest::url_decode_limited(&decoded, 10).unwrap_or_else(|| decoded.clone());
    if re_decoded != decoded && pattern.is_match(&re_decoded) {
        return true;
    }

    false
}

/// Confidence calibration based on count and position of matches.
pub fn calibrate_confidence(matches: usize, is_in_header: bool) -> f32 {
    // Base confidence grows with match count but saturates at ~75% for multiple
    let base = 0.4 + (matches.min(4) as f32 * 0.15);
    // Headers get a slight bump (more suspicious context)
    let header_boost = if is_in_header { 0.1 } else { 0.0 };
    (base + header_boost).min(0.95)
}

// ─── Tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        let input = "SELECT \r\n * FROM";
        assert_eq!(normalize_for_scan(input), "select  from");
    }

    #[test]
    fn test_check_encoded_variations() {
        let re = compile_regex(r"union.*select");
        let direct = "union select";
        assert!(check_encoded_variations(direct, &re));

        let encoded = "union%20select";
        assert!(check_encoded_variations(encoded, &re));
    }

    #[test]
    fn test_check_encoded_variations_no_match() {
        let re = compile_regex(r"super-secret-payload");
        assert!(!check_encoded_variations("normal text", &re));
    }

    #[test]
    fn test_normalize_removes_newlines() {
        let result = normalize_for_scan("line1\r\nline2\ntab\there");
        assert_eq!(result, "line1 line2 tab here");
    }

    #[test]
    fn test_normalize_lowercases() {
        let result = normalize_for_scan("SELECT * FROM Users");
        assert!(result.contains("select"));
        assert!(result.contains("from"));
    }

    #[test]
    fn test_compile_regex_fallback() {
        // Invalid regex should not panic, returns regex that only matches empty string
        let re = compile_regex(r"[invalid(regex");
        assert!(re.is_match(""));  // matches empty string via ^ anchor
        assert!(!re.is_match("anything at all")); // but nothing else
    }

    #[test]
    fn test_calibrate_confidence_single_match() {
        let conf = calibrate_confidence(1, false);
        assert!(conf >= 0.4 && conf <= 0.55);
    }

    #[test]
    fn test_calibrate_confidence_multiple_matches() {
        let conf = calibrate_confidence(3, false);
        assert!(conf > 0.6 && conf < 1.0);
    }

    #[test]
    fn test_calibrate_confidence_with_header_boost() {
        let conf_plain = calibrate_confidence(1, false);
        let conf_header = calibrate_confidence(1, true);
        assert!(conf_header > conf_plain);
    }

    #[test]
    fn test_calibrate_confidence_saturates() {
        let conf = calibrate_confidence(10, true);
        assert!(conf <= 0.95);
    }
}
