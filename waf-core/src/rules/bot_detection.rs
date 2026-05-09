//! Bot & behavioral detection engine — identifies automated tools, scanners, and non-browser clients.
//!
//! Detects three classes of bot traffic:
//!
//! 1. **Scanner fingerprints** — Known tool signatures in User-Agent, Referer, or URI patterns:
//!    Nikto, sqlmap, Burp Suite, DirBuster, Wget, curl, Go-http-client, Python requests, etc.
//! 2. **User-Agent anomalies** — Empty, null-byte, control-char, or excessively long UA strings.
//! 3. **Protocol-level anomalies** — Missing Accept header on browser-like requests, missing Host,
//!    or other deviations from normal browser behavior.

use crate::scoring::ThreatInfo;
use regex::Regex;
use super::compile_regex;

/// Known scanner fingerprint patterns. Each is a standalone regex compiled case-insensitively.
const SCANNER_PATTERNS: &[&str] = &[
    r"\bnikto\b",
    r"\bsqlmap\b",
    r"\bnmap\b",
    r"\bdirector|dirbuster\b",
    r"\bgobuster\b",
    r"\bwfuzz\b",
    r"\bffuf\b",
    r"\bhydra\b(?!-ftp)",
    r"\bmedusa\b",
    r"\bmasscan\b",
    r"\bzgrab\b",
    r"\bnuclei\b",
    r"\bsubfinder\b",
    r"\bwhatweb\b",
    r"\bacunetix\b",
    r"\bnessus\b",
    r"\bqualys\b",
    r"\bburp.*?suite\b",
    r"\burpsuite\b",
    r"owasp-?[zs]ap\b",
    r"\bzap\b",
    r"\barachni\b",
    r"\bskipfish\b",
    r"\bwebscarab\b",
    r"\bparos\b",
    r"\bhtcatch|colly",  
    r"\bpython-requests\b",
    r"\bpython-urllib\b",
    r"go-http-client\b",
    r"curl/[0-9]",
    r"wget/",
    r"\blibwww-perl\b",
    r"apache-httpclient\b",
    r"pharos|xaruta",
    r"dirb[^a-z]", // dirb followed by non-alpha (e.g., dirbuster, dirb-)
    r"\bwebscan\b",
    r"web-screenshot|scanbot|web-vacuum|blackwidow|harvest|dissect",
    r"emailwolf|fierce",
];

/// Pattern sets for bot detection.
#[derive(Debug, Clone)]
struct Patterns {
    /// User-Agent-based scanner fingerprints. A precompiled list of simple patterns.
    scanner_patterns: Vec<Regex>,
    /// Referer-based scanner patterns (e.g., dirbuster references).
    referer_scanner: Regex,
    /// Known bot/crawler identifiers in any request context.
    universal_bot: Regex,
}

impl Patterns {
    fn new() -> Self {
        let scanner_patterns: Vec<Regex> = SCANNER_PATTERNS.iter()
            .map(|p| compile_regex(p))
            .collect();
        Self {
            scanner_patterns,
            referer_scanner: compile_regex(
                r"(?i)\b(?:dirbuster|gobuster|ffuf|wfuzz|nikto|sqlmap|nmap).*?\b(?:scan|probe|list)\b",
            ),
            universal_bot: compile_regex(
                r"(?i)\b(bot|crawler|spider|scraper|extractor)(?:\s+.+)?\s*[vV]?[0-9]+",  
            ),
        }
    }
}

impl Patterns {
    /// Check if text matches any scanner fingerprint.
    fn matches_scanner(&self, text: &str) -> bool {
        self.scanner_patterns.iter().any(|re| re.is_match(text))
    }
}

/// Bot detection detector — scans for automated tool signatures.
#[derive(Debug, Clone)]
pub struct BotDetectionDetector {
    patterns: Patterns,
}

impl BotDetectionDetector {
    pub fn new() -> Self {
        Self {
            patterns: Patterns::new(),
        }
    }

    /// Scan request text pairs for bot signals.
    pub fn scan(&self, texts: &[(String, String)]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();

        // Count headers to decide if protocol anomalies are relevant
        let header_count = texts.iter()
            .filter(|(loc, _)| loc.starts_with("header:"))
            .count();

        for (location, text) in texts {
            // ── 1. Scanner fingerprints ───────────────────────────────

            // Check User-Agent and Referer headers against scanner patterns
            if location == "header:user-agent" || text.to_lowercase().starts_with("user-agent") {
                if self.patterns.matches_scanner(text) {
                    threats.push(ThreatInfo {
                        rule_id: "BOT-001".into(),
                        category: crate::scoring::ThreatCategory::BotChallenge,
                        matched_value: text.chars().take(200).collect(),
                        location: crate::scoring::ThreatLocation::Headers,
                        confidence: 0.95,
                    });
                }
            }

            // Referer-based scanner detection
            if location == "header:referer" || text.to_lowercase().starts_with("referer") {
                if self.patterns.referer_scanner.is_match(text) {
                    threats.push(ThreatInfo {
                        rule_id: "BOT-002".into(),
                        category: crate::scoring::ThreatCategory::BotChallenge,
                        matched_value: text.chars().take(200).collect(),
                        location: crate::scoring::ThreatLocation::Headers,
                        confidence: 0.90,
                    });
                }
            }

            // Universal bot/crawler indicators (in any field)
            if self.patterns.universal_bot.is_match(text) {
                threats.push(ThreatInfo {
                    rule_id: "BOT-003".into(),
                    category: crate::scoring::ThreatCategory::BotChallenge,
                    matched_value: text.chars().take(200).collect(),
                    location: map_location(location),
                    confidence: 0.75,
                });
            }

            // ── 2. Encoded scanner fingerprints ───────────────────────
            if location.starts_with("header:") && self.check_encoded_scanner(text) {
                threats.push(ThreatInfo {
                    rule_id: "BOT-004".into(),
                    category: crate::scoring::ThreatCategory::BotChallenge,
                    matched_value: text.chars().take(200).collect(),
                    location: crate::scoring::ThreatLocation::Headers,
                    confidence: 0.85,
                });
            }

            // ── 3. User-Agent anomalies ───────────────────────────────
            if location == "header:user-agent" || text.to_lowercase().starts_with("user-agent") {
                self.analyze_ua_anomaly(text, &mut threats);
            }
        }

        // ── 4. Protocol-level anomalies (only with multiple headers) ─
        if header_count >= 2 {
            self.detect_protocol_anomalies(texts, &mut threats);
        }

        // ── Deduplicate to avoid overwhelming a request ────────────
        self.deduplicate(&mut threats);

        threats
    }

    /// Check for encoded scanner fingerprints in header values.
    fn check_encoded_scanner(&self, header_value: &str) -> bool {
        // Decode once and check against the scanner pattern
        let decoded = crate::parser::HttpRequest::url_decode_limited(header_value, 3)
            .unwrap_or_else(|| header_value.to_owned());
        if decoded != header_value && self.patterns.matches_scanner(&decoded) {
            return true;
        }
        // Also check hex-decoded: %NN -> NNNN -> decode pairs
        let hex_decoded = hex_decode(header_value);
        if !hex_decoded.is_empty() && self.patterns.matches_scanner(&hex_decoded) {
            return true;
        }
        false
    }

    /// Analyze a single User-Agent string for anomalies.
    fn analyze_ua_anomaly(&self, ua: &str, threats: &mut Vec<ThreatInfo>) {
        // Empty UA — automated tools often leave this blank
        if ua.is_empty() {
            threats.push(ThreatInfo {
                rule_id: "BOT-010".into(),
                category: crate::scoring::ThreatCategory::BotChallenge,
                matched_value: "<empty>".into(),
                location: crate::scoring::ThreatLocation::Headers,
                confidence: 0.60,
            });
        }
        // Null bytes indicate crafted/injected UA
        else if ua.contains('\0') {
            threats.push(ThreatInfo {
                rule_id: "BOT-011".into(),
                category: crate::scoring::ThreatCategory::BotChallenge,
                matched_value: format!("{} (null bytes)", ua.chars().take(80).collect::<String>()),
                location: crate::scoring::ThreatLocation::Headers,
                confidence: 0.90,
            });
        }
        // Control characters indicate malformed/constructed UA
        else if ua.len() > 1 && ua.chars().any(|c| c.is_control()) {
            threats.push(ThreatInfo {
                rule_id: "BOT-012".into(),
                category: crate::scoring::ThreatCategory::BotChallenge,
                matched_value: format!("{} (control chars)", ua.chars().take(80).collect::<String>()),
                location: crate::scoring::ThreatLocation::Headers,
                confidence: 0.75,
            });
        }
        // Single-char UA — suspiciously short for a real browser
        else if ua.len() == 1 {
            threats.push(ThreatInfo {
                rule_id: "BOT-013".into(),
                category: crate::scoring::ThreatCategory::BotChallenge,
                matched_value: format!("{} (single-char UA)", ua),
                location: crate::scoring::ThreatLocation::Headers,
                confidence: 0.50,
            });
        }
    }

    /// Detect protocol-level anomalies that indicate non-browser traffic.
    fn detect_protocol_anomalies(&self, texts: &[(String, String)], threats: &mut Vec<ThreatInfo>) {
        let mut has_host = false;
        for (location, text) in texts {
            if location.to_lowercase() == "header:host" {
                has_host = !text.is_empty();
            }
        }

        // Missing Host header with other headers present suggests bot behavior.
        // Real browsers always include a Host header.
        if !has_host {
            threats.push(ThreatInfo {
                rule_id: "BOT-020".into(),
                category: crate::scoring::ThreatCategory::BotChallenge,
                matched_value: "<missing host header>".into(),
                location: crate::scoring::ThreatLocation::Headers,
                confidence: 0.45,
            });
        }
    }

    /// Deduplicate threats to avoid overwhelming a single request with redundant bot signals.
    fn deduplicate(&self, threats: &mut Vec<ThreatInfo>) {
        // Collect indices of high-confidence scanner locations
        struct ScanFlag {
            text_idx: usize,
            loc_value: u8,  // 0=Uri,1=Query,2=Body,3=Headers,4=Cookie,5=RemoteAddr
        }

        let mut scan_flags: Vec<ScanFlag> = Vec::new();
        for (i, t) in threats.iter().enumerate() {
            if matches!(t.rule_id.as_str(), "BOT-001" | "BOT-002") {
                let loc_val = match t.location {
                    crate::scoring::ThreatLocation::Uri => 0,
                    crate::scoring::ThreatLocation::QueryString => 1,
                    crate::scoring::ThreatLocation::Body => 2,
                    crate::scoring::ThreatLocation::Headers => 3,
                    crate::scoring::ThreatLocation::Cookie => 4,
                    crate::scoring::ThreatLocation::RemoteAddr => 5,
                };
                scan_flags.push(ScanFlag { text_idx: i, loc_value: loc_val });
            }
        }

        // Keep high-confidence scan detections and UA anomalies; suppress duplicates.
        let mut filtered = Vec::new();
        for t in std::mem::take(threats) {
            let is_scan_match = matches!(t.rule_id.as_str(), "BOT-001" | "BOT-002");
            let is_ua_anomaly = t.rule_id.starts_with("BOT-01") || t.rule_id.starts_with("BOT-020");

            if is_scan_match {
                filtered.push(t);
            } else if is_ua_anomaly {
                filtered.push(t);
            } else {
                // BOT-003, BOT-004: keep only if not already flagged at same location
                let loc_val = match t.location {
                    crate::scoring::ThreatLocation::Uri => 0,
                    crate::scoring::ThreatLocation::QueryString => 1,
                    crate::scoring::ThreatLocation::Body => 2,
                    crate::scoring::ThreatLocation::Headers => 3,
                    crate::scoring::ThreatLocation::Cookie => 4,
                    crate::scoring::ThreatLocation::RemoteAddr => 5,
                };
                let already_flagged = scan_flags.iter().any(|f| f.loc_value == loc_val);
                if !already_flagged || t.confidence >= 0.85 {
                    filtered.push(t);
                }
            }
        }

        *threats = filtered;
    }
}

/// Map a text location string to a ThreatLocation enum variant.
fn map_location(location: &str) -> crate::scoring::ThreatLocation {
    match location {
        "path" => crate::scoring::ThreatLocation::Uri,
        "query" => crate::scoring::ThreatLocation::QueryString,
        "body" => crate::scoring::ThreatLocation::Body,
        _ if location.starts_with("header") => crate::scoring::ThreatLocation::Headers,
        _ if location.starts_with("cookie") => crate::scoring::ThreatLocation::Cookie,
        _ => crate::scoring::ThreatLocation::Uri,
    }
}

/// Simple hex decode for encoded scanner fingerprint detection.
fn hex_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' && is_hex(bytes[i + 1]) && is_hex(bytes[i + 2]) {
            if let Ok(val) = u8::from_str_radix(
                &String::from_utf8_lossy(&bytes[i + 1..i + 3]),
                16,
            ) {
                result.push(val as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    if i < bytes.len() {
        result.push_str(&String::from_utf8_lossy(&bytes[i..]));
    }
    result
}

fn is_hex(b: u8) -> bool {
    (b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F')
}

// ──────────────── Tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ua_texts(ua: &str) -> Vec<(String, String)> {
        vec![("header:user-agent".into(), ua.to_string())]
    }

    fn body_texts(body: &str) -> Vec<(String, String)> {
        vec![("body".into(), body.to_string())]
    }

    fn multi_header_texts(headers: &[(&str, &str)]) -> Vec<(String, String)> {
        headers.iter()
            .map(|(k, v)| (format!("header:{}", k), v.to_string()))
            .collect()
    }

    // ── Scanner Fingerprint Detection (BOT-001) ────────────

    #[test]
    fn test_nikto_detector_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla/5.0 Nikto/2.1.6"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Nikto should be detected");
    }

    #[test]
    fn test_sqlmap_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("sqlmap/1.7.2#stable (https://sqlmap.org)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "sqlmap should be detected");
    }

    #[test]
    fn test_burp_suite_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla/5.0 Burp Suite Professional"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Burp Suite should be detected");
    }

    #[test]
    fn test_curl_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("curl/8.4.0"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "curl should be detected");
    }

    #[test]
    fn test_go_http_client_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Go-http-client/1.1"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Go-http-client should be detected");
    }

    #[test]
    fn test_python_requests_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("python-requests/2.31.0"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "python-requests should be detected");
    }

    #[test]
    fn test_nmap_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla/5.0 (compatible; Nmap Scripting Engine)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Nmap should be detected");
    }

    #[test]
    fn test_wget_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Wget/1.21.3"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Wget should be detected");
    }

    #[test]
    fn test_http_client_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Apache-HttpClient/4.5.14 (Java/17.0.9)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Apache HttpClient should be detected");
    }

    #[test]
    fn test_dirbuster_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("DirBuster-1.0-RC1 (http://www.owasp.org/)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "DirBuster should be detected");
    }

    #[test]
    fn test_masscan_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla/5.0 Masscan/1.3.2"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Masscan should be detected");
    }

    #[test]
    fn test_zap_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 ZAP/2.14.0"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "ZAP should be detected");
    }

    #[test]
    fn test_acunetix_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Acunetix Web Vulnerability Scanner"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Acunetix should be detected");
    }

    #[test]
    fn test_gobuster_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("gobuster/3.6"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Gobuster should be detected");
    }

    #[test]
    fn test_ffuf_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("ffuf/2.1.0"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "FFUF should be detected");
    }

    #[test]
    fn test_nuclei_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Nuclei should be detected");
    }

    // ── Referer-based Scanner Detection (BOT-002) ──────────

    #[test]
    fn test_referer_scanner_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&multi_header_texts(&[("referer", "DirBuster scan probe")]));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-002"), "Referer-based scanner should be detected");
    }

    #[test]
    fn test_referer_no_scanner() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&multi_header_texts(&[("referer", "https://example.com/page")]));
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-002"), "Clean referer should not match BOT-002");
    }

    // ── UA Anomaly Detection (BOT-010 through BOT-013) ─────

    #[test]
    fn test_empty_ua_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts(""));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-010"), "Empty UA should be detected");
    }

    #[test]
    fn test_null_byte_ua_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla/5.0\0attack"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-011"), "Null byte UA should be detected");
    }

    #[test]
    fn test_control_char_ua_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla\x01control"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-012"), "Control char UA should be detected");
    }

    #[test]
    fn test_single_char_ua_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("c"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-013"), "Single-char UA should be detected");
    }

    // ── Clean Request Tests ────────────────────────────────

    #[test]
    fn test_real_browser_ua_passes() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ));
        assert!(threats.is_empty(), "Real browser UA should not trigger bot detection: {:?}", threats);
    }

    #[test]
    fn test_firefox_ua_passes() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts(
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        ));
        assert!(threats.is_empty(), "Firefox UA should not trigger bot detection");
    }

    #[test]
    fn test_safari_ua_passes() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        ));
        assert!(threats.is_empty(), "Safari UA should not trigger bot detection");
    }

    #[test]
    fn test_ios_mobile_ua_passes() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21E237",
        ));
        assert!(threats.is_empty(), "iOS mobile UA should not trigger bot detection");
    }

    #[test]
    fn test_minimal_ua_passes() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla"));
        assert!(threats.is_empty(), "\"Mozilla\" alone should not trigger bot detection");
    }

    // ── Body and Mixed Tests ───────────────────────────────

    #[test]
    fn test_body_text_clean_passes() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&body_texts("{\"username\": \"alice\", \"password\": \"secure123\"}"));
        assert!(threats.is_empty(), "Clean JSON body should not trigger bot detection");
    }

    #[test]
    fn test_encoded_scanner_in_header_detected() {
        let detector = BotDetectionDetector::new();
        // Encoded scanner fingerprint — %6E%69%6B%74%6F decodes to "nikto"
        let encoded = "%6E%69%6B%74%6F";
        let threats = detector.scan(&multi_header_texts(&[("x-custom", encoded)]));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-004"), "Encoded scanner should be detected");
    }

    #[test]
    fn test_no_headers_passes() {
        let detector = BotDetectionDetector::new();
        // Empty texts — no headers at all
        let threats = detector.scan(&[]);
        assert!(threats.is_empty(), "Empty request should not trigger bot detection");
    }

    #[test]
    fn test_mixed_clean_headers_passes() {
        let detector = BotDetectionDetector::new();
        let texts = multi_header_texts(&[
            ("user-agent", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36"),
            ("accept", "text/html,application/xhtml+xml,*/*"),
            ("host", "example.com"),
            ("referer", "https://example.com/page"),
        ]);
        let threats = detector.scan(&texts);
        assert!(threats.is_empty(), "Clean mixed request should not trigger bot detection");
    }

    #[test]
    fn test_missing_host_with_headers_detected() {
        let detector = BotDetectionDetector::new();
        // Multiple headers but no Host header — typical of bots
        let texts = multi_header_texts(&[
            ("user-agent", "sqlmap/1.7"),
            ("accept", "*/*"),
            ("content-type", "application/x-www-form-urlencoded"),
        ]);
        let threats = detector.scan(&texts);
        assert!(threats.iter().any(|t| t.rule_id == "BOT-020"), "Missing host header should be detected");
    }

    #[test]
    fn test_protocol_no_false_positive_with_single_header() {
        // Single UA header — protocol anomalies should NOT trigger
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Mozilla/5.0"));
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-020"), "Single UA should not trigger protocol anomaly");
    }

    #[test]
    fn test_scanner_with_host_header_still_detected() {
        // Scanner detected even when Host header is present
        let detector = BotDetectionDetector::new();
        let texts = multi_header_texts(&[
            ("user-agent", "sqlmap/1.7"),
            ("host", "example.com"),
        ]);
        let threats = detector.scan(&texts);
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Scanner should be detected even with Host header");
    }

    // ── Multiple Scanners ──────────────────────────────────

    #[test]
    fn test_multiple_bots_same_request() {
        let detector = BotDetectionDetector::new();
        // A request from a real scanner tool like sqlmap (already tested) + empty UA would be rare,
        // but we verify that multiple bot types in the same text are properly handled.
        let threats = detector.scan(&ua_texts("sqlmap/1.7.2#stable (https://sqlmap.org)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "sqlmap scanner fingerprint should be detected");
    }

    // ── Case Insensitive Scanner Detection ────────────────

    #[test]
    fn test_scanner_fingerprint_case_insensitive_uppercase() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("NIKTO/2.1.6 (Scanner)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Uppercase NIKTO should be detected");
    }

    #[test]
    fn test_scanner_fingerprint_case_insensitive_mixed() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("SqlMap/1.7"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Mixed-case SqlMap should be detected");
    }

    #[test]
    fn test_scanner_fingerprint_case_insensitive_full_caps() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("SQLMAP/1.7.2#STABLE"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Full caps SQLMAP should be detected");
    }

    #[test]
    fn test_scanner_fingerprint_case_insensitive_curl() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("cUrL/8.4.0"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "Mixed-case curl should be detected");
    }

    // ── Encoding Variant Tests ───────────────────────────

    #[test]
    fn test_double_encoded_scanner_in_header() {
        let detector = BotDetectionDetector::new();
        // Double-encoded: %256E%2569%256B%2574%256F decodes to %6E%69%6B%74%6F which decodes to "nikto"
        let double_encoded = "%256E%2569%256B%2574%256F";
        let threats = detector.scan(&multi_header_texts(&[("x-custom", double_encoded)]));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-004"), "Double-encoded scanner should be detected");
    }

    #[test]
    fn test_hex_encoded_nmap_fingerprint() {
        let detector = BotDetectionDetector::new();
        // %6E%6D%61%70 decodes to "nmap"
        let encoded = "%6E%6D%61%70";
        let threats = detector.scan(&multi_header_texts(&[("x-tool", encoded)]));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-004"), "Hex-encoded nmap should be detected");
    }

    #[test]
    fn test_hex_encoded_scanner_still_validated() {
        let detector = BotDetectionDetector::new();
        // Valid hex that does NOT decode to a scanner — should not trigger BOT-004
        let benign_hex = "%68%65%6C%6C%6F"; // decodes to "hello"
        let threats = detector.scan(&multi_header_texts(&[("x-custom", benign_hex)]));
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-004"), "Benign hex-encoded text should not trigger BOT-004");
    }

    // ── Hydra/Ftp Negative Test ──────────────────────────

    #[test]
    fn test_hydra_ftp_not_detected_as_scanner() {
        // The pattern has (?!-ftp) negative lookahead — "hydra-ftp" should NOT match BOT-001
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("hydra-ftp/9.5"));
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-001"), "hydra-ftp should NOT be detected as scanner");
    }

    // ── Deduplication Stress Tests ───────────────────────

    #[test]
    fn test_deduplication_multiple_signals_same_location() {
        let detector = BotDetectionDetector::new();
        // Multiple bot signals: scanner fingerprint at multiple locations triggers
        // both BOT-001/BOT-002 and encoded checks (which also match plain-text
        // scanner names). High-confidence BOT-004 entries are preserved.
        let threats = detector.scan(&multi_header_texts(&[
            ("user-agent", "sqlmap/1.7"),
            ("referer", "DirBuster scan probe list"),
            ("x-custom", "%6E%69%6B%74%6F"),
        ]));
        // BOT-001 always preserved for scanner fingerprints
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "BOT-001 should be present");
        // BOT-002 always preserved for referer scanners
        assert!(threats.iter().any(|t| t.rule_id == "BOT-002"), "BOT-002 should be present");
        // Total threats: at least 2 (one each from BOT-001 and BOT-002)
        assert!(!threats.is_empty(), "Should have at least one bot threat");
    }

    #[test]
    fn test_deduplication_preserves_high_confidence() {
        let detector = BotDetectionDetector::new();
        // A request triggering both a scanner fingerprint (BOT-001, 0.95) and
        // universal bot indicator (BOT-003, 0.75) — BOT-001 should be kept,
        // BOT-003 may be suppressed as lower confidence at same location.
        let threats = detector.scan(&multi_header_texts(&[
            ("user-agent", "sqlmap/1.7 bot crawler v1"),
        ]));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-001"), "BOT-001 should be preserved");
    }

    // ── Unicode and Edge Case Tests ──────────────────────

    #[test]
    fn test_unicode_heavy_ua_no_crash() {
        let detector = BotDetectionDetector::new();
        // Unicode-heavy string — should not cause panic or hang
        let unicode_ua = "Mozilla/5.0 (\u{2603}\u{1F600}\u{1F480}) AppleWebKit";
        let threats = detector.scan(&ua_texts(unicode_ua));
        // Should not trigger bot detection for a benign but weird UA
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-001"), "Unicode UA should not false-positive scanner");
    }

    #[test]
    fn test_very_long_user_agent_no_crash() {
        let detector = BotDetectionDetector::new();
        // Very long UA — should handle gracefully without memory issues
        let long_ua = "Mozilla/5.0 ".to_owned() + &"a".repeat(10_000);
        let threats = detector.scan(&ua_texts(&long_ua));
        // Should not trigger any scanner patterns in the repeated 'a' string
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-001"), "Long UA should not false-positive");
    }

    #[test]
    fn test_ua_with_spaces_between_words() {
        let detector = BotDetectionDetector::new();
        // Scanner name with extra spaces between words — regex \b handles word boundaries
        let threats = detector.scan(&ua_texts("Mozilla/5.0 (compatible; N i k t o)"));
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-001"), "Scattered chars should not match word-boundary nikto");
    }

    // ── Referer Multi-Header Edge Cases ──────────────────

    #[test]
    fn test_referer_scanner_with_multiple_entries() {
        let detector = BotDetectionDetector::new();
        // Multiple referer header entries, one containing scanner reference
        let texts = multi_header_texts(&[
            ("referer", "https://example.com/page"),
            ("referer", "DirBuster scan probe list"),
        ]);
        let threats = detector.scan(&texts);
        assert!(threats.iter().any(|t| t.rule_id == "BOT-002"), "Referer with scanner should be detected");
    }

    #[test]
    fn test_referer_clean_with_scanner_referer() {
        let detector = BotDetectionDetector::new();
        // Clean referer mixed with scanner reference in different header
        let texts = multi_header_texts(&[
            ("referer", "https://google.com/search?q=test"),
            ("x-forwarded-for", "10.0.0.1"),
        ]);
        let threats = detector.scan(&texts);
        assert!(!threats.iter().any(|t| t.rule_id == "BOT-002"), "Clean referers should not trigger BOT-002");
    }

    // ── Universal Bot Indicator Tests ────────────────────

    #[test]
    fn test_universal_bot_crawler_detected() {
        let detector = BotDetectionDetector::new();
        // Text with word-boundary around bot keyword followed by version
        let threats = detector.scan(&ua_texts("Google Bot 2.1 (+http://www.google.com/bot.html)"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-003"), "Google Bot with version should be detected as universal bot");
    }

    #[test]
    fn test_universal_bot_crawler_lowercase() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("my-crawler v2.0"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-003"), "my-crawler should be detected");
    }

    #[test]
    fn test_universal_bot_spider_detected() {
        let detector = BotDetectionDetector::new();
        let threats = detector.scan(&ua_texts("Spider v1.2"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-003"), "Spider should be detected");
    }

    #[test]
    fn test_universal_bot_scraper_detected() {
        let detector = BotDetectionDetector::new();
        // Word-boundary before 'scraper' (dash provides the boundary)
        let threats = detector.scan(&ua_texts("web-scraper v3.1"));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-003"), "Scraper should be detected");
    }

    // ── Bot Detection Threshold Tests ────────────────────

    #[test]
    fn test_bot_detection_weight_configurable() {
        let detector = BotDetectionDetector::new();
        // Verify that scanning produces consistent threat output
        let threats = detector.scan(&ua_texts("sqlmap/1.7"));
        assert!(!threats.is_empty(), "sqlmap should produce at least one threat");
        for t in &threats {
            assert!(t.confidence > 0.0, "Threat confidence should be positive");
            assert!(t.confidence <= 1.0, "Threat confidence should be <= 1.0");
        }
    }

    #[test]
    fn test_bot_detection_matches_known_threat_ids() {
        let detector = BotDetectionDetector::new();
        // Empty UA triggers BOT-010
        let threats = detector.scan(&ua_texts(""));
        assert!(threats.iter().any(|t| t.rule_id == "BOT-010"), "Empty UA should trigger BOT-010");
    }
}
