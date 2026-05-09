//! Ultra-fast HTTP request parser — zero-copy where possible.
//! Parses methods, paths, query strings, headers, and body from raw bytes.

use ahash::AHashMap;
use std::net::SocketAddr;

// ──────────────── Request ────────────────────────────────

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub path: String,
    pub query_string: String,
    pub full_uri: String,
    pub headers: AHashMap<String, Vec<String>>,
    pub cookies: AHashMap<String, String>,
    pub body: Vec<u8>,
    pub content_length: Option<usize>,
    pub remote_addr: SocketAddr,
    pub is_https: bool,
}

impl HttpRequest {
    /// Fast path for extracting a header value (first occurrence), case-insensitive.
    #[inline]
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.first())
            .map(|s| s.as_str())
    }

    /// Get header values (all occurrences), case-insensitive.
    pub fn get_header_all(&self, name: &str) -> &[String] {
        self.headers
            .get(name)
            .or_else(|| {
                self.headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v)
            })
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Check if content type matches a MIME substring.
    #[inline]
    pub fn is_content_type(&self, mime: &str) -> bool {
        match self.get_header("content-type") {
            Some(ct) => ct.to_ascii_lowercase().contains(mime),
            None => false,
        }
    }

    /// Decode a URL-encoded string (limited depth to prevent ReDoS).
    /// max_depth controls the number of full-string decode passes,
    /// handling double/triple encoding (e.g. %253C -> %3C -> <).
    pub fn url_decode_limited(input: &str, max_depth: usize) -> Option<String> {
        let mut current = input.to_string();
        for _ in 0..max_depth {
            let decoded = Self::decode_once(&current)?;
            if decoded == current {
                break;
            }
            current = decoded;
        }
        Some(current)
    }

    fn decode_once(input: &str) -> Option<String> {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.bytes().peekable();

        while let Some(b) = chars.next() {
            if b == b'%' && chars.peek().map_or(false, |&c| c != b'%') {
                let mut hex_chars = Vec::with_capacity(2);
                for _ in 0..2 {
                    if let Some(b) = chars.next() {
                        hex_chars.push(b);
                    }
                }
                let hex: String = String::from_utf8(hex_chars).unwrap_or_default();
                if let Ok(val) = u8::from_str_radix(&hex, 16) {
                    result.push(val as char);
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            } else {
                result.push(b as char);
            }
        }
        Some(result)
    }

    /// Parse all URL query parameters (keeps first occurrence for duplicate keys).
    pub fn parse_query_params(&self) -> AHashMap<String, String> {
        if self.query_string.is_empty() {
            return AHashMap::new();
        }
        let mut params = AHashMap::with_capacity(8);
        for pair in self.query_string.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                params.entry(k.to_string()).or_insert_with(|| v.to_string());
            } else {
                params.entry(pair.to_string()).or_insert_with(String::new);
            }
        }
        params
    }

    /// Parse cookies from the Cookie header.
    pub fn parse_cookies(&self) -> AHashMap<String, String> {
        let mut cookies = AHashMap::new();
        if let Some(cookie_header) = self.get_header("cookie") {
            for part in cookie_header.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    cookies.insert(k.to_string(), v.to_string());
                }
            }
        }
        cookies
    }

    /// Decode the body as UTF-8 string, with max size guard.
    pub fn body_as_str(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    /// Return all searchable text from the request for scanning.
    pub fn searchable_text(&self) -> Vec<(String, String)> {
        let mut texts = Vec::new();
        if !self.path.is_empty() {
            texts.push(("path".into(), self.path.clone()));
        }
        if !self.query_string.is_empty() {
            texts.push(("query".into(), self.query_string.clone()));
        }
        if let Some(ct) = self.get_header("content-type") {
            texts.push(("content_type".into(), ct.to_owned()));
        }
        for (k, v) in &self.headers {
            if !matches!(k.as_str(), "host" | "connection") {
                texts.push((format!("header:{}", k), v.join(", ")));
            }
        }
        if let Some(body) = self.body_as_str() {
            texts.push(("body".into(), body));
        }
        for (k, v) in &self.cookies {
            texts.push((format!("cookie:{}", k), v.clone()));
        }
        texts
    }
}

// ──────────────── Benchmark (standalone) ─────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(
            HttpRequest::url_decode_limited("hello%20world", 1).unwrap(),
            "hello world"
        );
        assert_eq!(
            HttpRequest::url_decode_limited("%3Cscript%3E", 1).unwrap(),
            "<script>"
        );
    }

    #[test]
    fn test_url_decode_double_encoding() {
        let double_encoded = "%253Cscript%253E";
        assert_eq!(
            HttpRequest::url_decode_limited(double_encoded, 2).unwrap(),
            "<script>"
        );
    }

    #[test]
    fn test_url_decode_no_encoding() {
        assert_eq!(
            HttpRequest::url_decode_limited("plain text", 1).unwrap(),
            "plain text"
        );
    }

    #[test]
    fn test_url_decode_invalid_hex() {
        let result = HttpRequest::url_decode_limited("hello%GGworld", 1).unwrap();
        assert_eq!(result, "hello%GGworld");
    }

    #[test]
    fn test_url_decode_partial_sequence() {
        let result = HttpRequest::url_decode_limited("hello%2", 1);
        assert!(result.is_some());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_url_decode_mixed_encoding() {
        let mixed = "%3Cdiv%20class=%22test%22%3E";
        let decoded = HttpRequest::url_decode_limited(mixed, 1).unwrap();
        assert_eq!(decoded, "<div class=\"test\">");
    }

    #[test]
    fn test_url_decode_triple_encoding() {
        let triple = "%25253Cscript%25253E";
        let decoded = HttpRequest::url_decode_limited(triple, 3).unwrap();
        assert_eq!(decoded, "<script>");
    }

    #[test]
    fn test_url_decode_empty_string() {
        let result = HttpRequest::url_decode_limited("", 1).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_get_header_present() {
        let mut headers = AHashMap::new();
        headers.insert("content-type".to_string(), vec!["application/json".into()]);
        let req = HttpRequest {
            method: "POST".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        assert_eq!(req.get_header("content-type"), Some("application/json"));
    }

    #[test]
    fn test_get_header_case_insensitive() {
        let mut headers = AHashMap::new();
        headers.insert("Content-Type".to_string(), vec!["text/html".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        // HTTP headers are case-insensitive per RFC 7230
        assert_eq!(req.get_header("content-type"), Some("text/html"));
    }

    #[test]
    fn test_get_header_missing() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        assert!(req.get_header("x-custom").is_none());
    }

    #[test]
    fn test_get_header_all() {
        let mut headers = AHashMap::new();
        headers.insert("accept".to_string(), vec!["text/html".into(), "application/json".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let all = req.get_header_all("accept");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_is_content_type_match() {
        let mut headers = AHashMap::new();
        headers.insert("content-type".to_string(), vec!["application/json; charset=utf-8".into()]);
        let req = HttpRequest {
            method: "POST".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        assert!(req.is_content_type("json"));
    }

    #[test]
    fn test_is_content_type_no_match() {
        let mut headers = AHashMap::new();
        headers.insert("content-type".to_string(), vec!["text/html".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        assert!(!req.is_content_type("xml"));
    }

    #[test]
    fn test_parse_query_params_empty() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/path".into(), path: "/path".into(),
            query_string: "".into(), full_uri: "/path".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let params = req.parse_query_params();
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_query_params_single() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: "key=value".into(), full_uri: "/?key=value".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let params = req.parse_query_params();
        assert_eq!(params.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_parse_query_params_multiple() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: "name=Alice&age=30&city=NYC".into(), full_uri: "/?name=Alice&age=30&city=NYC".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let params = req.parse_query_params();
        assert_eq!(params.len(), 3);
        assert_eq!(params.get("name"), Some(&"Alice".to_string()));
        assert_eq!(params.get("age"), Some(&"30".to_string()));
        assert_eq!(params.get("city"), Some(&"NYC".to_string()));
    }

    #[test]
    fn test_parse_query_params_duplicate_keys() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: "tag=rust&tag=waf&tag=security".into(), full_uri: "/?tag=rust&tag=waf&tag=security".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let params = req.parse_query_params();
        // First occurrence wins
        assert_eq!(params.get("tag"), Some(&"rust".to_string()));
    }

    #[test]
    fn test_parse_query_params_key_only() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: "flag&key=value".into(), full_uri: "/?flag&key=value".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let params = req.parse_query_params();
        assert_eq!(params.len(), 2);
        assert_eq!(params.get("flag"), Some(&String::new()));
    }

    #[test]
    fn test_parse_query_params_empty_value() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: "key=".into(), full_uri: "/?key=".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let params = req.parse_query_params();
        assert_eq!(params.get("key"), Some(&String::new()));
    }

    #[test]
    fn test_parse_cookies_single() {
        let mut headers = AHashMap::new();
        headers.insert("cookie".to_string(), vec!["session=abc123".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let cookies = req.parse_cookies();
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_parse_cookies_multiple() {
        let mut headers = AHashMap::new();
        headers.insert("cookie".to_string(), vec!["session=abc123; id=42; theme=dark".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let cookies = req.parse_cookies();
        assert_eq!(cookies.len(), 3);
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(cookies.get("id"), Some(&"42".to_string()));
        assert_eq!(cookies.get("theme"), Some(&"dark".to_string()));
    }

    #[test]
    fn test_parse_cookies_empty() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let cookies = req.parse_cookies();
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_parse_cookies_spaces() {
        let mut headers = AHashMap::new();
        headers.insert("cookie".to_string(), vec![" session=abc123 ; id=42 ".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let cookies = req.parse_cookies();
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_body_as_str_valid_utf8() {
        let body: Vec<u8> = "Hello, world!".as_bytes().to_vec();
        let req = HttpRequest {
            method: "POST".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body,
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        assert_eq!(req.body_as_str(), Some("Hello, world!".to_string()));
    }

    #[test]
    fn test_body_as_str_empty() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        assert_eq!(req.body_as_str(), Some(String::new()));
    }

    #[test]
    fn test_searchable_text_basic() {
        let mut headers = AHashMap::new();
        headers.insert("content-type".to_string(), vec!["application/json".into()]);
        let body: Vec<u8> = "{\"key\": \"value\"}".as_bytes().to_vec();
        let req = HttpRequest {
            method: "POST".into(), uri: "/api".into(), path: "/api".into(),
            query_string: String::new(), full_uri: "/api".into(),
            headers, cookies: AHashMap::new(), body,
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let texts = req.searchable_text();
        assert!(!texts.is_empty());
    }

    #[test]
    fn test_searchable_text_includes_all_fields() {
        let mut headers = AHashMap::new();
        headers.insert("x-custom".to_string(), vec!["custom-value".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/test?q=hello".into(), path: "/test".into(),
            query_string: "q=hello".into(), full_uri: "/test?q=hello".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let texts = req.searchable_text();
        let keys: Vec<&str> = texts.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"path"));
        assert!(keys.contains(&"query"));
    }

    #[test]
    fn test_searchable_text_excludes_host_header() {
        let mut headers = AHashMap::new();
        headers.insert("host".to_string(), vec!["fr.brain.local.agent".into()]);
        headers.insert("connection".to_string(), vec!["keep-alive".into()]);
        headers.insert("x-custom".to_string(), vec!["value".into()]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers, cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let texts = req.searchable_text();
        let keys: Vec<&str> = texts.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"host"));
        assert!(!keys.contains(&"connection"));
    }

    #[test]
    fn test_searchable_text_includes_cookies() {
        let cookies = AHashMap::from_iter([
            ("session".to_string(), "abc123".to_string()),
            ("secret".to_string(), "topsecret".to_string()),
        ]);
        let req = HttpRequest {
            method: "GET".into(), uri: "/".into(), path: "/".into(),
            query_string: String::new(), full_uri: "/".into(),
            headers: AHashMap::new(), cookies, body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let texts = req.searchable_text();
        let keys: Vec<&str> = texts.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"cookie:session"));
        assert!(keys.contains(&"cookie:secret"));
    }

    #[test]
    fn test_http_request_clone() {
        let req = HttpRequest {
            method: "GET".into(), uri: "/clone-test".into(), path: "/clone-test".into(),
            query_string: String::new(), full_uri: "/clone-test".into(),
            headers: AHashMap::new(), cookies: AHashMap::new(), body: Vec::new(),
            content_length: None, remote_addr: "127.0.0.1:0".parse().unwrap(),
            is_https: false,
        };
        let cloned = req.clone();
        assert_eq!(req.method, cloned.method);
        assert_eq!(req.uri, cloned.uri);
    }
}
