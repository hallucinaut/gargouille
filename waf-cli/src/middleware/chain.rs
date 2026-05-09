//! Request middleware chain — each middleware processes the request in sequence.
//! Middleware runs before and after the WAF engine evaluation.

use waf_core::ResponseHeadersConfig;
use axum::http::{HeaderName, HeaderValue};

/// A middleware layer that can be applied to the Axum router.
#[derive(Clone)]
pub struct GargouilleMiddleware {
    pub response_headers: ResponseHeadersConfig,
}

impl GargouilleMiddleware {
    /// Create a new middleware with standard security headers.
    pub fn new(response_headers: ResponseHeadersConfig) -> Self {
        Self { response_headers }
    }

    /// Apply security headers to a response header map.
    pub fn apply_security_headers(&self, headers: &mut axum::http::HeaderMap) {
        let mut set = |name: &str, value: &str| {
            if let Ok(hv) = HeaderValue::from_str(value) {
                headers.insert(HeaderName::from_bytes(name.as_bytes()).unwrap(), hv);
            }
        };

        set("X-Frame-Options", &self.response_headers.x_frame_options);
        set("X-Content-Type-Options", &self.response_headers.x_content_type_options);
        set("X-XSS-Protection", &self.response_headers.x_xss_protection);
        set("Content-Security-Policy", &self.response_headers.content_security_policy);
        set("Referrer-Policy", &self.response_headers.referrer_policy);
        set("Permissions-Policy", &self.response_headers.permissions_policy);

        // HSTS — always applied when present
        if !self.response_headers.strict_transport_security.is_empty() {
            set("Strict-Transport-Security", &self.response_headers.strict_transport_security);
        }
    }
}
