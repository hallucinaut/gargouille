// ╔══════════════════════════════════════════════════════════╗
// ║  Gargouille WAF — Lightweight Web Application Firewall   ║
// ╚══════════════════════════════════════════════════════════╝

//! # Gargouille WAF Engine Library
//!
//! A modular web application firewall engine written in Rust.
//! Parses HTTP requests, runs 9 rule detectors, scores threats,
//! and returns a simple allow/block decision.
//!
//! ## Quick start
//!
//! Add this crate as a dependency in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! gargouille = { version = "0.1" }
//! ```
//!
//! ```ignore
//! use gargouille::config::WafConfig;
//! use gargouille::{GargouilleWaf, HttpRequest};
//!
//! let config = WafConfig::default();
//! let mut waf = GargouilleWaf::new(config);
//!
//! let request = HttpRequest {
//!     method: "GET".into(),
//!     uri: "/page".into(),
//!     path: "/page".into(),
//!     query_string: String::new(),
//!     full_uri: "/page".into(),
//!     headers: Default::default(),
//!     cookies: Default::default(),
//!     body: Vec::new(),
//!     content_length: None,
//!     remote_addr: "127.0.0.1:12345".parse().unwrap(),
//!     is_https: false,
//! };
//!
//! let decision = waf.evaluate(&request);
//! println!("{:?}", decision);
//! ```
//!
//! ## Feature flags
//!
//! | Feature | Default | What it gates |
//! |---------|---------|---------------|
//! | `sqlite` | yes     | [`database`] module (SQLite blocklist / audit log) |
//! | `prometheus` | yes | [`metrics`] module (Prometheus text exporter) |
//! | `tls-inspection` | no | TLS config types in the [`config`] module |
//! | `geo-ip` | no | GeoIP config types in the [`config`] module |
//!
//! Drop a feature with `default-features = false` in your `Cargo.toml`
//! to shrink the dependency tree.

#![deny(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

// ── Always-available modules ───────────────────────────────

mod allowlist_schema;
mod allowlist_service;

mod config;
pub use config::*;

mod engine;
pub use engine::*;

mod parser;
pub use parser::*;

pub mod scoring;

mod rate_limit;
pub use rate_limit::*;

mod waf;
pub use waf::*;

/// Rule detectors — one module per attack category.
pub mod rules;

// ── Feature-gated modules ─────────────────────────────────

#[cfg(feature = "prometheus")]
pub mod metrics;

#[cfg(feature = "sqlite")]
pub mod database;
