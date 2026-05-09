//! Middleware pipeline for integrating Gargouille into an HTTP server.
//! Provides security header injection and response modification.

mod chain;
pub use chain::GargouilleMiddleware;
