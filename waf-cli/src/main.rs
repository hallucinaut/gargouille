// ╔══════════════════════════════════════════════════╗
// ║  Gargouille WAF CLI - Management & Server        ║
// ╚══════════════════════════════════════════════════╝

#![deny(unsafe_code)]
#![warn(clippy::all)]

mod middleware;

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::Body;
use axum::{http::{HeaderMap, Response, StatusCode}, Router};
use axum::response::IntoResponse;
use clap::Parser;

use ahash::AHashMap;
use waf_core::{admin_auth::AdminAuthService, Decision, GargouilleWaf, HttpRequest, WafConfig};
use crate::middleware::GargouilleMiddleware;

// ── CLI argument parsing ────────────────────────────────

#[derive(clap::Parser, Debug)]
#[command(name = "gargouille", version, about = "Gargouille WAF - Ultra-fast web application firewall")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Start the WAF reverse proxy server
    Serve {
        #[arg(long, short = 'c', default_value = "config/default.toml")]
        config: String,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        upstream_port: Option<u16>,
    },

    /// Block an IP address via the management API
    Block {
        #[arg()]
        ip: String,
        #[arg(long, short = 'r', default_value = "security")]
        reason: String,
        #[arg(long, default_value_t = 8080u16)]
        admin_port: u16,
        #[arg(long)]
        token: Option<String>,
    },

    /// Unblock an IP address via the management API
    Unblock {
        #[arg()]
        ip: String,
        #[arg(long, default_value_t = 8080u16)]
        admin_port: u16,
        #[arg(long)]
        token: Option<String>,
    },

    /// Add an IP to the whitelist via the management API
    Whitelist {
        #[arg()]
        ip: String,
        #[arg(long, short = 'r', default_value = "trusted")]
        reason: String,
        #[arg(long, default_value_t = 8080u16)]
        admin_port: u16,
        #[arg(long)]
        token: Option<String>,
    },

    /// Show WAF status and recent threats via the management API
    Status {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = 8080u16)]
        admin_port: u16,
        #[arg(long)]
        token: Option<String>,
    },

    /// Render Prometheus metrics (for scraping)
    Metrics,

    /// Validate configuration file
    CheckConfig {
        #[arg()]
        config: String,
    },
}

// ── Main entry point ────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Serve { .. } => {
            serve(cli.command).await;
        }
        Commands::Block { ip, reason, admin_port, token } => {
            let tok = token.as_deref();
            handle_block_ip(ip.as_str(), reason.as_str(), *admin_port, tok).await;
        }
        Commands::Unblock { ip, admin_port, token } => {
            let tok = token.as_deref();
            handle_unblock_ip(ip.as_str(), *admin_port, tok).await;
        }
        Commands::Whitelist { ip, reason, admin_port, token } => {
            let tok = token.as_deref();
            handle_whitelist_ip(ip.as_str(), reason.as_str(), *admin_port, tok).await;
        }
        Commands::Status { limit, admin_port, token } => {
            let tok = token.as_deref();
            handle_status(limit.unwrap_or(20), *admin_port, tok).await;
        }
        Commands::Metrics => {
            println!("Gargouille WAF Metrics");
            let metrics = waf_core::metrics::WafMetrics::new();
            println!("{}", metrics.render_metrics());
        }
        Commands::CheckConfig { config } => {
            handle_check_config(config.as_str());
        }
    }
}

// ── Server implementation ───────────────────────────────

async fn serve(cmd: Commands) {
    let serve_cmd = match &cmd {
        Commands::Serve { config, port, upstream_port } => ServeCmd {
            config: config.clone(),
            port: *port,
            upstream_port: *upstream_port,
        },
        _ => return,
    };

    // Load and sanitize configuration
    let config_path = std::path::PathBuf::from(&serve_cmd.config);
    let mut config = WafConfig::load(&config_path).expect("Failed to load config");
    config.sanitize();

    // Create the WAF instance (thread-safe via Mutex internals)
    let waf = Arc::new(GargouilleWaf::new(config.clone()));

    // Determine effective ports
    let server_port = serve_cmd.port.unwrap_or(config.server.listen_port);
    let upstream_host = config.server.upstream_host.clone();
    let upstream_port = serve_cmd.upstream_port.unwrap_or(config.server.upstream_port);

    println!("Gargouille WAF v{} - Starting...", env!("CARGO_PKG_VERSION"));
    println!("   Listen:         {}:{} ", config.server.listen_addr, server_port);
    println!("   Upstream:       {}:{}", upstream_host, upstream_port);
    // Set up secure admin auth
    let admin_service = AdminAuthService::new(&config);
    let admin_prefix = admin_service.get_path_prefix();
    let admin_token = admin_service.get_log_token_value();
    println!("   Admin API:      http://{}:{}", config.server.listen_addr, server_port);
    println!("   Admin path:     {}", admin_prefix);
    println!("   Admin token:    {} (set in X-Admin-Token header)", admin_token);

    // Bind listener
    let addr: SocketAddr = format!("{}:{}", config.server.listen_addr, server_port).parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind listener");
    println!("Listening on port {} (WAF proxy + Admin API)", server_port);

    // Create middleware for security headers
    let middleware = GargouilleMiddleware::new(config.response_headers.clone());

    // Build the app with shared state and proper route handlers
    let state = AppState {
        waf: waf.clone(),
        admin_service: admin_service.clone(),
        upstream_host: upstream_host.clone(),
        upstream_port,
        middleware,
    };

    // Use the dynamic admin prefix for all admin routes
    let router = Router::new()
        .route(&format!("{}block/{{ip}}", admin_prefix), axum::routing::post(block_admin_handler))
        .route(&format!("{}unblock/{{ip}}", admin_prefix), axum::routing::post(unblock_admin_handler))
        .route(&format!("{}whitelist/{{ip}}", admin_prefix), axum::routing::post(whitelist_admin_handler))
        .route(&format!("{}status", admin_prefix), axum::routing::get(status_handler))
        .route(&format!("{}metrics", admin_prefix), axum::routing::get(metrics_handler))
        .fallback(axum::routing::get(proxy_handler).post(proxy_handler))
        .with_state(state);

    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("Server error: {}", e);
    }
}

// ── Application state ───────────────────────────────────

#[derive(Clone)]
struct AppState {
    waf: Arc<GargouilleWaf>,
    admin_service: AdminAuthService,
    upstream_host: String,
    upstream_port: u16,
    middleware: GargouilleMiddleware,
}

// ── Admin route handlers ────────────────────────────────

async fn block_admin_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    path: String,
) -> impl IntoResponse {
    // Authenticate via X-Admin-Token header
    let token = headers.get("X-Admin-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let result = state.admin_service.authenticate(token, &format!("/block/{}", path));
    if !result.authorized {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"authentication_required"}"#))
            .unwrap();
    }

    let ip = path;
    if !waf_core::database::validate_ip(&ip) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"invalid_ip_address"}"#))
            .unwrap();
    }
    state.waf.block_ip(&ip, "cli-admin");
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(format!("IP {} blocked", ip)))
        .unwrap();
    state.middleware.apply_security_headers(resp.headers_mut());
    resp
}

async fn unblock_admin_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    path: String,
) -> impl IntoResponse {
    // Authenticate via X-Admin-Token header
    let token = headers.get("X-Admin-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let result = state.admin_service.authenticate(token, &format!("/unblock/{}", path));
    if !result.authorized {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"authentication_required"}"#))
            .unwrap();
    }

    let ip = path;
    if !waf_core::database::validate_ip(&ip) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"invalid_ip_address"}"#))
            .unwrap();
    }
    state.waf.unblock_ip(&ip);
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(format!("IP {} unblocked", ip)))
        .unwrap();
    state.middleware.apply_security_headers(resp.headers_mut());
    resp
}

async fn whitelist_admin_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
    path: String,
) -> impl IntoResponse {
    // Authenticate via X-Admin-Token header
    let token = headers.get("X-Admin-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let result = state.admin_service.authenticate(token, &format!("/whitelist/{}", path));
    if !result.authorized {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"authentication_required"}"#))
            .unwrap();
    }

    let ip = path;
    if !waf_core::database::validate_ip(&ip) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"invalid_ip_address"}"#))
            .unwrap();
    }
    state.waf.whitelist_ip(&ip, "cli-admin");
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(format!("IP {} whitelisted", ip)))
        .unwrap();
    state.middleware.apply_security_headers(resp.headers_mut());
    resp
}

async fn status_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Authenticate via X-Admin-Token header
    let token = headers.get("X-Admin-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let result = state.admin_service.authenticate(token, "/status");
    if !result.authorized {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"authentication_required"}"#))
            .unwrap();
    }

    let status_json = waf_core::admin_auth::service::AdminCommandExecutor::execute_status();
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(status_json))
        .unwrap();
    state.middleware.apply_security_headers(resp.headers_mut());
    resp
}

async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Authenticate via X-Admin-Token header
    let token = headers.get("X-Admin-Token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let result = state.admin_service.authenticate(token, "/metrics");
    if !result.authorized {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "text/plain")
            .body(Body::from(r#"{"error":"authentication_required"}"#))
            .unwrap();
    }

    let metrics_text = state.waf.render_metrics();
    let body_content = if metrics_text.is_empty() {
        String::from("No metrics enabled (prometheus feature not active)")
    } else {
        metrics_text
    };
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(body_content))
        .unwrap();
    state.middleware.apply_security_headers(resp.headers_mut());
    resp
}

// ── Proxy handler — WAF evaluation + upstream forwarding ─

async fn proxy_handler(
    axum::extract::State(state): axum::extract::State<AppState>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let waf = &state.waf;

    // Build headers map from the request (normalized to lowercase keys)
    let mut headers_map = ahash::AHashMap::<String, Vec<String>>::new();
    for (name, value) in headers.iter() {
        if let Ok(s) = std::str::from_utf8(value.as_bytes()) {
            headers_map.entry(name.as_str().to_lowercase()).or_insert_with(Vec::new).push(s.to_string());
        }
    }

    // Extract body bytes
    let body_bytes: Vec<u8> = body.to_vec();

    // Check body size limit
    let max_body = waf.config().waf.max_body_size;
    if max_body > 0 && body_bytes.len() > max_body {
        let mut resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"error":"blocked","reason":"Body exceeds maximum size"}"#))
            .unwrap();
        state.middleware.apply_security_headers(resp.headers_mut());
        return resp;
    }

    // Build internal request representation
    let http_req = HttpRequest {
        method: method.as_str().to_string(),
        uri: uri.path().to_string(),
        path: uri.path().to_string(),
        query_string: uri.query().unwrap_or("").to_string(),
        full_uri: uri.to_string(),
        headers: headers_map,
        cookies: AHashMap::new(),
        body: body_bytes.clone(),
        content_length: None,
        remote_addr: "127.0.0.1:0".parse().unwrap(),
        is_https: false,
    };

    // Evaluate against WAF rules
    let decision = waf.evaluate(&http_req);

    match decision {
        Decision::Pass => {
            // Actually forward to upstream
            let upstream = format!("http://{}:{}", state.upstream_host, state.upstream_port);
            let client = reqwest::Client::new();
            let url = if let Some(q) = uri.query() {
                format!("{}?{}", upstream, q)
            } else {
                format!("{}{}", upstream, uri.path())
            };

            let method = reqwest::Method::from_str(&method.to_string()).unwrap_or(reqwest::Method::GET);
            match client.request(method, &url)
                .body(reqwest::Body::from(body_bytes))
                .send().await
            {
                Ok(resp) => {
                    let status = resp.status();
                    let resp_headers = resp.headers().clone();
                    match resp.bytes().await {
                        Ok(bytes) => {
                            let mut builder = Response::builder().status(status.as_u16());
                            for (name, value) in &resp_headers {
                                if let Ok(v) = value.to_str() {
                                    builder = builder.header(name.as_str(), v);
                                }
                            }
                            let mut response = builder.body(Body::from(bytes.to_vec())).unwrap();
                            state.middleware.apply_security_headers(response.headers_mut());
                            response
                        },
                        Err(_) => {
                            let mut resp = Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from("Failed to read upstream response body"))
                                .unwrap();
                            state.middleware.apply_security_headers(resp.headers_mut());
                            resp
                        }
                    }
                },
                Err(_) => {
                    let mut resp = Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from("Upstream connection failed"))
                        .unwrap();
                    state.middleware.apply_security_headers(resp.headers_mut());
                    resp
                }
            }
        },
        Decision::Blocked(reason) => {
            let mut resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .body(Body::from(format!(r#"{{"error":"blocked","reason":"{}"}}"#, reason)))
                .unwrap();
            state.middleware.apply_security_headers(resp.headers_mut());
            resp
        },
        Decision::Challenge => {
            let mut resp = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "text/html")
                .body(Body::from("<h1>Challenge Required</h1>"))
                .unwrap();
            state.middleware.apply_security_headers(resp.headers_mut());
            resp
        },
        Decision::RateLimited => {
            let mut resp = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", "60")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"error":"rate_limited"}"#))
                .unwrap();
            state.middleware.apply_security_headers(resp.headers_mut());
            resp
        },
    }
}

// ── Serve command helper struct ──────────────────────────

struct ServeCmd {
    config: String,
    port: Option<u16>,
    upstream_port: Option<u16>,
}

// ── CLI handler functions ───────────────────────────────

async fn handle_block_ip(ip: &str, reason: &str, admin_port: u16, token: Option<&str>) {
    let client = reqwest::Client::new();
    let mut builder = client.post(format!("http://127.0.0.1:{}/block/{}", admin_port, ip));
    if let Some(tok) = token {
        builder = builder.header("X-Admin-Token", tok);
    }
    match builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                println!("✅ Blocked IP: {} (reason: {})", ip, reason);
            } else {
                let text = resp.text().await.unwrap_or_default();
                eprintln!("❌ Server error: {} - {}", status, text);
            }
        }
        Err(e) => eprintln!("❌ Failed to block IP {}: {}", ip, e),
    }
}

async fn handle_unblock_ip(ip: &str, admin_port: u16, token: Option<&str>) {
    let client = reqwest::Client::new();
    let mut builder = client.post(format!("http://127.0.0.1:{}/unblock/{}", admin_port, ip));
    if let Some(tok) = token {
        builder = builder.header("X-Admin-Token", tok);
    }
    match builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                println!("✅ Unblocked IP: {}", ip);
            } else {
                let text = resp.text().await.unwrap_or_default();
                eprintln!("❌ Server error: {} - {}", status, text);
            }
        }
        Err(e) => eprintln!("❌ Failed to unblock IP {}: {}", ip, e),
    }
}

async fn handle_whitelist_ip(ip: &str, reason: &str, admin_port: u16, token: Option<&str>) {
    let client = reqwest::Client::new();
    let mut builder = client.post(format!("http://127.0.0.1:{}/whitelist/{}", admin_port, ip));
    if let Some(tok) = token {
        builder = builder.header("X-Admin-Token", tok);
    }
    match builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                println!("✅ Whitelisted IP: {} (reason: {})", ip, reason);
            } else {
                let text = resp.text().await.unwrap_or_default();
                eprintln!("❌ Server error: {} - {}", status, text);
            }
        }
        Err(e) => eprintln!("❌ Failed to whitelist IP {}: {}", ip, e),
    }
}

async fn handle_status(limit: usize, admin_port: u16, token: Option<&str>) {
    let client = reqwest::Client::new();
    let mut builder = client.get(format!("http://127.0.0.1:{}/status?limit={}", admin_port, limit));
    if let Some(tok) = token {
        builder = builder.header("X-Admin-Token", tok);
    }
    match builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                println!("📋 WAF Status:\n{}", text);
            } else {
                let text = resp.text().await.unwrap_or_default();
                eprintln!("❌ Server error: {} - {}", status, text);
            }
        }
        Err(e) => eprintln!("❌ Failed to get status: {}", e),
    }
}

fn handle_check_config(config_path: &str) {
    let path = std::path::PathBuf::from(config_path);
    match waf_core::WafConfig::load(&path) {
        Ok(mut config) => {
            println!("✅ Config loaded successfully");
            config.sanitize();
            let warnings = config.validate();
            if !warnings.is_empty() {
                for w in &warnings {
                    println!("⚠  Warning: {}", w);
                }
            }
            if warnings.is_empty() {
                println!("✅ No warnings");
            }
        }
        Err(e) => eprintln!("❌ Config load error: {}", e),
    }
}
