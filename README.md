# Gargouille — Web Application Firewall

A lightweight HTTP request inspection engine written in Rust. It evaluates incoming requests against 9 rule detectors, scores threats, and returns an allow/block decision. Built as a reverse proxy server with an admin API for runtime management.

## Architecture

```
                    Client ──▶ Gargouille WAF ──▶ Upstream Backend
                             (inspect & decide)     (forward allowed)
```

## What it does

### Core Engine (`waf-core` crate)

- **Request parsing** — Extracts method, URI, path, query string, headers, cookies, and body
- **9 rule detectors** — SQL injection, XSS, command injection, LFI/RFI, SSTI, SSRF, insecure deserialization, HTTP header injection, path traversal
  - Each detector uses compiled regex patterns for deep analysis
  - Confidence scores per match (0.4–0.95) based on pattern type
  - Double/triple URL-decoding check to catch encoded attacks
- **Risk scoring** — Accumulates threat points across all detectors; capped at 100, max 3 hits per category
- **Decision pipeline** — Returns one of four outcomes: `Pass`, `Block(reason)`, `Challenge`, `RateLimited`
- **Direct-block override** — Any single threat with confidence >= config threshold forces a block
- **Path-based allowlist (deny-by-default)** — Block all requests except those on explicitly allowed paths. Auto-whitelists `/admin/*` and `/metrics` so the WAF stays manageable. Allowed paths still get full WAF rule scanning, so attacks inside allowed paths are detected and blocked.
- **Sliding-window rate limiter** — Per-IP request counting with configurable burst allowance and auto-expiring blocks
- **Per-endpoint rate limiting** — Separate limits for configured paths (e.g., `/api/login`)
- **SQLite blocklist & audit log** — Persistent IP block/whitelist lists and per-request audit entries (feature-gated)
- **Prometheus metrics** — Atomic counters for requests, blocks, challenges, allowed, and per-category threat tallies (feature-gated)

### Server (`waf-cli` binary)

- **Axum-based HTTP server** — Reverse proxy that binds to a configurable port
- **Security headers** — X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy, HSTS applied to all responses
- **Admin API** — REST endpoints for runtime management:
  - `POST /admin/block/{ip}` — Block an IP with reason (validates IP format)
  - `POST /admin/unblock/{ip}` — Unblock an IP (validates IP format)
  - `POST /admin/whitelist/{ip}` — Whitelist an IP with reason (validates IP format)
  - `GET /admin/status` — Health check (returns JSON status)
  - `GET /admin/metrics` — Prometheus metrics text export
- **Upstream forwarding** — Allowed requests are forwarded to the configured backend preserving method, query string, body, and response headers

## Quick start

```bash
cd gargouille

# Build everything
cargo build

# Run all tests (190 unit + 62 integration)
cargo test --all

# Validate configuration
./target/debug/gargouille check-config config/default.toml

# Render metrics (standalone, no server needed)
./target/debug/gargouille metrics
```

## CLI commands

| Command | Description |
|---------|-------------|
| `serve [-c config] [--port PORT] [--upstream-port PORT]` | Starts the WAF reverse proxy + admin API server. Loads TOML config and binds to configurable port. |
| `block <ip> [-r reason] [--admin-port PORT]` | Sends a POST request to a running server's admin API at `/admin/block/{ip}`. Validates IP format. |
| `unblock <ip> [--admin-port PORT]` | Sends a POST request to `/admin/unblock/{ip}` on the running server. |
| `whitelist <ip> [-r reason] [--admin-port PORT]` | Sends a POST request to `/admin/whitelist/{ip}` on the running server. |
| `status [--limit N] [--admin-port PORT]` | Sends a GET request to `/admin/status?limit={N}` on the running server. Prints JSON status. |
| `metrics` | Instantiates a fresh WafMetrics, renders and prints Prometheus-format metrics. (No live data.) |
| `check-config <file>` | Loads, validates, and sanitizes a TOML configuration file. Prints warnings for out-of-range values. |

## Configuration

All settings live in `config/default.toml`, loaded via `WafConfig::load()`. Missing keys fall back to sensible defaults.

### Server settings

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `0.0.0.0` | Bind address |
| `listen_port` | `8443` | WAF proxy + admin API port |
| `upstream_host` | `127.0.0.1` | Backend server host |
| `upstream_port` | `3000` | Backend server port |
| `tls_enabled` | `true` | TLS configuration flag (server-side TLS serving not yet implemented) |

### WAF engine settings

| Key | Default | Description |
|-----|---------|-------------|
| `default_action` | `Block` | Block, Challenge, Log, RateLimit, or Scan |
| `max_body_size` | `10485760` | 10 MB — oversized bodies rejected before scanning (DoS protection) |
| `upstream_timeout_ms` | `30000` | reqwest timeout for upstream forwarding |
| `strict_mode` | `true` | Enable strict HTTP compliance checks |

### Allowlist settings

| Key | Default | Description |
|-----|---------|-------------|
| `allowlist.allowed` | `false` | When true, only requests whose path matches an entry in `allowed_paths` are forwarded. All other paths return 403 immediately. Admin endpoints (`/admin/*`) and metrics (`/metrics*`) are always accessible regardless of this setting. |
| `allowlist.allowed_paths` | `[]` | List of paths (exact or prefix) that are permitted when allowlist mode is active. Each entry must start with `/`, contain no query strings, no path traversal sequences, and no control characters. Maximum 512 characters per entry. Prefix matching: adding `/api` allows `/api`, `/api/users`, `/api/v1/data`. |

### Scoring settings

Each category contributes `weight * min(matches, 3)` points (max 3 per category). Total is capped at 100.

| Key | Default | Description |
|-----|---------|-------------|
| `threat_threshold` | `50` | Block if accumulated score >= this value (capped at 100) |
| `high_confidence_threshold` | `0.90` | Any single match at >= this confidence forces a direct block |

Per-category weights: `sql_injection_weight`, `xss_weight`, `command_injection_weight`, `lfi_rfi_weight`, `ssti_weight`, `ssrf_weight`, `deserialization_weight`, `header_injection_weight`, `path_traversal_weight`, `protocol_violation_weight` (all default 15–35).

### Rate limiting settings

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable sliding window rate limiter |
| `requests_per_window` | `100` | Allowed requests per IP per window |
| `window_seconds` | `60` | Sliding window size |
| `burst_allowance` | `20` | Extra requests allowed above the hard limit |
| `endpoint_limits` | `{}` | Per-path limits: `{"\/api\/login": 10, ...}` |

### Blocklist settings

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable SQLite blocklist/whitelist |
| `database_path` | `database/gargouille.db` | SQLite database file path |

### Metrics settings

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable Prometheus metrics |
| `port` | `9090` | Metrics server port (for future use) |
| `path` | `\/metrics` | Metrics endpoint path |

### Response headers

These security headers are applied to all responses via middleware:

- `X-Frame-Options`: DENY
- `X-Content-Type-Options`: nosniff
- `Content-Security-Policy`: default-src 'self'; script-src 'self'
- `Referrer-Policy`: strict-origin-when-cross-origin
- `Permissions-Policy`: camera=(), microphone=(), geolocation=()
- `Strict-Transport-Security`: max-age=31536000; includeSubDomains

## Library usage

`waf-core` is a standalone crate you can embed in any Rust project:

```toml
[dependencies]
# With all features (SQLite + Prometheus):
waf-core = { path = "../gargouille/waf-core", version = "0.1" }

# Minimal — no SQLite, no Prometheus (~15 fewer deps):
waf-core = { path = "../gargouille/waf-core", version = "0.1", default-features = false }
```

```rust
use waf_core::{GargouilleWaf, HttpRequest, WafConfig};
use std::net::SocketAddr;
use ahash::AHashMap;

let config = WafConfig::default();
let waf = GargouilleWaf::new(config);

let request = HttpRequest {
    method: "GET".into(),
    uri: "/page?q=test".into(),
    path: "/page".into(),
    query_string: "q=test".into(),
    full_uri: "/page?q=test".into(),
    headers: Default::default(),
    cookies: Default::default(),
    body: Vec::new(),
    content_length: None,
    remote_addr: "127.0.0.1:54321".parse().unwrap(),
    is_https: false,
};

match waf.evaluate(&request) {
    waf_core::Decision::Pass            => println!("allowed"),
    waf_core::Decision::Blocked(reason) => println!("blocked: {}", reason),
    waf_core::Decision::Challenge       => println!("challenge required"),
    waf_core::Decision::RateLimited     => println!("rate limited"),
}
```

### SQLite feature (blocklist and audit log)

```rust
#[cfg(feature = "sqlite")]
let result: bool = waf.block_ip("10.0.0.1", "suspicious activity");
#[cfg(feature = "sqlite")]
let threats: Vec<_> = waf.get_recent_threats(50).unwrap_or_default();

#[cfg(feature = "prometheus")]
println!("{}", waf.render_metrics());
```

### Feature flags

| Feature | Default | What it gates |
|---------|---------|---------------|
| `sqlite` | yes | `database` module — SQLite blocklist, whitelist, audit log |
| `prometheus` | yes | `metrics` module — Prometheus atomic counters + text export |
| `tls-inspection` | no | Config types in `WafConfig` (TLS inspector, bot protection) |
| `geo-ip` | no | Config types in `WafConfig` (GeoIP blocking settings) |

Drop features with `default-features = false` to minimize the dependency tree. The core engine (~15 deps, regex-only) runs without any optional feature.

## Decision flow

```
Request arrives
    │
    ├─ Per-endpoint rate limiter ── if exceeded → Decision::RateLimited
    │
    ├─ General rate limiter ──────── if exceeded → Decision::RateLimited
    │
    ├─ Blocklist lookup ──────────── if matched → Decision::Blocked(IpBlocklisted)
    │
    ├─ Body size check ───────────── if oversized → Decision::Blocked(ThreatScoreExceeded)
    │
    ├─ Run all 9 detectors ─────────► collect threats with confidence scores
    │
    ├─ Score accumulation ────────── weight * min(matches, 3), capped at 100
    │
    ├─ Direct-block check ────────── any confidence >= threshold → Decision::Blocked(DirectBlock)
    │
    ├─ Threshold comparison ──────── score >= threshold → Decision::Blocked(ThreatScoreExceeded)
    │
    └─ Default ─────────────────────► Decision::Pass (forward to upstream)
```

### Deny-by-default decision flow (when allowlist is enabled)

When `waf.allowlist.allowed = true`, the pipeline changes slightly. A new first checkpoint runs before everything else:

```
Request arrives
    │
    ├─ Allowlist check ─────────── if path not in allowed list → Decision::Blocked
    │                                  (but /admin/* and /metrics* auto-pass)
    │
    ├─ Per-endpoint rate limiter ── if exceeded → Decision::RateLimited
    ...
```

The key difference: **only requests whose path matches an entry in `allowed_paths` reach the WAF rule detectors**. All other paths are dropped at the door with a 403.

This is different from traditional WAF behavior where everything passes through unless something malicious is detected. The deny-by-default model starts from zero trust: no endpoint is accessible unless you explicitly name it.

#### Why deny-by-default?

For small projects, traditional allow-list-and-check approach creates maintenance debt:

| Traditional (allow-by-default) | Deny-by-default |
|-------------------------------|-----------------|
| Every new route must stay clean or be patched | You whitelist routes you actually have |
| Forgetting a rule catches nothing | Forgetting to add a path blocks it immediately |
| 9 detectors run on every request, including static assets that would never be attacked | Only whitelisted routes hit the detection engine |
| Attackers probe all endpoints looking for loopholes | Most of your surface area is already closed |

With deny-by-default:

- You list only your real API routes (e.g., `/test/toto`, `/api/login`)
- Every other URL returns 403 before any scanning happens
- Whitelisted routes still get all 9 WAF rule detectors active, so SQLi and XSS inside allowed paths are caught
- Admin endpoints (`/admin/*`) are auto-whitelisted so you can always manage the WAF

Example config:

```toml
[waf]
allowlist = { allowed = true, allowed_paths = ["/test/toto", "/api/login"] }
```

With this configuration:
- `GET /test/toto` — passes through WAF scanning, clean requests reach upstream, attacks are blocked
- `POST /test/toto` with body `' OR 1=1 --` — allowed by allowlist (path matches), then SQLi detector catches the attack and blocks it
- `GET /anything-else` — immediately blocked, never reaches WAF rules
- `GET /admin/status` — always accessible (auto-whitelisted)

## Rule detectors

| Detector | File | Patterns | Key features |
|----------|------|----------|--------------|
| **SQL Injection** | `rules/sql_injection.rs` | UNION SELECT, stacked queries, tautologies, error-based, keyword sequences, comment injection | URL-encoded variants via decoded pass-through |
| **XSS** | `rules/xss.rs` | Script tags, event handlers (30+ attributes), data/JavaScript URIs, vector elements, template expressions | Case-insensitive, encoded `<script>` detection |
| **Command Injection** | `rules/cmdi.rs` | Pipe chains, subshell exec `$()`, backtick execution, dangerous commands, environment abuse, NOP tricks | `%3B` semicolon-encoded detection |
| **LFI/RFI** | `rules/lfi_rfi.rs` | Path traversal sequences, `/etc/passwd` access, PHP wrappers, Java class loading | Encoded traversal and UNC path patterns |
| **SSTI** | `rules/ssti.rs` | Jinja/Twig config/self access, Groovy/SpEL Runtime.exec, Python object access | Safely allows benign templates like `Hello {{ name }}` |
| **SSRF** | `rules/ssrf.rs` | Cloud metadata endpoints, private RFC1918 ranges, localhost/loopback, internal protocol abuse | Encoded hostname detection |
| **Deserialization** | `rules/deserialization.rs` | PHP serialized objects, Python pickle protocols, YAML object tags, .NET BinaryFormatter | Matches raw serialized payload signatures |
| **Header Injection** | `rules/header_injection.rs` | CRLF sequences, response splitting, Set-Cookie/Location manipulation, X-Forwarded-Host injection | Double-encoded CRLF detection |
| **Path Traversal** | `rules/path_traversal.rs` | Classic `../`, backslash traversal, double encoding, null byte injection | Separate from LFI — focuses on filename/path poisoning |

## Metrics

When the `prometheus` feature is active, `WafMetrics` tracks:

| Counter / Gauge | Description |
|-----------------|-------------|
| `gargouille_total_requests` | Total requests processed |
| `gargouille_blocked_requests` | Requests blocked by WAF |
| `gargouille_allowed_requests` | Requests passed to upstream |
| `gargouille_challenged_requests` | Requests sent to challenge |
| `gargouille_threat_score` | Threat score of the last blocked request (gauge) |
| Per-category counters | Match counts per attack category |

Rendered in Prometheus text exposition format via `WafMetrics::render_metrics()`.

## Architecture

```
gargouille/
  waf-core/src/                  ← reusable library crate
    lib.rs                       — Public API surface (pub use re-exports)
    config.rs                    — WafConfig, all sub-configs, TOML load/validate/sanitize
    waf.rs                       — GargouilleWaf: orchestrates rate limiter → blocklist →
                                   body check → rule engine → scoring → decision
    engine.rs                    — RuleEngine: instantiates 9 detectors, runs scan pipeline
    parser.rs                    — HttpRequest struct, URL decoding (limited depth),
                                   query param parsing, cookie parsing, searchable_text()
    allowlist_schema.rs          — Zero-trust path validation: rejects traversal, null bytes, encoded attacks, entries over 512 chars
    allowlist_service.rs         — Thread-safe allowlist gatekeeper: prefix matching, auto-whitelist for /admin and /metrics, runtime update support
    scoring.rs                   — ThreatInfo, ThreatCategory, ThreatScore, Action,
                                   BlockingReason, ScoringEngine (weight accumulation)
    rate_limit.rs                — RateLimiter: per-IP sliding window + blocked IP map
    metrics.rs                   — WafMetrics: atomic counters + Prometheus render
    database.rs                  — SQLite CRUD: blocklist, whitelist, audit log (feature-gated)
    rules/                       — Rule detectors — one module per attack category
      mod.rs                     — Shared helpers: compile_regex(), normalize_for_scan(),
                                   check_encoded_variations(), calibrate_confidence()
      sql_injection.rs           — 6 patterns (union, stacked, error, keyword, tautology, comments)
      xss.rs                     — 5 patterns (event handlers, script tags, data URIs,
                                     vector elements, template expressions)
      cmdi.rs                    — 5 patterns (pipe chains, subshell exec, dangerous cmds,
                                     env abuse, NOP tricks)
      lfi_rfi.rs                 — 4 patterns (path traversal, etc. access, PHP wrappers,
                                     Java class loading)
      ssti.rs                    — 3 patterns (Jinja/Twig, Groovy/SpEL, Python object access)
      ssrf.rs                    — 4 patterns (cloud metadata, private networks, localhost,
                                     protocol abuse)
      deserialization.rs         — 4 patterns (PHP serialized, Python pickle, YAML tags,
                                     .NET BinaryFormatter)
      header_injection.rs        — 4 patterns (CRLF direct, CRLF header manipulation,
                                     host injection, response splitting)
      path_traversal.rs          — 4 patterns (classic traversal, double encoding, null byte,
                                     backslash traversal)

  waf-cli/src/                   ← binary crate — CLI + HTTP server
    main.rs                      — clap CLI parsing, Axum router setup with state-driven
                                   admin API + proxy handlers, upstream forwarding via reqwest,
                                   security header middleware applied to all responses
    middleware/mod.rs            — Middleware module re-export
    middleware/chain.rs           — GargouilleMiddleware: applies security headers to responses

  waf-core/tests/
    integration_tests.rs         — End-to-end tests across all attack vectors, rate limiting,
                                   scoring thresholds, per-endpoint limits, IP validation, and HTTP methods
  config/default.toml            — Full configuration with defaults for every section
```

## Testing

```bash
# All crates — unit + integration tests
cargo test --all          # 288 tests pass (210 unit + 78 integration)

# Only waf-core library
cargo test -p waf-core    # 210 tests: lib unit tests + schema/service internal tests + integration tests

# Only CLI binary compilation (no tests in the binary crate itself)
cargo test -p waf-cli     # compiles cleanly, 0 tests
```

| Test scope | Count | Coverage |
|------------|-------|----------|
| Parser | ~28 | URL decode (single/double/triple/invalid/mixed/empty), header access, query params, cookies, searchable text |
| Config | ~12 | Defaults, deserialization, partial TOML, JSON schema generation, validation warnings, allowlist config defaults |
| Rate limiter | 14 | Limits, burst allowance, per-IP independence, blocked/unblocked IPs, endpoint-specific limits, stats, cleanup |
| Scoring engine | 12 | Empty input, single/multi-category weights, capping at 100, threshold decisions, display formatting |
| Rule detectors | ~85 | Each detector has positive tests (attack payloads), negative tests (clean inputs), case-insensitivity, edge cases |
| WAF orchestrator (`engine.rs`) | 17 | Clean requests, SQLi/XSS/CLI/PT in body+query, combined attacks, header injection, SSTI/SSRF/LFI/deserialization detection |
| Allowlist schema | ~9 | Path validation: leading slash requirement, traversal rejection, query/fragment rejection, null bytes, control chars, length limit, normalization |
| Allowlist service | ~12 | Prefix matching, exact match, auto-whitelist, disabled mode, case sensitivity, runtime update, query string stripping |
| Database | 8 | Schema creation, add/check/remove blocklist, audit log, recent threats, whitelist, duplicate handling |
| Prometheus metrics | 11 | Zero-state, increment counters, render format, reset, high/low scores |
| Integration (all) | 78 | Full pipeline: clean passes, all attack vectors blocked, rate limiting, scoring thresholds, per-endpoint limits, mixed requests, cookies, encoded queries, IP validation, case-insensitive headers, direct-block thresholds, allowlist pass/block, WAF rules on allowed paths, auto-whitelist bypass prevention |

## Security considerations

- **No raw SQL** — All database queries use parameterized statements via `rusqlite::params!`
- **ReDoS prevention** — Regex compilation uses `size_limit(1 MB)` and URL decoding is depth-limited to 10 passes
- **Score inflation defense** — Max 3 matches per category, total capped at 100
- **IP validation** — Blocklist/whitelist/admin API inserts validate IPv4/IPv6 format before writing
- **Body size enforcement** — Oversized bodies rejected before expensive scanning (DoS protection)
- **No stack trace leaks** — All errors return generic messages to clients; internal errors logged with tracing
- **Case-insensitive header lookups** — HTTP headers compared case-insensitively per RFC 7230
- **Security headers on all responses** — CSP, HSTS, X-Frame-Options applied via middleware
- **`#![deny(unsafe_code)]`** — Entire codebase forbids `unsafe` blocks

## License

MIT
