# Gargouille — Web Application Firewall

A lightweight HTTP request inspection engine written in Rust. It evaluates incoming requests against 10 rule detectors, scores threats, and returns an allow/block/challenge decision. Built as a reverse proxy server with an admin API for runtime management.

## Architecture

```
                    Client ──▶ Gargouille WAF ──▶ Upstream Backend
                             (inspect & decide)     (forward allowed)
```

## What it does

### Core Engine (`waf-core` crate)

- **Request parsing** — Extracts method, URI, path, query string, headers, cookies, and body
- **10 rule detectors** — SQL injection, XSS, command injection, LFI/RFI, SSTI, SSRF, insecure deserialization, HTTP header injection, path traversal, bot detection
  - Each detector uses compiled regex patterns for deep analysis
  - Confidence scores per match (0.4–0.95) based on pattern type
  - Double/triple URL-decoding check to catch encoded attacks
- **Risk scoring** — Accumulates threat points across all detectors; capped at 100, max 3 hits per category
- **Decision pipeline** — Returns one of four outcomes: `Pass`, `Block(reason)`, `Challenge`, `RateLimited`
- **Direct-block override** — Any single threat with confidence >= config threshold forces a block
- **Path-based allowlist (deny-by-default)** — Block all requests except those on explicitly allowed paths. Auto-whitelists literal `/admin/*` and `/metrics` endpoints so the WAF stays manageable. Allowed paths still get full WAF rule scanning, so attacks inside allowed paths are detected and blocked.
- **Sliding-window rate limiter** — Per-IP request counting with configurable burst allowance and auto-expiring blocks
- **Per-endpoint rate limiting** — Separate limits for configured paths (e.g., `/api/login`)
- **SQLite blocklist & audit log** — Persistent IP block/whitelist lists and per-request audit entries (feature-gated)
- **Prometheus metrics** — Atomic counters for requests, blocks, challenges, allowed, and per-category threat tallies (feature-gated)

### Server (`waf-cli` binary)

- **Axum-based HTTP server** — Reverse proxy that binds to a configurable port
- **Security headers** — X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy, HSTS applied to all responses
- **Admin API** — Token-authenticated REST endpoints for runtime management. All admin paths use a randomized prefix (not `/admin`) to prevent enumeration. Admin endpoints are auto-whitelisted regardless of allowlist mode:
  - `POST <prefix>block/{ip}` — Block an IP with reason (validates IPv4/IPv6 format)
  - `POST <prefix>unblock/{ip}` — Unblock an IP
  - `POST <prefix>whitelist/{ip}` — Whitelist an IP with reason
  - `GET <prefix>status` — Health check (returns JSON status)
  - `GET <prefix>metrics` — Prometheus metrics text export
  Authentication uses the `X-Admin-Token` header.
- **Upstream forwarding** — Allowed requests are forwarded to the configured backend preserving method, query string, body, and response headers

## Quick start

```bash
cd gargouille

# Build everything
cargo build

# Run all tests (287 unit + 125 integration)
cargo test --all

# Validate configuration
./target/debug/gargouille check-config config/default.toml

# Render metrics (standalone, no server needed)
./target/debug/gargouille metrics
```

## CLI commands

| Command | Description |
|---------|-------------|
| `serve [-c config] [--port PORT] [--upstream-port PORT]` | Starts the WAF reverse proxy + admin API server. Loads TOML config and binds to configurable port. Prints admin token and randomized path prefix on startup. |
| `block <ip> [-r reason] [--admin-port PORT] [--token TOKEN]` | Sends a POST request to a running server's admin API to block an IP. Validates IPv4/IPv6 format. Uses `--token` for auth if auto-generated token is not in config. |
| `unblock <ip> [--admin-port PORT] [--token TOKEN]` | Sends a POST request to the server's unblock endpoint on the running server. |
| `whitelist <ip> [-r reason] [--admin-port PORT] [--token TOKEN]` | Sends a POST request to the server's whitelist endpoint on the running server. |
| `status [--limit N] [--admin-port PORT] [--token TOKEN]` | Sends a GET request to the server's status endpoint. Prints JSON status. |
| `metrics` | Instantiates a fresh WafMetrics, renders and prints Prometheus-format metrics. (No live data.) |
| `check-config <file>` | Loads, validates, and sanitizes a TOML configuration file. Prints warnings for out-of-range values. |

The `--token` flag on CLI commands can be used when the admin token was auto-generated at startup or set via config.

## Configuration

All settings live in `config/default.toml`, loaded via `WafConfig::load()`. Missing keys fall back to sensible defaults.

### Server settings

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `0.0.0.0` | Bind address |
| `listen_port` | `8443` | WAF proxy + admin API port |
| `reverse_proxy_port` | `8080` | HTTP reverse proxy port (for TLS termination) |
| `upstream_host` | `127.0.0.1` | Backend server host |
| `upstream_port` | `3000` | Backend server port |
| `tls_enabled` | `true` | Enable TLS on the listener |
| `tls_cert` | (empty) | Path to TLS certificate file |
| `tls_key` | (empty) | Path to TLS private key file |

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

Per-category weights: `sql_injection_weight` (30), `xss_weight` (25), `command_injection_weight` (35), `lfi_rfi_weight` (30), `ssti_weight` (30), `ssrf_weight` (25), `deserialization_weight` (35), `header_injection_weight` (20), `path_traversal_weight` (20), `protocol_violation_weight` (15), `anomaly_score` (10), `bot_detection_weight` (10).

### Rate limiting settings

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable sliding window rate limiter |
| `requests_per_window` | `100` | Allowed requests per IP per window |
| `window_seconds` | `60` | Sliding window size |
| `burst_allowance` | `20` | Extra requests allowed above the hard limit |
| `endpoint_limits` | `{}` | Per-path limits: `{"\/api\/login": 10, "\/api\/register": 5, ...}` |

#### Rate limit blocking (sub-section)

| Key | Default | Description |
|-----|---------|-------------|
| `block.duration_minutes` | `60` | Duration to block an IP after exceeding the rate limit |
| `auto_unblock` | `false` | Automatically unblock IPs after the duration expires |

### Blocklist settings

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable SQLite blocklist/whitelist |
| `database_path` | `database/gargouille.db` | SQLite database file path |

### GeoIP settings (feature: geo-ip)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable IP geolocation and country blocking |
| `db_path` | (empty) | Path to MaxMind GeoLite2 Country database file |
| `blocked_countries` | `[]` | List of ISO 3166-1 alpha-2 country codes to block |
| `min_reputation_score` | `40` | Minimum IP reputation score (0–100) to allow |

### Logging settings

| Key | Default | Description |
|-----|---------|-------------|
| `level` | `info` | Log level: trace, debug, info, warn, error |
| `format` | `json` | Output format: json or pretty |
| `log_file` | (empty) | Path to log file |
| `log_blocked` | `false` | Include full details of blocked requests in logs |
| `sample_rate` | `1.0` | Request sampling ratio for high-traffic (1.0 = all, 0.1 = 10%) |

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable Prometheus metrics export |
| `port` | `9090` | Prometheus metrics server port |
| `path` | `\/metrics` | Metrics endpoint path |

### Response headers (sub-section)

These security headers are applied to all responses via middleware:

| Key | Default |
|-----|---------|
| `x_frame_options` | `DENY` |
| `x_content_type_options` | `nosniff` |
| `x_xss_protection` | `0` (disabled -- CSP handles XSS protection) |
| `content_security_policy` | `default-src 'self'; script-src 'self'` |
| `referrer_policy` | `strict-origin-when-cross-origin` |
| `permissions_policy` | `camera=(), microphone=(), geolocation=()` |
| `strict_transport_security` | `max-age=31536000; includeSubDomains` |

### Admin auth settings (sub-section)

Admin endpoints use a randomized path prefix and token-based authentication. The admin prefix is not `/admin` (it's generated from config to prevent enumeration).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Require authentication on admin endpoints |
| `token` | (auto-generated) | Secret token for X-Admin-Token header. If empty, a random 64-char hex string is generated at startup |
| `path_length` | `16` | Length of the randomized admin path prefix (8–32). Longer = more unpredictable |

### TLS Inspector settings (feature: tls-inspection)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable TLS traffic inspection |
| `deep_packet_inspection` | `false` | Enable deep packet analysis of TLS payloads |
| `min_tls_version` | `TLS_1_2` | Minimum allowed TLS version: TLS_1_2, TLS_1_3 |
| `cipher_suites_blocked` | `[]` | List of blocked cipher suite names (e.g., RC4, 3DES) |

### Bot Protection settings (sub-section)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable bot detection and blocking |
| `block_bad_bots` | `true` | Automatically block detected scanners/bots |
| `captcha_threshold` | `5` | Number of challenges before requiring CAPTCHA |
| `challenge_type` | `js_challenge` | Challenge type: js_challenge, captcha, honeypot |

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
| `tls-inspection` | no | TLS config types in `WafConfig` (deep packet inspection, cipher analysis) |
| `geo-ip` | no | GeoIP config types in `WafConfig` (country blocking, IP reputation) |

Drop features with `default-features = false` to minimize the dependency tree. The core engine (~15 deps, regex-only) runs without any optional feature.

## Decision flow

```
Request arrives
    │
    ├─ Allowlist check ─────────── if path not in allowed list → Decision::Blocked(AllowlistDenied) [only when allowlist.enabled=true]
    │
    ├─ Per-endpoint rate limiter ── if exceeded → Decision::RateLimited
    │
    ├─ General rate limiter ──────── if exceeded → Decision::RateLimited
    │
    ├─ Blocklist lookup ──────────── if matched → Decision::Blocked(IpBlocklisted)
    │
    ├─ Body size check ───────────── if oversized → Decision::Blocked(ThreatScoreExceeded)
    │
    ├─ Run all 10 detectors ───────► collect threats with confidence scores
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
| 10 detectors run on every request, including static assets that would never be attacked | Only whitelisted routes hit the detection engine |
| Attackers probe all endpoints looking for loopholes | Most of your surface area is already closed |

With deny-by-default:

- You list only your real API routes (e.g., `/test/toto`, `/api/login`)
- Every other URL returns 403 before any scanning happens
- Whitelisted routes still get all 10 WAF rule detectors active, so SQLi and XSS inside allowed paths are caught
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
| **Path Traversal** | `rules/path_traversal.rs` | Classic `../`, backslash traversal, double encoding, null byte injection | Separate from LFI -- focuses on filename/path poisoning |
| **Bot Detection** | `rules/bot_detection.rs` | Scanner fingerprints (sqlmap, nmap, nikto, burp suite, nuclei, ffuf, gobuster, dirbuster, hydra, masscan, acunetix, zap), empty UA detection, single-char UA, control characters in headers, encoded scanner fingerprints, referer-based scanning | Case-insensitive matching, deduplication across locations, hex-encoded scanner fingerprint support |

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
    engine.rs                    — RuleEngine: instantiates 10 detectors, runs scan pipeline
    parser.rs                    — HttpRequest struct, URL decoding (limited depth),
                                   query param parsing, cookie parsing, searchable_text()
    allowlist_schema.rs          — Zero-trust path validation: rejects traversal, null bytes, encoded attacks, entries over 512 chars
    allowlist_service.rs         — Thread-safe allowlist gatekeeper: prefix matching, auto-whitelist for /admin and /metrics, runtime update support
    scoring.rs                   — ThreatInfo, ThreatCategory, ThreatScore, Action,
                                   BlockingReason, ScoringEngine (weight accumulation)
    rate_limit.rs                — RateLimiter: per-IP sliding window + blocked IP map
    metrics.rs                   — WafMetrics: atomic counters + Prometheus render
    database.rs                  — SQLite CRUD: blocklist, whitelist, audit log (feature-gated)
    admin_auth/
      types.rs                   — AdminCommand, AdminPathConfig, AdminAuthError, AuthResult,
                                   const_time_eq for timing-safe token comparison
      schema.rs                  — AdminCommandValidator, AdminTokenValidation: validates commands
                                   against traversal/null-byte injection, generates deterministic admin
                                   path prefix and auth token from config seed
      service.rs                 — AdminAuthService: thread-safe authentication gatekeeper with
                                   randomized admin prefix (not "/admin"), masked token logging,
                                   AdminCommandExecutor for block/unblock/whitelist/status operations
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
      bot_detection.rs           — Scanner fingerprint detection: sqlmap, nmap, nikto, burp suite,
                                     nuclei, ffuf, gobuster, dirbuster, hydra, masscan, acunetix, zap;
                                     empty UA, single-char UA, control chars, null bytes, encoded
                                     fingerprints, referer scanning, case-insensitive matching

  waf-cli/src/                   ← binary crate — CLI + HTTP server
    main.rs                      — clap CLI parsing, Axum router setup with state-driven
                                   admin API + proxy handlers, upstream forwarding via reqwest,
                                   security header middleware applied to all responses
    middleware/mod.rs            — Middleware module re-export
    middleware/chain.rs           — GargouilleMiddleware: applies security headers to responses

  waf-core/tests/
    admin_auth_tests.rs          — Admin auth: token validation, const-time comparison, path prefix
                                   security, command decoding with traversal/null-byte rejection,
                                   deterministic token generation, error non-leakage
    allowlist_tests.rs           — Allowlist enabled/disabled, path matching, traversal bypass attempts,
                                   encoding bypass, SQLi/XSS still caught on allowed paths, case sensitivity
    integration_tests.rs         — End-to-end tests across all attack vectors, rate limiting,
                                   scoring thresholds, per-endpoint limits, IP validation, HTTP methods,
                                   bot detection integration
  config/default.toml            — Full configuration with defaults for every section
```

## Testing

```bash
# All crates — unit + integration tests
cargo test --all          # 412 tests pass (287 unit + 125 integration)

# Only waf-core library
cargo test -p waf-core    # 412 tests: lib unit tests + admin_auth + allowlist + integration tests

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
| Bot detection | ~37 | Scanner fingerprints (sqlmap, nmap, nikto, burp, nuclei, ffuf, gobuster, dirbuster, hydra, masscan, acunetix, zap), empty UA, single-char UA, control chars, null byte UA, encoded scanners, referer scanning, case-insensitive matching |
| WAF orchestrator (`engine.rs`) | 17 | Clean requests, SQLi/XSS/CLI/PT in body+query, combined attacks, header injection, SSTI/SSRF/LFI/deserialization detection |
| Admin auth | 22 | Token validation (correct/wrong/empty/null-byte), const-time comparison, path prefix generation, command decoding (traversal/rejection), config determinism, error non-leakage |
| Allowlist schema | ~9 | Path validation: leading slash requirement, traversal rejection, query/fragment rejection, null bytes, control chars, length limit, normalization |
| Allowlist service | ~12 | Prefix matching, exact match, auto-whitelist, disabled mode, case sensitivity, runtime update, query string stripping |
| Database | 8 | Schema creation, add/check/remove blocklist, audit log, recent threats, whitelist, duplicate handling |
| Prometheus metrics | 11 | Zero-state, increment counters, render format, reset, high/low scores |
| Integration (all) | 87 | Full pipeline: clean passes, all attack vectors blocked, rate limiting, scoring thresholds, per-endpoint limits, mixed requests, cookies, encoded queries, IP validation, case-insensitive headers, direct-block thresholds, allowlist pass/block, WAF rules on allowed paths, auto-whitelist bypass prevention, bot detection integration |
| Allowlist tests | 16 | Allowlist enabled/disabled, path matching, traversal bypass attempts, encoding bypass, SQLi/XSS still caught on allowed paths, case sensitivity |

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
