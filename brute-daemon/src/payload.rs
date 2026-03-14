use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::Serialize;

// ─── Shared HTTP client ───────────────────────────────────────────────────────

/// Single client instance reused across all requests.
/// reqwest::Client manages a connection pool internally.
static CLIENT: OnceLock<Client> = OnceLock::new();

fn client() -> &'static Client {
    CLIENT.get_or_init(Client::new)
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

/// Maximum attempts from a single IP within the window before we stop posting.
const RATE_LIMIT: u32 = 30;
/// Rolling window duration.
const WINDOW: Duration = Duration::from_secs(60);

static RATE_LIMITER: OnceLock<Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();

fn limiter() -> &'static Mutex<HashMap<String, (u32, Instant)>> {
    RATE_LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns `true` if this IP has exceeded the rate limit and the attempt
/// should NOT be forwarded to the HTTP endpoint.
fn is_rate_limited(ip: &str) -> bool {
    let mut map = limiter().lock().unwrap();
    let now = Instant::now();
    let entry = map.entry(ip.to_string()).or_insert((0, now));

    if now.duration_since(entry.1) >= WINDOW {
        // Window has expired — reset the counter.
        *entry = (1, now);
        false
    } else {
        entry.0 += 1;
        entry.0 > RATE_LIMIT
    }
}

// ─── Startup config ───────────────────────────────────────────────────────────

/// Cached at startup — see `validate_config()` in main.rs.
static ENDPOINT: OnceLock<String> = OnceLock::new();
static BEARER_TOKEN: OnceLock<String> = OnceLock::new();

/// Validate and cache required env vars. Call once at startup before any
/// protocol server is started. Panics with a clear message if either var is
/// missing or empty.
pub fn validate_config() {
    let url = std::env::var("ADD_ATTACK_ENDPOINT")
        .expect("ADD_ATTACK_ENDPOINT must be set (e.g. http://localhost:7000/brute/attack/add)");
    let token = std::env::var("BEARER_TOKEN")
        .expect("BEARER_TOKEN must be set and must match the brute-http BEARER_TOKEN");

    if url.is_empty() {
        panic!("ADD_ATTACK_ENDPOINT is set but empty");
    }
    if token.is_empty() {
        panic!("BEARER_TOKEN is set but empty");
    }

    ENDPOINT.set(url).ok();
    BEARER_TOKEN.set(token).ok();
}

// ─── Payload ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Payload<'a> {
    username: &'a str,
    password: &'a str,
    ip_address: &'a str,
    protocol: &'a str,
}

/// Post an attack attempt to the brute-http endpoint.
///
/// Silently skips if the IP is rate-limited. Logs a warning if the HTTP
/// request itself fails so that credential loss is never completely silent.
pub async fn post(username: &str, password: &str, ip_address: &str, protocol: &str) {
    if is_rate_limited(ip_address) {
        log::debug!("Rate limited IP: {} ({})", ip_address, protocol);
        return;
    }

    let url = ENDPOINT.get().expect("validate_config() was not called");
    let token = BEARER_TOKEN.get().expect("validate_config() was not called");

    let payload = Payload { username, password, ip_address, protocol };

    if let Err(e) = client()
        .post(url)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
    {
        log::warn!(
            "Failed to post attack to {}: {} | ip={} protocol={}",
            url, e, ip_address, protocol
        );
    }
}
