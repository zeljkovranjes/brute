use std::collections::HashMap;
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::Serialize;

// ─── Rate limiter ────────────────────────────────────────────────────────────

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
        // Window has expired — reset the counter
        *entry = (1, now);
        false
    } else {
        entry.0 += 1;
        entry.0 > RATE_LIMIT
    }
}

// ─── Payload ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Payload {
    username: String,
    password: String,
    ip_address: String,
    protocol: String,
}

pub struct PayloadConfig {
    url: String,
    bearer_token: String,
}

impl Payload {
    pub fn new(
        username: String,
        password: String,
        ip_address: String,
        protocol: String,
        url: String,
        bearer_token: String,
    ) -> anyhow::Result<(Payload, PayloadConfig)> {
        let payload = Payload {
            username,
            password,
            ip_address,
            protocol,
        };
        let config = PayloadConfig {
            url: String::from(url),
            bearer_token: String::from(bearer_token),
        };
        Ok((payload, config))
    }

    pub async fn post(username: &str, password: &str, ip_address: &str, protocol: &str) -> anyhow::Result<()> {
        if is_rate_limited(ip_address) {
            log::debug!("Rate limited IP: {} ({})", ip_address, protocol);
            return Ok(());
        }

        let url = env::var("ADD_ATTACK_ENDPOINT")?;
        let bearer_token = env::var("BEARER_TOKEN")?;
        let payload = Self::new(
            String::from(username),
            String::from(password),
            String::from(ip_address),
            String::from(protocol),
            url,
            bearer_token,
        )?;
        Self::create_post(payload.0, payload.1).await?;
        Ok(())
    }

    async fn create_post(payload: Payload, config: PayloadConfig) -> anyhow::Result<()> {
        let client = Client::new();
        client
            .post(&config.url)
            .bearer_auth(&config.bearer_token)
            .json(&payload)
            .send()
            .await?;
        Ok(())
    }
}
