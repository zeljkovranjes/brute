use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    traits::geo::{GeoData, GeoProvider},
};
use log::warn;
use reqwest::Client;
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

/// IPinfo.io implementation of `GeoProvider` using raw HTTP.
///
/// Uses reqwest directly so rate-limit response headers are accessible.
/// When a 429 is received the `X-RateLimit-Reset` header (Unix timestamp)
/// is read and the task sleeps until that moment before retrying. If the
/// header is absent a 60-second fallback is used.
pub struct IpInfoProvider {
    pub token: String,
    pub client: Client,
    /// Shared across all callers — set to the reset timestamp on 429, cleared after waking.
    pub rate_limited_until: Arc<Mutex<Option<SystemTime>>>,
}

impl IpInfoProvider {
    pub fn new(token: String) -> Self {
        Self {
            token,
            client: Client::new(),
            rate_limited_until: Arc::new(Mutex::new(None)),
        }
    }
}

// ── IPinfo JSON shapes ────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct IpInfoResponse {
    hostname: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    loc: Option<String>,
    org: Option<String>,
    postal: Option<String>,
    timezone: Option<String>,
    asn: Option<IpInfoAsn>,
    company: Option<IpInfoCompany>,
    privacy: Option<IpInfoPrivacy>,
    abuse: Option<IpInfoAbuse>,
    domains: Option<IpInfoDomains>,
}

#[derive(Deserialize)]
struct IpInfoAsn {
    asn: Option<String>,
    name: Option<String>,
    domain: Option<String>,
    route: Option<String>,
    #[serde(rename = "type")]
    asn_type: Option<String>,
}

#[derive(Deserialize)]
struct IpInfoCompany {
    name: Option<String>,
    domain: Option<String>,
    #[serde(rename = "type")]
    company_type: Option<String>,
}

#[derive(Deserialize)]
struct IpInfoPrivacy {
    vpn: Option<bool>,
    proxy: Option<bool>,
    tor: Option<bool>,
    relay: Option<bool>,
    hosting: Option<bool>,
    service: Option<String>,
}

#[derive(Deserialize)]
struct IpInfoAbuse {
    address: Option<String>,
    country: Option<String>,
    email: Option<String>,
    name: Option<String>,
    network: Option<String>,
    phone: Option<String>,
}

#[derive(Deserialize)]
struct IpInfoDomains {
    ip: Option<String>,
    total: Option<i64>,
    domains: Option<Vec<String>>,
}

// ── GeoProvider impl ──────────────────────────────────────────────────────────

#[async_trait]
impl GeoProvider for IpInfoProvider {
    async fn lookup(&self, ip: &str) -> Result<GeoData, BruteError> {
        // If another task already determined we are rate-limited, wait it out
        // before even sending a request.
        {
            let rl = self.rate_limited_until.lock().await;
            if let Some(reset_at) = *rl {
                if let Ok(remaining) = reset_at.duration_since(SystemTime::now()) {
                    drop(rl);
                    warn!(
                        "IPinfo rate limited — waiting {:.1}s before lookup",
                        remaining.as_secs_f64()
                    );
                    tokio::time::sleep(remaining).await;
                }
            }
        }

        let url = format!("https://ipinfo.io/{}?token={}", ip, self.token);

        loop {
            let resp = self
                .client
                .get(&url)
                .send()
                .await
                .map_err(|e| BruteError::Geo(format!("IPinfo request failed: {}", e)))?;

            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let sleep_for = rate_limit_wait(
                    resp.headers().get("X-RateLimit-Reset"),
                    60,
                );

                let reset_at = SystemTime::now() + sleep_for;
                *self.rate_limited_until.lock().await = Some(reset_at);

                warn!(
                    "IPinfo rate limit hit — sleeping {:.1}s until reset",
                    sleep_for.as_secs_f64()
                );
                tokio::time::sleep(sleep_for).await;
                *self.rate_limited_until.lock().await = None;
                continue;
            }

            let info: IpInfoResponse = resp
                .json()
                .await
                .map_err(|e| BruteError::Geo(format!("IPinfo parse failed for {}: {}", ip, e)))?;

            return Ok(GeoData {
                hostname: info.hostname,
                city: info.city,
                region: info.region,
                country: info.country,
                loc: info.loc,
                org: info.org,
                postal: info.postal,
                timezone: info.timezone,
                asn: info.asn.as_ref().and_then(|a| a.asn.clone()),
                asn_name: info.asn.as_ref().and_then(|a| a.name.clone()),
                asn_domain: info.asn.as_ref().and_then(|a| a.domain.clone()),
                asn_route: info.asn.as_ref().and_then(|a| a.route.clone()),
                asn_type: info.asn.as_ref().and_then(|a| a.asn_type.clone()),
                company_name: info.company.as_ref().and_then(|c| c.name.clone()),
                company_domain: info.company.as_ref().and_then(|c| c.domain.clone()),
                company_type: info.company.as_ref().and_then(|c| c.company_type.clone()),
                vpn: info.privacy.as_ref().and_then(|p| p.vpn),
                proxy: info.privacy.as_ref().and_then(|p| p.proxy),
                tor: info.privacy.as_ref().and_then(|p| p.tor),
                relay: info.privacy.as_ref().and_then(|p| p.relay),
                hosting: info.privacy.as_ref().and_then(|p| p.hosting),
                service: info
                    .privacy
                    .as_ref()
                    .and_then(|p| p.service.clone())
                    .filter(|s| !s.is_empty()),
                abuse_address: info.abuse.as_ref().and_then(|a| a.address.clone()),
                abuse_country: info.abuse.as_ref().and_then(|a| a.country.clone()),
                abuse_email: info.abuse.as_ref().and_then(|a| a.email.clone()),
                abuse_name: info.abuse.as_ref().and_then(|a| a.name.clone()),
                abuse_network: info.abuse.as_ref().and_then(|a| a.network.clone()),
                abuse_phone: info.abuse.as_ref().and_then(|a| a.phone.clone()),
                domain_ip: info.domains.as_ref().and_then(|d| d.ip.clone()),
                domain_total: info.domains.as_ref().and_then(|d| d.total),
                domains: info.domains.as_ref().and_then(|d| d.domains.clone()),
            });
        }
    }
}

/// Compute how long to sleep from a rate-limit reset header.
///
/// `header` is expected to be a Unix timestamp (seconds). If absent or
/// unparseable, `fallback_secs` is used instead.
fn rate_limit_wait(
    header: Option<&reqwest::header::HeaderValue>,
    fallback_secs: u64,
) -> Duration {
    header
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|ts| {
            let reset_at = UNIX_EPOCH + Duration::from_secs(ts);
            reset_at.duration_since(SystemTime::now()).ok()
        })
        .unwrap_or(Duration::from_secs(fallback_secs))
}
