use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    traits::geo::{GeoData, GeoProvider},
};
use serde::Deserialize;

/// IPinfo.io implementation of `GeoProvider` for Cloudflare Workers.
///
/// Uses `worker::Fetch` (the JS-backed HTTP client available in WASM Workers).
/// No caching or rate-limit sleeping — Workers are stateless per-request.
/// On any error the caller should fall back to `CfGeoProvider`.
///
/// The `base_url` field allows pointing at a self-hosted round-robin proxy
/// (e.g. https://github.com/zeljkovranjes/ipinfo-round-robin-api) instead of
/// the real `https://ipinfo.io` endpoint.  The token is always forwarded as a
/// query param so it works with both the real API and a pass-through proxy.
pub struct IpInfoProvider {
    pub base_url: String,
    pub token: String,
}

impl IpInfoProvider {
    /// `base_url` — either `"https://ipinfo.io"` or your proxy root URL.
    /// `token`    — IPinfo API token (passed as `?token=…`).
    pub fn new(token: String, base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
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

#[async_trait(?Send)]
impl GeoProvider for IpInfoProvider {
    async fn lookup(&self, ip: &str) -> Result<GeoData, BruteError> {
        let url = if self.token.is_empty() {
            format!("{}/{}", self.base_url, ip)
        } else {
            format!("{}/{}?token={}", self.base_url, ip, self.token)
        };

        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Get);
        let mut headers = worker::Headers::new();
        headers.set("Accept", "application/json").ok();
        init.with_headers(headers);

        let request = worker::Request::new_with_init(&url, &init)
            .map_err(|e| BruteError::Geo(format!("IPinfo request build failed: {}", e)))?;

        let mut resp = worker::Fetch::Request(request)
            .send()
            .await
            .map_err(|e| BruteError::Geo(format!("IPinfo fetch failed: {}", e)))?;

        if resp.status_code() != 200 {
            return Err(BruteError::Geo(format!(
                "IPinfo returned status {}",
                resp.status_code()
            )));
        }

        let info: IpInfoResponse = resp
            .json()
            .await
            .map_err(|e| BruteError::Geo(format!("IPinfo parse failed for {}: {}", ip, e)))?;

        Ok(GeoData {
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
            domains: info.domains.and_then(|d| d.domains),
        })
    }
}
