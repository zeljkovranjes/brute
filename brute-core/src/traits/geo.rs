use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::BruteError;

/// Geo-location data returned by a GeoProvider.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GeoData {
    pub hostname: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub loc: Option<String>,
    pub org: Option<String>,
    pub postal: Option<String>,
    pub timezone: Option<String>,
    // ASN
    pub asn: Option<String>,
    pub asn_name: Option<String>,
    pub asn_domain: Option<String>,
    pub asn_route: Option<String>,
    pub asn_type: Option<String>,
    // Company
    pub company_name: Option<String>,
    pub company_domain: Option<String>,
    pub company_type: Option<String>,
    // Privacy
    pub vpn: Option<bool>,
    pub proxy: Option<bool>,
    pub tor: Option<bool>,
    pub relay: Option<bool>,
    pub hosting: Option<bool>,
    pub service: Option<String>,
    // Abuse
    pub abuse_address: Option<String>,
    pub abuse_country: Option<String>,
    pub abuse_email: Option<String>,
    pub abuse_name: Option<String>,
    pub abuse_network: Option<String>,
    pub abuse_phone: Option<String>,
    // Domains
    pub domain_ip: Option<String>,
    pub domain_total: Option<i64>,
    pub domains: Option<Vec<String>>,
}

/// Trait for IP geo-location providers.
///
/// In brute-http this calls the IPinfo.io HTTP API.
/// In brute-worker this reads from the Cloudflare `cf` request object (free, no token needed).
#[async_trait]
pub trait GeoProvider: Send + Sync {
    async fn lookup(&self, ip: &str) -> Result<GeoData, BruteError>;
}
