use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    traits::geo::{GeoData, GeoProvider},
};
use ipinfo::{IpInfo, IpInfoConfig};
use std::sync::Arc;
use tokio::sync::Mutex;

/// IPinfo.io implementation of `GeoProvider`.
///
/// Makes an HTTP call to the IPinfo.io API for each unique IP lookup.
pub struct IpInfoProvider {
    pub client: Arc<Mutex<IpInfo>>,
}

impl IpInfoProvider {
    pub fn new(token: String) -> Result<Self, BruteError> {
        let config = IpInfoConfig {
            token: Some(token),
            ..Default::default()
        };
        let client = IpInfo::new(config)
            .map_err(|e| BruteError::Geo(format!("Failed to create IpInfo client: {}", e)))?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    pub fn from_client(client: IpInfo) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
        }
    }
}

#[async_trait]
impl GeoProvider for IpInfoProvider {
    async fn lookup(&self, ip: &str) -> Result<GeoData, BruteError> {
        let mut client = self.client.lock().await;
        let info = client
            .lookup(ip)
            .await
            .map_err(|e| BruteError::Geo(format!("IPinfo lookup failed for {}: {}", ip, e)))?;

        let privacy = info.privacy.as_ref();
        let asn = info.asn.as_ref();
        let company = info.company.as_ref();
        let abuse = info.abuse.as_ref();
        let domains = info.domains.as_ref();

        Ok(GeoData {
            hostname: info.hostname.clone(),
            city: Some(info.city.clone()),
            region: Some(info.region.clone()),
            country: Some(info.country.clone()),
            loc: Some(info.loc.clone()),
            org: Some(info.org.clone()),
            postal: info.postal.clone(),
            timezone: info.timezone.clone(),
            // ASN fields
            asn: asn.map(|a| a.asn.clone()),
            asn_name: asn.map(|a| a.name.clone()),
            asn_domain: asn.map(|a| a.domain.clone()),
            asn_route: asn.map(|a| a.route.clone()),
            asn_type: asn.map(|a| a.asn_type.clone()),
            // Company fields
            company_name: company.map(|c| c.name.clone()),
            company_domain: company.map(|c| c.domain.clone()),
            company_type: company.map(|c| c.company_type.clone()),
            // Privacy flags
            vpn: privacy.map(|p| p.vpn),
            proxy: privacy.map(|p| p.proxy),
            tor: privacy.map(|p| p.tor),
            relay: privacy.map(|p| p.relay),
            hosting: privacy.map(|p| p.hosting),
            service: privacy.and_then(|p| {
                if p.service.is_empty() {
                    None
                } else {
                    Some(p.service.clone())
                }
            }),
            // Abuse fields
            abuse_address: abuse.map(|a| a.address.clone()),
            abuse_country: abuse.map(|a| a.country.clone()),
            abuse_email: abuse.map(|a| a.email.clone()),
            abuse_name: abuse.map(|a| a.name.clone()),
            abuse_network: abuse.map(|a| a.network.clone()),
            abuse_phone: abuse.map(|a| a.phone.clone()),
            // Domain fields
            domain_ip: domains.map(|d| d.ip.clone()),
            domain_total: domains.map(|d| d.total as i64),
            domains: domains.map(|d| d.domains.clone()),
        })
    }
}
