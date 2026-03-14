use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    traits::geo::{GeoData, GeoProvider},
};
use worker::Cf;

/// Cloudflare `cf` object implementation of `GeoProvider`.
///
/// Cloudflare populates geo data on every incoming request at no extra cost —
/// no external API token is required unlike IPinfo.io.
///
/// Available fields from `Cf`:
///   - country()     → ISO 3166-1 alpha-2 country code
///   - city()        → city name (Cloudflare Enterprise)
///   - region()      → region/state name (Cloudflare Enterprise)
///   - timezone()    → IANA timezone string (Cloudflare Enterprise)
///   - postal_code() → postal code (Cloudflare Enterprise)
///   - asn()         → ASN number as u32
///   - coordinates() → (latitude, longitude) as (f64, f64)
///
/// Fields not provided by Cloudflare (hostname, org name, abuse contact,
/// privacy flags, domain info) are left as None and can be enriched
/// separately if needed.
pub struct CfGeoProvider {
    pub cf: Cf,
}

impl CfGeoProvider {
    pub fn new(cf: Cf) -> Self {
        Self { cf }
    }
}

#[async_trait(?Send)]
impl GeoProvider for CfGeoProvider {
    async fn lookup(&self, _ip: &str) -> Result<GeoData, BruteError> {
        // Build the location string "lat,lon" if coordinates are available
        let loc = self.cf.coordinates().map(|(lat, lon)| format!("{},{}", lat, lon));

        // Format ASN as "AS{number}" to match IPinfo.io format
        let asn = self.cf.asn().map(|n| format!("AS{}", n));

        Ok(GeoData {
            hostname: None,
            city: self.cf.city().map(|s| s.to_string()),
            region: self.cf.region().map(|s| s.to_string()),
            country: self.cf.country().map(|s| s.to_string()),
            loc,
            org: None,      // not available from cf object
            postal: self.cf.postal_code().map(|s| s.to_string()),
            timezone: Some(self.cf.timezone_name()).filter(|s| !s.is_empty()),
            // ASN — number only, name/domain/route not available from cf
            asn,
            asn_name: None,
            asn_domain: None,
            asn_route: None,
            asn_type: None,
            // Company info not available from cf object
            company_name: None,
            company_domain: None,
            company_type: None,
            // Privacy signals not available from cf object
            // Cloudflare does expose bot score but not VPN/proxy/tor flags directly
            vpn: None,
            proxy: None,
            tor: None,
            relay: None,
            hosting: None,
            service: None,
            // Abuse contact not available from cf object
            abuse_address: None,
            abuse_country: None,
            abuse_email: None,
            abuse_name: None,
            abuse_network: None,
            abuse_phone: None,
            // Domain info not available from cf object
            domain_ip: None,
            domain_total: None,
            domains: None,
        })
    }
}
