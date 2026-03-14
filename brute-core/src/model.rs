use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Individual {
    pub id: String,
    pub username: String,
    pub password: String,
    pub ip: String,
    pub protocol: String,
    pub timestamp: i64,
}

impl Individual {
    pub fn new(
        id: String,
        username: String,
        password: String,
        ip: String,
        protocol: String,
        timestamp: i64,
    ) -> Self {
        Self {
            id,
            username,
            password,
            ip,
            protocol,
            timestamp,
        }
    }

    pub fn new_short(username: String, password: String, ip: String, protocol: String) -> Self {
        Self {
            id: String::default(),
            username,
            password,
            ip,
            protocol,
            timestamp: 0,
        }
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ProcessedIndividual {
    pub id: String,
    pub username: String,
    pub password: String,
    pub ip: String,
    pub protocol: String,
    pub hostname: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub timezone: String,
    pub country: Option<String>,
    pub loc: Option<String>,
    pub org: Option<String>,
    pub postal: Option<String>,
    pub asn: Option<String>,
    pub asn_name: Option<String>,
    pub asn_domain: Option<String>,
    pub asn_route: Option<String>,
    pub asn_type: Option<String>,
    pub company_name: Option<String>,
    pub company_domain: Option<String>,
    pub company_type: Option<String>,
    pub vpn: Option<bool>,
    pub proxy: Option<bool>,
    pub tor: Option<bool>,
    pub relay: Option<bool>,
    pub hosting: Option<bool>,
    pub service: Option<String>,
    pub abuse_address: Option<String>,
    pub abuse_country: Option<String>,
    pub abuse_email: Option<String>,
    pub abuse_name: Option<String>,
    pub abuse_network: Option<String>,
    pub abuse_phone: Option<String>,
    pub domain_ip: Option<String>,
    pub domain_total: Option<i64>,
    pub domains: Option<Vec<String>>,
    pub timestamp: i64,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopUsername {
    pub username: String,
    pub amount: i32,
}

impl TopUsername {
    pub fn new(username: String, amount: i32) -> Self {
        TopUsername { username, amount }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopPassword {
    pub password: String,
    pub amount: i32,
    pub is_breached: bool,
}

impl TopPassword {
    pub fn new(password: String, amount: i32) -> Self {
        TopPassword {
            password,
            amount,
            is_breached: false,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopIp {
    pub ip: String,
    pub amount: i32,
}

impl TopIp {
    pub fn new(ip: String, amount: i32) -> Self {
        TopIp { ip, amount }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopProtocol {
    pub protocol: String,
    pub amount: i32,
}

impl TopProtocol {
    pub fn new(protocol: String, amount: i32) -> Self {
        TopProtocol { protocol, amount }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopCountry {
    pub country: String,
    pub amount: i32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopCity {
    pub city: String,
    pub country: String,
    pub amount: i32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopRegion {
    pub region: String,
    pub country: String,
    pub amount: i32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopTimezone {
    pub timezone: String,
    pub amount: i32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopOrg {
    pub org: String,
    pub amount: i32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopPostal {
    pub postal: String,
    pub amount: i32,
}

impl TopPostal {
    pub fn new(postal: String, amount: i32) -> Self {
        TopPostal { postal, amount }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TopLocation {
    pub loc: String,
    pub amount: i32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopUsrPassCombo {
    pub id: String,
    pub username: String,
    pub password: String,
    pub amount: i32,
}

impl TopUsrPassCombo {
    pub fn new(id: String, username: String, password: String, amount: i32) -> Self {
        TopUsrPassCombo {
            id,
            username,
            password,
            amount,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TopHourly {
    pub timestamp: i64,
    pub amount: i32,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TopDaily {
    pub timestamp: i64,
    pub amount: i32,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TopWeekly {
    pub timestamp: i64,
    pub amount: i32,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TopYearly {
    pub timestamp: i64,
    pub amount: i32,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct HeatmapCell {
    pub day_of_week: i32,
    pub hour_of_day: i32,
    pub amount: i64,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct TopSubnet {
    pub subnet: String,
    pub amount: i64,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ProtocolCombo {
    pub username: String,
    pub password: String,
    pub amount: i64,
}

pub struct ProtocolComboRequest {
    pub protocol: String,
    pub limit: usize,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct IpSeen {
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_sessions: i64,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct AttackVelocity {
    pub minute_bucket: i64,
    pub amount: i64,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct IpAbuse {
    pub ip: String,
    pub confidence_score: i32,
    pub total_reports: i32,
    pub checked_at: i64,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RollingStats {
    pub total_attacks: i64,
    pub attacks_last_hour: i32,
    pub top_protocol: Option<String>,
    pub top_country: Option<String>,
}
