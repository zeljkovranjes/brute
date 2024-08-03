use actix::Message;
use derive_getters::Getters;

use serde::{Deserialize, Serialize};

use crate::{error::BruteResponeError, system::RequestWithLimit};

#[derive(Default, Clone, Debug, sqlx::FromRow,Getters)]
pub struct Individual {
    pub id: String,
    username: String,
    password: String,
    ip: String,
    pub protocol: String,
    pub timestamp: i64,
}

impl Individual {
    pub fn new(id: String, username: String, password: String, ip: String, protocol: String, timestamp: i64) -> Self {
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

// allow as a message in actix actor.
impl Message for Individual {
    type Result = ();
}

#[derive(Default, Clone, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct ProcessedIndividual {
    pub id: String,
    username: String,
    password: String,
    ip: String,
    protocol: String,
    hostname: Option<String>,
    city: Option<String>,
    region: Option<String>,
    timezone: String,
    country: Option<String>,
    loc: Option<String>,
    org: Option<String>,
    pub postal: Option<String>,
    asn: Option<String>,
    asn_name: Option<String>,
    asn_domain: Option<String>,
    asn_route: Option<String>,
    asn_type: Option<String>,
    company_name: Option<String>,
    company_domain: Option<String>,
    company_type: Option<String>,
    vpn: Option<bool>,
    proxy: Option<bool>,
    tor: Option<bool>,
    relay: Option<bool>,
    hosting: Option<bool>,
    service: Option<String>,
    abuse_address: Option<String>,
    abuse_country: Option<String>,
    abuse_email: Option<String>,
    abuse_name: Option<String>,
    abuse_network: Option<String>,
    abuse_phone: Option<String>,
    domain_ip: Option<String>,
    domain_total: Option<i64>,
    domains: Option<Vec<String>>,
    pub timestamp: i64,
}

impl Message for RequestWithLimit<ProcessedIndividual> {
    type Result = Result<Vec<ProcessedIndividual>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopUsername {
    username: String,
    amount: i32,
}

impl TopUsername {
    pub fn new(username: String, amount: i32) -> Self {
        TopUsername { username, amount }
    }
}

impl Message for RequestWithLimit<TopUsername> {
    type Result = Result<Vec<TopUsername>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopPassword {
    password: String,
    amount: i32,
}

impl TopPassword {
    pub fn new(password: String, amount: i32) -> Self {
        TopPassword { password, amount }
    }
}

impl Message for RequestWithLimit<TopPassword> {
    type Result = Result<Vec<TopPassword>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopIp {
    ip: String,
    amount: i32,
}

impl Message for RequestWithLimit<TopIp> {
    type Result = Result<Vec<TopIp>, BruteResponeError>;
}

impl TopIp {
    pub fn new(ip: String, amount: i32) -> Self {
        TopIp { ip, amount }
    }
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopProtocol {
    protocol: String,
    amount: i32,
}

impl TopProtocol {
    pub fn new(protocol: String, amount: i32) -> Self {
        TopProtocol { protocol, amount }
    }
}

impl Message for TopProtocol {
    type Result = ();
}

impl Message for RequestWithLimit<TopProtocol> {
    type Result = Result<Vec<TopProtocol>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopCountry {
    country: String,
    amount: i32,
}

impl Message for RequestWithLimit<TopCountry> {
    type Result = Result<Vec<TopCountry>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopCity {
    city: String,
    country: String,
    amount: i32,
}

impl Message for RequestWithLimit<TopCity> {
    type Result = Result<Vec<TopCity>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopRegion {
    region: String,
    country: String,
    amount: i32,
}

impl Message for RequestWithLimit<TopRegion> {
    type Result = Result<Vec<TopRegion>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopTimezone {
    timezone: String,
    amount: i32,
}

impl Message for RequestWithLimit<TopTimezone> {
    type Result = Result<Vec<TopTimezone>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopOrg {
    org: String,
    amount: i32,
}

impl Message for RequestWithLimit<TopOrg> {
    type Result = Result<Vec<TopOrg>, BruteResponeError>;
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopPostal {
    postal: String,
    amount: i32,
}

impl Message for RequestWithLimit<TopPostal> {
    type Result = Result<Vec<TopPostal>, BruteResponeError>;
}

impl TopPostal {
    pub fn new(postal: String, amount: i32) -> Self {
        TopPostal {
            postal,
            amount
        }
    }
}

#[derive(Default, Debug, sqlx::FromRow, Getters, Serialize, Deserialize)]
pub struct TopUsrPassCombo {
    id: String,
    username: String,
    password: String,
    amount: i32,
}

impl TopUsrPassCombo {
    pub fn new(id: String, username: String, password: String, amount: i32) -> Self {
        TopUsrPassCombo {
            id,
            username,
            password,
            amount
        }
    }
}

impl Message for RequestWithLimit<TopUsrPassCombo> {
    type Result = Result<Vec<TopUsrPassCombo>, BruteResponeError>;
}

#[derive(Debug, Clone, sqlx::FromRow, Getters)]
pub struct TopHourly {
    pub timestamp: i64,
    pub amount: i32,
}

#[derive(Debug, Clone, sqlx::FromRow, Getters)]
pub struct TopDaily {
    pub timestamp: i64,
    pub amount: i32,
}

#[derive(Debug, Clone, sqlx::FromRow, Getters)]
pub struct TopWeekly {
    pub timestamp: i64,
    pub amount: i32,
}

#[derive(Debug, Clone, sqlx::FromRow, Getters)]
pub struct TopYearly {
    pub timestamp: i64,
    pub amount: i32,
}
