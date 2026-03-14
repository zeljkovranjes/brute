use std::net::IpAddr;

use ipnetwork::{Ipv4Network, Ipv6Network};
use regex::Regex;

use crate::error::BruteError;
use crate::model::Individual;

pub trait Validate {
    fn validate(&mut self) -> Result<(), BruteError>;
}

impl Validate for Individual {
    fn validate(&mut self) -> Result<(), BruteError> {
        if self.username.is_empty() {
            return Err(BruteError::Validation(
                "input validation error: username is empty.".to_string(),
            ));
        }

        if self.username.len() > 255 {
            return Err(BruteError::Validation(
                "input validation error: username is too long max is 255 characters.".to_string(),
            ));
        }

        if self.password.is_empty() {
            // allow empty passwords.
            self.password = String::default();
        }

        if self.password.len() > 255 {
            return Err(BruteError::Validation(
                "input validation error: password is too long max is 255 characters.".to_string(),
            ));
        }

        if self.ip.is_empty() {
            return Err(BruteError::Validation(
                "input validation error: ip is empty.".to_string(),
            ));
        }

        if self.protocol.is_empty() {
            return Err(BruteError::Validation(
                "input validation error: protocol is empty.".to_string(),
            ));
        }

        if self.protocol.len() > 50 {
            return Err(BruteError::Validation(
                "input validation error: protocol is too long max is 50 characters.".to_string(),
            ));
        }

        if self.protocol.eq_ignore_ascii_case("sshd") {
            self.protocol = "SSH".to_string();
        }

        validate_and_check_ip(&self.ip)?;
        Ok(())
    }
}

pub fn validate_and_check_ip(ip_str: &str) -> Result<(), BruteError> {
    let ip: IpAddr = ip_str.parse().map_err(|_| {
        BruteError::Validation("Input validation error: Invalid IP address format.".to_string())
    })?;

    validate_ip_format(ip_str)?;
    is_private_ip(ip)?;

    Ok(())
}

fn validate_ip_format(ip_address: &str) -> Result<(), BruteError> {
    let ipv4_re = Regex::new(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$").unwrap();
    let ipv6_re = Regex::new(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))").unwrap();

    if !ipv4_re.is_match(ip_address) && !ipv6_re.is_match(ip_address) {
        Err(BruteError::Validation(
            "Input validation error: IP address is not formatted correctly.".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn is_private_ip(ip: IpAddr) -> Result<(), BruteError> {
    let ipv4_networks = [
        Ipv4Network::new("10.0.0.0".parse().unwrap(), 8).unwrap(),
        Ipv4Network::new("172.16.0.0".parse().unwrap(), 12).unwrap(),
        Ipv4Network::new("192.168.0.0".parse().unwrap(), 16).unwrap(),
        Ipv4Network::new("127.0.0.0".parse().unwrap(), 8).unwrap(),
    ];

    let ipv6_networks = [
        Ipv6Network::new("fc00::".parse().unwrap(), 7).unwrap(),
        Ipv6Network::new("fe80::".parse().unwrap(), 10).unwrap(),
    ];

    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4_networks.iter().any(|network| network.contains(ipv4)) {
                Err(BruteError::Validation(
                    "Input validation error: IPv4 address is from a private network.".to_string(),
                ))
            } else {
                Ok(())
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6_networks.iter().any(|network| network.contains(ipv6)) {
                Err(BruteError::Validation(
                    "Input validation error: IPv6 address is from a private network.".to_string(),
                ))
            } else {
                Ok(())
            }
        }
    }
}
