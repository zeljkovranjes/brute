use std::net::IpAddr;

use actix_web::HttpResponse;
use ipnetwork::Ipv4Network;
use regex::Regex;

use crate::{error::BruteResponeError, model::Individual};

pub trait Validate {
    fn validate(&mut self) -> anyhow::Result<(), BruteResponeError>;
}

impl Validate for Individual {
    fn validate(&mut self) -> anyhow::Result<(), BruteResponeError> {
        if self.username().is_empty() {
            return Err(BruteResponeError::BadRequest(
                "input validation error: username is empty.".to_string(),
            ));
        }

        if self.username().len() > 255 {
            return Err(BruteResponeError::BadRequest(
                "input validation error: username is too long max is 255 characters.".to_string(),
            ));
        }

        if self.password().is_empty() {
            return Err(BruteResponeError::BadRequest(
                "input validation error: password is empty.".to_string(),
            ));
        }

        if self.password().len() > 255 {
            return Err(BruteResponeError::BadRequest(
                "input validation error: password is too long max is 255 characters.".to_string(),
            ));
        }

        if self.ip().is_empty() {
            return Err(BruteResponeError::BadRequest(
                "input validation error: ip is empty.".to_string(),
            ));
        }

        if self.protocol().is_empty() {
            return Err(BruteResponeError::BadRequest(
                "input validation error: protocol is empty.".to_string(),
            ));
        }

        if self.protocol().len() > 50 {
            return Err(BruteResponeError::BadRequest(
                "input validation error: protocol is too long max is 50 characters.".to_string(),
            ));
        }

        if self.protocol().eq_ignore_ascii_case("sshd") {
            self.protocol = "SSH".to_string();
        }

        validate_ip(&self.ip())?;
        is_private_ip(self.ip().parse::<IpAddr>().unwrap())?;
        Ok(())
    }
}

pub fn is_private_ip(ip: IpAddr) -> Result<(), BruteResponeError> {
    let private_networks = [
        Ipv4Network::new("10.0.0.0".parse().unwrap(), 8).unwrap(),
        Ipv4Network::new("172.16.0.0".parse().unwrap(), 12).unwrap(),
        Ipv4Network::new("192.168.0.0".parse().unwrap(), 16).unwrap(),
        Ipv4Network::new("127.0.0.0".parse().unwrap(), 8).unwrap(), // Loopback network
    ];

    if let IpAddr::V4(ipv4) = ip {
        if private_networks
            .iter()
            .any(|network| network.contains(ipv4))
        {
            Err(BruteResponeError::ValidationError("input validation error: ip_address is from a private network.".to_string()))
        } else {
            Ok(())
        }
    } else {
        unreachable!()
    }
}

pub fn validate_ip(ip_address: &str) -> Result<(), BruteResponeError> {
    let re = Regex::new(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$").unwrap();
    if !re.is_match(ip_address) {
        //log::info!("received a bad request ip_address is not formatted correctly.");
        Err(BruteResponeError::ValidationError("input validation error: ip_address is not formatted correctly.".to_string()))
    } else {
        Ok(())
    }
}