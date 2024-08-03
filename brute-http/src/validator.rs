use regex::Regex;

use crate::{error::BruteResponeError, model::Individual};

pub trait Validate {
    fn validate(&mut self) -> anyhow::Result<(), BruteResponeError>;
}

impl Validate for Individual {
    fn validate(&mut self) -> anyhow::Result<(), BruteResponeError> {
        if self.username().is_empty() {
            return Err(BruteResponeError::BadRequest("input validation error: username is empty.".to_string()))
        }

        if self.username().len() > 255 {
            return Err(BruteResponeError::BadRequest("input validation error: username is too long max is 255 characters.".to_string()))
        }

        if self.password().is_empty() {
            return Err(BruteResponeError::BadRequest("input validation error: password is empty.".to_string()))
        }

        if self.password().len() > 255 {
            return Err(BruteResponeError::BadRequest("input validation error: password is too long max is 255 characters.".to_string()))
        }

        if self.ip().is_empty() {
            return Err(BruteResponeError::BadRequest("input validation error: ip is empty.".to_string()))
        }

        if self.protocol().is_empty() {
            return Err(BruteResponeError::BadRequest("input validation error: protocol is empty.".to_string()))
        }

        if self.protocol().len() > 50 {
            return Err(BruteResponeError::BadRequest("input validation error: protocol is too long max is 50 characters.".to_string()))
        }

        if self.protocol().eq_ignore_ascii_case("sshd") {
            self.protocol = "SSH".to_string();
        }

        let regex_ip = Regex::new(r#"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"#).unwrap();
        if !regex_ip.is_match(&self.ip()) {
            return Err(BruteResponeError::BadRequest("input validation error: ip_address is not formatted correctly.".to_string()))
        }
        Ok(())
    }
}