use async_trait::async_trait;
use brute_core::{error::BruteError, traits::hibp::HibpProvider};
use reqwest::Client;
use sha1::{Digest, Sha1};

/// HTTP implementation of `HibpProvider` using the Have I Been Pwned
/// k-anonymity range API.
///
/// Computes the SHA1 of the password, splits it into a 5-character prefix and
/// the remaining suffix, and queries `https://api.pwnedpasswords.com/range/{prefix}`.
/// The suffix is then matched against the returned list — the full password
/// never leaves the process.
pub struct HibpChecker {
    client: Client,
}

impl HibpChecker {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl Default for HibpChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HibpProvider for HibpChecker {
    async fn check_password(&self, password: &str) -> Result<bool, BruteError> {
        // Compute SHA1 of the password.
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash_bytes = hasher.finalize();
        let hex = format!("{:X}", hash_bytes);
        let (prefix, suffix) = (&hex[..5], &hex[5..]);

        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        let resp = self
            .client
            .get(&url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| BruteError::Internal(format!("HIBP request failed: {}", e)))?;

        if resp.status() == 429 {
            return Err(BruteError::Internal("HIBP rate limited".to_string()));
        }

        if !resp.status().is_success() {
            return Err(BruteError::Internal(format!(
                "HIBP unexpected status: {}",
                resp.status()
            )));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| BruteError::Internal(format!("HIBP response read failed: {}", e)))?;

        let breached = body.lines().any(|line| {
            line.split(':')
                .next()
                .map(|h| h.eq_ignore_ascii_case(suffix))
                .unwrap_or(false)
        });

        Ok(breached)
    }
}
