use async_trait::async_trait;
use brute_core::{error::BruteError, traits::hibp::HibpProvider};
use sha1::{Digest, Sha1};
use worker::Fetch;

/// Cloudflare Workers implementation of `HibpProvider`.
///
/// Uses `worker::Fetch` instead of reqwest (reqwest is not available in the
/// WASM Workers runtime). SHA1 is computed with the pure-Rust `sha1` crate so
/// no Web Crypto API is needed.
pub struct WorkerHibpChecker;

impl WorkerHibpChecker {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WorkerHibpChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait(?Send)]
impl HibpProvider for WorkerHibpChecker {
    async fn check_password(&self, password: &str) -> Result<bool, BruteError> {
        // Compute SHA1 of the password using pure-Rust sha1 crate.
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash_bytes = hasher.finalize();
        let hex = format!("{:X}", hash_bytes);
        let (prefix, suffix) = (&hex[..5], &hex[5..]);

        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        let mut req = worker::Request::new(&url, worker::Method::Get)
            .map_err(|e| BruteError::Internal(format!("HIBP request build failed: {}", e)))?;

        req.headers_mut()
            .map_err(|e| BruteError::Internal(format!("HIBP headers failed: {}", e)))?
            .set("Add-Padding", "true")
            .map_err(|e| BruteError::Internal(format!("HIBP header set failed: {}", e)))?;

        let mut resp = Fetch::Request(req)
            .send()
            .await
            .map_err(|e| BruteError::Internal(format!("HIBP fetch failed: {}", e)))?;

        if resp.status_code() == 429 {
            return Err(BruteError::Internal("HIBP rate limited".to_string()));
        }

        if resp.status_code() != 200 {
            return Err(BruteError::Internal(format!(
                "HIBP unexpected status: {}",
                resp.status_code()
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
