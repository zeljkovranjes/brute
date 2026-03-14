use async_trait::async_trait;
use crate::error::BruteError;

#[async_trait]
pub trait HibpProvider: Send + Sync {
    /// Check if a password appears in known breach data.
    /// Returns Ok(true) if breached, Ok(false) if clean, Ok(false) if unconfigured.
    async fn check_password(&self, password: &str) -> Result<bool, BruteError>;
}
