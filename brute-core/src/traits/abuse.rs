use async_trait::async_trait;

use crate::error::BruteError;

/// Data returned from an AbuseIPDB check.
#[derive(Debug, Clone, Default)]
pub struct AbuseData {
    pub ip: String,
    pub confidence_score: i32,
    pub total_reports: i32,
    pub checked_at: i64,
}

/// Trait for IP abuse reputation providers.
///
/// In brute-http this calls the AbuseIPDB v2 API with a 24-hour cache in PostgreSQL.
/// In brute-worker this calls the AbuseIPDB v2 API with a 24-hour cache in D1.
/// The key is read from the `ABUSEIPDB_KEY` environment variable; when absent the
/// check is silently skipped.
#[cfg_attr(feature = "wasm", async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait)]
pub trait AbuseProvider: Send + Sync {
    /// Check the abuse reputation of an IP address.
    ///
    /// Implementations are expected to cache results for 24 hours and return
    /// `Ok(None)` when the API key is not configured or the IP was checked
    /// recently enough.
    async fn check(&self, ip: &str) -> Result<Option<AbuseData>, BruteError>;
}
