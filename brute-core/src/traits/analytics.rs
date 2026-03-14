use async_trait::async_trait;

use crate::error::BruteError;
use crate::model::{Individual, ProcessedIndividual};

/// Trait for recording attack analytics events.
///
/// In brute-http this updates the top_* aggregation tables in PostgreSQL.
/// In brute-worker this writes data points to Cloudflare Analytics Engine.
#[async_trait]
pub trait BruteAnalytics: Send + Sync {
    /// Record a raw attack event from an individual attempt.
    async fn record_attack_event(
        &self,
        individual: &Individual,
        processed: &ProcessedIndividual,
    ) -> Result<(), BruteError>;

    /// Record a protocol-only increment event (used by /brute/protocol/increment).
    async fn record_protocol_event(
        &self,
        protocol: &str,
        amount: i32,
    ) -> Result<(), BruteError>;
}
