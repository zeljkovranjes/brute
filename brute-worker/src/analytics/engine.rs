use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    model::{Individual, ProcessedIndividual},
    traits::analytics::BruteAnalytics,
};
use worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset};

/// Cloudflare Analytics Engine implementation of `BruteAnalytics`.
///
/// Instead of mutating aggregation tables, this writes structured data points
/// to Analytics Engine. Queries are performed via the Analytics Engine SQL API.
///
/// Data point layout for attack events:
///   blob1  = username
///   blob2  = password
///   blob3  = country (or empty string)
///   blob4  = city (or empty string)
///   blob5  = protocol
///   blob6  = ip
///   blob7  = org (or empty string)
///   double1 = 1.0 (event count)
pub struct AnalyticsEngine {
    pub dataset: AnalyticsEngineDataset,
}

impl AnalyticsEngine {
    pub fn new(dataset: AnalyticsEngineDataset) -> Self {
        Self { dataset }
    }
}

#[async_trait(?Send)]
impl BruteAnalytics for AnalyticsEngine {
    async fn record_attack_event(
        &self,
        individual: &Individual,
        processed: &ProcessedIndividual,
    ) -> Result<(), BruteError> {
        AnalyticsEngineDataPointBuilder::new()
            .add_blob(individual.username.clone())
            .add_blob(individual.password.clone())
            .add_blob(processed.country.clone().unwrap_or_default())
            .add_blob(processed.city.clone().unwrap_or_default())
            .add_blob(individual.protocol.clone())
            .add_blob(individual.ip.clone())
            .add_blob(processed.org.clone().unwrap_or_default())
            .add_double(1.0)
            .write_to(&self.dataset)
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        Ok(())
    }

    async fn record_protocol_event(
        &self,
        protocol: &str,
        amount: i32,
    ) -> Result<(), BruteError> {
        // blob1 = "_protocol_increment" sentinel to distinguish from attack events
        // blob2 = protocol name
        // double1 = amount
        AnalyticsEngineDataPointBuilder::new()
            .add_blob("_protocol_increment".to_string())
            .add_blob(protocol.to_string())
            .add_double(amount as f64)
            .write_to(&self.dataset)
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        Ok(())
    }
}
