use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    model::{Individual, ProcessedIndividual},
    traits::analytics::BruteAnalytics,
};
use worker::AnalyticsEngineDataset;

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
        self.dataset
            .write_data_point()
            .map_err(|e| BruteError::Analytics(e.to_string()))?
            .blob(individual.username.clone())
            .blob(individual.password.clone())
            .blob(processed.country.clone().unwrap_or_default())
            .blob(processed.city.clone().unwrap_or_default())
            .blob(individual.protocol.clone())
            .blob(individual.ip.clone())
            .blob(processed.org.clone().unwrap_or_default())
            .double(1.0)
            .send()
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        Ok(())
    }

    async fn record_protocol_event(
        &self,
        protocol: &str,
        amount: i32,
    ) -> Result<(), BruteError> {
        // Write a protocol-only increment data point.
        // blob1 = "_protocol_increment" sentinel to distinguish from attack events
        // blob2 = protocol name
        // double1 = amount
        self.dataset
            .write_data_point()
            .map_err(|e| BruteError::Analytics(e.to_string()))?
            .blob("_protocol_increment".to_string())
            .blob(protocol.to_string())
            .double(amount as f64)
            .send()
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        Ok(())
    }
}
