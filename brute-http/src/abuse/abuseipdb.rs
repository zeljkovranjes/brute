use async_trait::async_trait;
use brute_core::{error::BruteError, traits::abuse::{AbuseData, AbuseProvider}};
use reqwest::Client;
use serde::Deserialize;
use sqlx::{Pool, Postgres};
use std::time::{SystemTime, UNIX_EPOCH};

/// AbuseIPDB v2 implementation of `AbuseProvider`.
///
/// Results are cached in the `ip_abuse` PostgreSQL table for 24 hours.
/// When `api_key` is empty the check is skipped and `Ok(None)` is returned.
pub struct AbuseIpDb {
    pub api_key: String,
    pub pool: Pool<Postgres>,
    pub client: Client,
}

impl AbuseIpDb {
    pub fn new(api_key: String, pool: Pool<Postgres>) -> Self {
        Self {
            api_key,
            pool,
            client: Client::new(),
        }
    }
}

#[derive(Deserialize)]
struct ApiResponse {
    data: ApiData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiData {
    abuse_confidence_score: i32,
    total_reports: i32,
}

const CACHE_TTL_MS: i64 = 86_400_000; // 24 hours

#[async_trait]
impl AbuseProvider for AbuseIpDb {
    async fn check(&self, ip: &str) -> Result<Option<AbuseData>, BruteError> {
        if self.api_key.is_empty() {
            return Ok(None);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Return cached result if checked within the last 24 hours.
        let cached: Option<i64> =
            sqlx::query_scalar("SELECT checked_at FROM ip_abuse WHERE ip = $1")
                .bind(ip)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| BruteError::Database(e.to_string()))?;

        if let Some(checked_at) = cached {
            if now - checked_at < CACHE_TTL_MS {
                return Ok(None);
            }
        }

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );

        let resp = self
            .client
            .get(&url)
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| BruteError::Geo(format!("AbuseIPDB request failed: {}", e)))?;

        let api: ApiResponse = resp
            .json()
            .await
            .map_err(|e| BruteError::Geo(format!("AbuseIPDB parse failed: {}", e)))?;

        let data = AbuseData {
            ip: ip.to_string(),
            confidence_score: api.data.abuse_confidence_score,
            total_reports: api.data.total_reports,
            checked_at: now,
        };

        sqlx::query(
            r#"
            INSERT INTO ip_abuse (ip, confidence_score, total_reports, checked_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (ip) DO UPDATE SET
                confidence_score = EXCLUDED.confidence_score,
                total_reports    = EXCLUDED.total_reports,
                checked_at       = EXCLUDED.checked_at
            "#,
        )
        .bind(&data.ip)
        .bind(data.confidence_score)
        .bind(data.total_reports)
        .bind(data.checked_at)
        .execute(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))?;

        Ok(Some(data))
    }
}
