use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    traits::abuse::{AbuseData, AbuseProvider},
};
use log::warn;
use reqwest::Client;
use serde::Deserialize;
use sqlx::{Pool, Postgres};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

/// AbuseIPDB v2 implementation of `AbuseProvider`.
///
/// Results are cached in the `ip_abuse` PostgreSQL table for 24 hours.
/// When a 429 is received the `Retry-After` header (seconds) is read and
/// the task sleeps for that duration before retrying. If the header is
/// absent a 60-second fallback is used.
/// When `api_key` is empty the check is skipped and `Ok(None)` is returned.
pub struct AbuseIpDb {
    pub api_key: String,
    pub pool: Pool<Postgres>,
    pub client: Client,
    /// Shared across all callers — set to the resume time on 429, cleared after waking.
    pub rate_limited_until: Arc<Mutex<Option<SystemTime>>>,
}

impl AbuseIpDb {
    pub fn new(api_key: String, pool: Pool<Postgres>) -> Self {
        Self {
            api_key,
            pool,
            client: Client::new(),
            rate_limited_until: Arc::new(Mutex::new(None)),
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

        // If another task already tripped the rate limit, wait it out first.
        {
            let rl = self.rate_limited_until.lock().await;
            if let Some(resume_at) = *rl {
                if let Ok(remaining) = resume_at.duration_since(SystemTime::now()) {
                    drop(rl);
                    warn!(
                        "AbuseIPDB rate limited — waiting {:.1}s before check",
                        remaining.as_secs_f64()
                    );
                    tokio::time::sleep(remaining).await;
                }
            }
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

        loop {
            let resp = self
                .client
                .get(&url)
                .header("Key", &self.api_key)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| BruteError::Geo(format!("AbuseIPDB request failed: {}", e)))?;

            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                // Retry-After is in seconds.
                let retry_after = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(60);

                let resume_at = SystemTime::now() + Duration::from_secs(retry_after);
                *self.rate_limited_until.lock().await = Some(resume_at);

                warn!(
                    "AbuseIPDB rate limit hit — sleeping {}s until reset",
                    retry_after
                );
                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                *self.rate_limited_until.lock().await = None;
                continue;
            }

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

            return Ok(Some(data));
        }
    }
}
