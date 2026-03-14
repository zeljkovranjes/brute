use async_trait::async_trait;
use brute_core::{error::BruteError, traits::abuse::{AbuseData, AbuseProvider}};
use worker::{D1Database, Env};

/// AbuseIPDB v2 implementation of `AbuseProvider` for Cloudflare Workers.
///
/// Results are cached in the D1 `ip_abuse` table for 24 hours.
/// The API key is read from the `ABUSEIPDB_KEY` Workers secret/var.
/// When absent the check is skipped and `Ok(None)` is returned.
pub struct WorkerAbuseIpDb {
    pub api_key: String,
    pub db: D1Database,
}

impl WorkerAbuseIpDb {
    pub fn from_env(env: &Env, db: D1Database) -> Self {
        let api_key = env.var("ABUSEIPDB_KEY")
            .map(|v| v.to_string())
            .unwrap_or_default();
        Self { api_key, db }
    }
}

const CACHE_TTL_MS: i64 = 86_400_000; // 24 hours

#[async_trait(?Send)]
impl AbuseProvider for WorkerAbuseIpDb {
    async fn check(&self, ip: &str) -> Result<Option<AbuseData>, BruteError> {
        if self.api_key.is_empty() {
            return Ok(None);
        }

        let now = js_sys::Date::now() as i64;

        // Return cached result if checked within the last 24 hours.
        let cached: Option<i64> = self
            .db
            .prepare("SELECT checked_at FROM ip_abuse WHERE ip = ?1")
            .bind(&[ip.into()])
            .map_err(|e| BruteError::Database(e.to_string()))?
            .first::<serde_json::Value>(Some("checked_at"))
            .await
            .map_err(|e| BruteError::Database(e.to_string()))?
            .and_then(|v| v.as_i64());

        if let Some(checked_at) = cached {
            if now - checked_at < CACHE_TTL_MS {
                return Ok(None);
            }
        }

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip
        );

        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Get);
        let mut headers = worker::Headers::new();
        headers.set("Key", &self.api_key).ok();
        headers.set("Accept", "application/json").ok();
        init.with_headers(headers);

        let req = worker::Request::new_with_init(&url, &init)
            .map_err(|e| BruteError::Geo(format!("AbuseIPDB request build failed: {}", e)))?;

        let mut resp = worker::Fetch::Request(req)
            .send()
            .await
            .map_err(|e| BruteError::Geo(format!("AbuseIPDB fetch failed: {}", e)))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BruteError::Geo(format!("AbuseIPDB parse failed: {}", e)))?;

        let confidence_score = body["data"]["abuseConfidenceScore"]
            .as_i64()
            .unwrap_or(0) as i32;
        let total_reports = body["data"]["totalReports"]
            .as_i64()
            .unwrap_or(0) as i32;

        let data = AbuseData {
            ip: ip.to_string(),
            confidence_score,
            total_reports,
            checked_at: now,
        };

        self.db
            .prepare(
                "INSERT INTO ip_abuse (ip, confidence_score, total_reports, checked_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (ip) DO UPDATE SET
                     confidence_score = excluded.confidence_score,
                     total_reports    = excluded.total_reports,
                     checked_at       = excluded.checked_at",
            )
            .bind(&[
                ip.into(),
                confidence_score.into(),
                total_reports.into(),
                now.into(),
            ])
            .map_err(|e| BruteError::Database(e.to_string()))?
            .run()
            .await
            .map_err(|e| BruteError::Database(e.to_string()))?;

        Ok(Some(data))
    }
}
