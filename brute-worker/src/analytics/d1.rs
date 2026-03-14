use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    model::{Individual, ProcessedIndividual},
    traits::analytics::BruteAnalytics,
};
use worker::D1Database;

/// Free-tier analytics implementation backed entirely by D1.
///
/// Mirrors the PostgreSQL `top_*` aggregation table approach: each attack
/// event upserts counters into SQLite tables inside D1. This avoids the
/// Cloudflare Analytics Engine binding which requires the Workers Paid plan.
///
/// Enabled when the `paid` feature is NOT active.
pub struct D1Analytics {
    pub db: D1Database,
}

impl D1Analytics {
    pub fn new(db: D1Database) -> Self {
        Self { db }
    }
}

#[async_trait(?Send)]
impl BruteAnalytics for D1Analytics {
    async fn record_attack_event(
        &self,
        individual: &Individual,
        processed: &ProcessedIndividual,
    ) -> Result<(), BruteError> {
        let db = &self.db;

        macro_rules! upsert {
            ($sql:expr, $($bind:expr),+) => {{
                db.prepare($sql)
                    .bind(&[$($bind.into()),+])
                    .map_err(|e| BruteError::Database(e.to_string()))?
                    .run()
                    .await
                    .map_err(|e| BruteError::Database(e.to_string()))?;
            }};
        }

        // ── top_username ──────────────────────────────────────────────────────
        upsert!(
            "INSERT INTO top_username (username, amount) VALUES (?1, 1)
             ON CONFLICT (username) DO UPDATE SET amount = amount + 1",
            individual.username.clone()
        );

        // ── top_password ──────────────────────────────────────────────────────
        upsert!(
            "INSERT INTO top_password (password, amount) VALUES (?1, 1)
             ON CONFLICT (password) DO UPDATE SET amount = amount + 1",
            individual.password.clone()
        );

        // ── top_ip ────────────────────────────────────────────────────────────
        upsert!(
            "INSERT INTO top_ip (ip, amount) VALUES (?1, 1)
             ON CONFLICT (ip) DO UPDATE SET amount = amount + 1",
            individual.ip.clone()
        );

        // ── top_protocol ──────────────────────────────────────────────────────
        upsert!(
            "INSERT INTO top_protocol (protocol, amount) VALUES (?1, 1)
             ON CONFLICT (protocol) DO UPDATE SET amount = amount + 1",
            individual.protocol.clone()
        );

        // ── top_country ───────────────────────────────────────────────────────
        if let Some(ref country) = processed.country {
            upsert!(
                "INSERT INTO top_country (country, amount) VALUES (?1, 1)
                 ON CONFLICT (country) DO UPDATE SET amount = amount + 1",
                country.clone()
            );
        }

        // ── top_city ──────────────────────────────────────────────────────────
        if let Some(ref city) = processed.city {
            upsert!(
                "INSERT INTO top_city (city, amount) VALUES (?1, 1)
                 ON CONFLICT (city) DO UPDATE SET amount = amount + 1",
                city.clone()
            );
        }

        // ── top_region ────────────────────────────────────────────────────────
        if let Some(ref region) = processed.region {
            upsert!(
                "INSERT INTO top_region (region, amount) VALUES (?1, 1)
                 ON CONFLICT (region) DO UPDATE SET amount = amount + 1",
                region.clone()
            );
        }

        // ── top_timezone ──────────────────────────────────────────────────────
        if let Some(ref tz) = processed.timezone {
            upsert!(
                "INSERT INTO top_timezone (timezone, amount) VALUES (?1, 1)
                 ON CONFLICT (timezone) DO UPDATE SET amount = amount + 1",
                tz.clone()
            );
        }

        // ── top_org ───────────────────────────────────────────────────────────
        if let Some(ref org) = processed.org {
            upsert!(
                "INSERT INTO top_org (org, amount) VALUES (?1, 1)
                 ON CONFLICT (org) DO UPDATE SET amount = amount + 1",
                org.clone()
            );
        }

        // ── top_postal ────────────────────────────────────────────────────────
        if let Some(ref postal) = processed.postal {
            upsert!(
                "INSERT INTO top_postal (postal, amount) VALUES (?1, 1)
                 ON CONFLICT (postal) DO UPDATE SET amount = amount + 1",
                postal.clone()
            );
        }

        // ── top_loc ───────────────────────────────────────────────────────────
        if let Some(ref loc) = processed.loc {
            upsert!(
                "INSERT INTO top_loc (loc, amount) VALUES (?1, 1)
                 ON CONFLICT (loc) DO UPDATE SET amount = amount + 1",
                loc.clone()
            );
        }

        // ── top_usr_pass_combo ────────────────────────────────────────────────
        upsert!(
            "INSERT INTO top_usr_pass_combo (username, password, amount) VALUES (?1, ?2, 1)
             ON CONFLICT (username, password) DO UPDATE SET amount = amount + 1",
            individual.username.clone(),
            individual.password.clone()
        );

        // ── time-series buckets (epoch-second timestamps rounded to bucket) ───
        let now_s = (js_sys::Date::now() / 1000.0) as i64;
        let hour_bucket = now_s - (now_s % 3600);
        let day_bucket = now_s - (now_s % 86400);

        upsert!(
            "INSERT INTO top_hourly (bucket, amount) VALUES (?1, 1)
             ON CONFLICT (bucket) DO UPDATE SET amount = amount + 1",
            hour_bucket
        );

        upsert!(
            "INSERT INTO top_daily (bucket, amount) VALUES (?1, 1)
             ON CONFLICT (bucket) DO UPDATE SET amount = amount + 1",
            day_bucket
        );

        // ── heatmap (day-of-week × hour-of-day) ──────────────────────────────
        let js_date = js_sys::Date::new_0();
        let dow = js_date.get_day() as i32;  // 0 = Sunday
        let hod = js_date.get_hours() as i32;

        upsert!(
            "INSERT INTO heatmap (day_of_week, hour_of_day, amount) VALUES (?1, ?2, 1)
             ON CONFLICT (day_of_week, hour_of_day) DO UPDATE SET amount = amount + 1",
            dow,
            hod
        );

        Ok(())
    }

    async fn record_protocol_event(
        &self,
        protocol: &str,
        amount: i32,
    ) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_protocol (protocol, amount) VALUES (?1, ?2)
                 ON CONFLICT (protocol) DO UPDATE SET amount = amount + ?2",
            )
            .bind(&[protocol.into(), amount.into()])
            .map_err(|e| BruteError::Database(e.to_string()))?
            .run()
            .await
            .map_err(|e| BruteError::Database(e.to_string()))?;

        Ok(())
    }
}
