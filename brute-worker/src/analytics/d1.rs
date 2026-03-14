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
/// All upserts for a single attack event are submitted as a single `db.batch()`
/// call to minimise D1 round trips.
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

        // ── time-series buckets ───────────────────────────────────────────────
        let now_s = (js_sys::Date::now() / 1000.0) as i64;
        let hour_bucket = now_s - (now_s % 3600);
        let day_bucket = now_s - (now_s % 86400);

        let js_date = js_sys::Date::new_0();
        let dow = js_date.get_day() as i32; // 0 = Sunday
        let hod = js_date.get_hours() as i32;

        // Build the batch — unconditional upserts first.
        let mut stmts = vec![
            // top_username
            db.prepare(
                "INSERT INTO top_username (username, amount) VALUES (?1, 1)
                 ON CONFLICT (username) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[individual.username.clone().into()])
            .map_err(|e| BruteError::Database(e.to_string()))?,

            // top_password
            db.prepare(
                "INSERT INTO top_password (password, amount) VALUES (?1, 1)
                 ON CONFLICT (password) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[individual.password.clone().into()])
            .map_err(|e| BruteError::Database(e.to_string()))?,

            // top_ip
            db.prepare(
                "INSERT INTO top_ip (ip, amount) VALUES (?1, 1)
                 ON CONFLICT (ip) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[individual.ip.clone().into()])
            .map_err(|e| BruteError::Database(e.to_string()))?,

            // top_protocol
            db.prepare(
                "INSERT INTO top_protocol (protocol, amount) VALUES (?1, 1)
                 ON CONFLICT (protocol) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[individual.protocol.clone().into()])
            .map_err(|e| BruteError::Database(e.to_string()))?,

            // top_usr_pass_combo
            db.prepare(
                "INSERT INTO top_usr_pass_combo (username, password, amount) VALUES (?1, ?2, 1)
                 ON CONFLICT (username, password) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[
                individual.username.clone().into(),
                individual.password.clone().into(),
            ])
            .map_err(|e| BruteError::Database(e.to_string()))?,

            // top_hourly
            db.prepare(
                "INSERT INTO top_hourly (bucket, amount) VALUES (?1, 1)
                 ON CONFLICT (bucket) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[hour_bucket.into()])
            .map_err(|e| BruteError::Database(e.to_string()))?,

            // top_daily
            db.prepare(
                "INSERT INTO top_daily (bucket, amount) VALUES (?1, 1)
                 ON CONFLICT (bucket) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[day_bucket.into()])
            .map_err(|e| BruteError::Database(e.to_string()))?,

            // heatmap
            db.prepare(
                "INSERT INTO heatmap (day_of_week, hour_of_day, amount) VALUES (?1, ?2, 1)
                 ON CONFLICT (day_of_week, hour_of_day) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[dow.into(), hod.into()])
            .map_err(|e| BruteError::Database(e.to_string()))?,
        ];

        // ── optional geo upserts ──────────────────────────────────────────────
        if let Some(ref country) = processed.country {
            stmts.push(
                db.prepare(
                    "INSERT INTO top_country (country, amount) VALUES (?1, 1)
                     ON CONFLICT (country) DO UPDATE SET amount = amount + 1",
                )
                .bind(&[country.clone().into()])
                .map_err(|e| BruteError::Database(e.to_string()))?,
            );
        }

        if let Some(ref city) = processed.city {
            stmts.push(
                db.prepare(
                    "INSERT INTO top_city (city, amount) VALUES (?1, 1)
                     ON CONFLICT (city) DO UPDATE SET amount = amount + 1",
                )
                .bind(&[city.clone().into()])
                .map_err(|e| BruteError::Database(e.to_string()))?,
            );
        }

        if let Some(ref region) = processed.region {
            stmts.push(
                db.prepare(
                    "INSERT INTO top_region (region, amount) VALUES (?1, 1)
                     ON CONFLICT (region) DO UPDATE SET amount = amount + 1",
                )
                .bind(&[region.clone().into()])
                .map_err(|e| BruteError::Database(e.to_string()))?,
            );
        }

        if let Some(ref tz) = processed.timezone {
            stmts.push(
                db.prepare(
                    "INSERT INTO top_timezone (timezone, amount) VALUES (?1, 1)
                     ON CONFLICT (timezone) DO UPDATE SET amount = amount + 1",
                )
                .bind(&[tz.clone().into()])
                .map_err(|e| BruteError::Database(e.to_string()))?,
            );
        }

        if let Some(ref org) = processed.org {
            stmts.push(
                db.prepare(
                    "INSERT INTO top_org (org, amount) VALUES (?1, 1)
                     ON CONFLICT (org) DO UPDATE SET amount = amount + 1",
                )
                .bind(&[org.clone().into()])
                .map_err(|e| BruteError::Database(e.to_string()))?,
            );
        }

        if let Some(ref postal) = processed.postal {
            stmts.push(
                db.prepare(
                    "INSERT INTO top_postal (postal, amount) VALUES (?1, 1)
                     ON CONFLICT (postal) DO UPDATE SET amount = amount + 1",
                )
                .bind(&[postal.clone().into()])
                .map_err(|e| BruteError::Database(e.to_string()))?,
            );
        }

        if let Some(ref loc) = processed.loc {
            stmts.push(
                db.prepare(
                    "INSERT INTO top_loc (loc, amount) VALUES (?1, 1)
                     ON CONFLICT (loc) DO UPDATE SET amount = amount + 1",
                )
                .bind(&[loc.clone().into()])
                .map_err(|e| BruteError::Database(e.to_string()))?,
            );
        }

        // Submit all statements in a single round trip.
        db.batch(stmts)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))?;

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
