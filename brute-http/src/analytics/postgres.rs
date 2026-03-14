use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    model::{Individual, ProcessedIndividual},
    traits::analytics::BruteAnalytics,
};
use sqlx::{Pool, Postgres};

/// PostgreSQL implementation of `BruteAnalytics`.
///
/// Instead of writing to an external event stream, this updates the
/// aggregation (top_*) tables directly in PostgreSQL.
#[derive(Clone)]
pub struct PostgresAnalytics {
    pub pool: Pool<Postgres>,
}

impl PostgresAnalytics {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BruteAnalytics for PostgresAnalytics {
    async fn record_attack_event(
        &self,
        individual: &Individual,
        processed: &ProcessedIndividual,
    ) -> Result<(), BruteError> {
        // Upsert top_username
        sqlx::query(
            r#"INSERT INTO top_username (username, amount) VALUES ($1, 1)
               ON CONFLICT (username) DO UPDATE SET amount = top_username.amount + 1"#,
        )
        .bind(&individual.username)
        .execute(&self.pool)
        .await
        .map_err(|e| BruteError::Analytics(e.to_string()))?;

        // Upsert top_password
        sqlx::query(
            r#"INSERT INTO top_password (password, amount) VALUES ($1, 1)
               ON CONFLICT (password) DO UPDATE SET amount = top_password.amount + 1"#,
        )
        .bind(&individual.password)
        .execute(&self.pool)
        .await
        .map_err(|e| BruteError::Analytics(e.to_string()))?;

        // Upsert top_ip
        sqlx::query(
            r#"INSERT INTO top_ip (ip, amount) VALUES ($1, 1)
               ON CONFLICT (ip) DO UPDATE SET amount = top_ip.amount + 1"#,
        )
        .bind(&individual.ip)
        .execute(&self.pool)
        .await
        .map_err(|e| BruteError::Analytics(e.to_string()))?;

        // Upsert top_protocol
        sqlx::query(
            r#"INSERT INTO top_protocol (protocol, amount) VALUES ($1, 1)
               ON CONFLICT (protocol) DO UPDATE SET amount = top_protocol.amount + 1"#,
        )
        .bind(&individual.protocol)
        .execute(&self.pool)
        .await
        .map_err(|e| BruteError::Analytics(e.to_string()))?;

        // Location-based aggregations from processed data
        if let Some(country) = &processed.country {
            sqlx::query(
                r#"INSERT INTO top_country (country, amount) VALUES ($1, 1)
                   ON CONFLICT (country) DO UPDATE SET amount = top_country.amount + 1"#,
            )
            .bind(country)
            .execute(&self.pool)
            .await
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        }

        if let (Some(city), Some(country)) = (&processed.city, &processed.country) {
            sqlx::query(
                r#"INSERT INTO top_city (city, country, amount) VALUES ($1, $2, 1)
                   ON CONFLICT (city, country) DO UPDATE SET amount = top_city.amount + 1"#,
            )
            .bind(city)
            .bind(country)
            .execute(&self.pool)
            .await
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        }

        if let (Some(region), Some(country)) = (&processed.region, &processed.country) {
            sqlx::query(
                r#"INSERT INTO top_region (region, country, amount) VALUES ($1, $2, 1)
                   ON CONFLICT (region, country) DO UPDATE SET amount = top_region.amount + 1"#,
            )
            .bind(region)
            .bind(country)
            .execute(&self.pool)
            .await
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        }

        if !processed.timezone.is_empty() {
            sqlx::query(
                r#"INSERT INTO top_timezone (timezone, amount) VALUES ($1, 1)
                   ON CONFLICT (timezone) DO UPDATE SET amount = top_timezone.amount + 1"#,
            )
            .bind(&processed.timezone)
            .execute(&self.pool)
            .await
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        }

        if let Some(org) = &processed.org {
            sqlx::query(
                r#"INSERT INTO top_org (org, amount) VALUES ($1, 1)
                   ON CONFLICT (org) DO UPDATE SET amount = top_org.amount + 1"#,
            )
            .bind(org)
            .execute(&self.pool)
            .await
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        }

        if let Some(postal) = &processed.postal {
            sqlx::query(
                r#"INSERT INTO top_postal (postal, amount) VALUES ($1, 1)
                   ON CONFLICT (postal) DO UPDATE SET amount = top_postal.amount + 1"#,
            )
            .bind(postal)
            .execute(&self.pool)
            .await
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        }

        if let Some(loc) = &processed.loc {
            sqlx::query(
                r#"INSERT INTO top_loc (loc, amount) VALUES ($1, 1)
                   ON CONFLICT (loc) DO UPDATE SET amount = top_loc.amount + 1"#,
            )
            .bind(loc)
            .execute(&self.pool)
            .await
            .map_err(|e| BruteError::Analytics(e.to_string()))?;
        }

        Ok(())
    }

    async fn record_protocol_event(
        &self,
        protocol: &str,
        amount: i32,
    ) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_protocol (protocol, amount) VALUES ($1, $2)
               ON CONFLICT (protocol) DO UPDATE SET amount = top_protocol.amount + EXCLUDED.amount"#,
        )
        .bind(protocol)
        .bind(amount)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Analytics(e.to_string()))
    }
}
