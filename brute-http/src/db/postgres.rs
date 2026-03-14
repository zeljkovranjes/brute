use async_trait::async_trait;
use brute_core::{
    error::BruteError,
    model::{
        AttackVelocity, HeatmapCell, Individual, IpAbuse, IpSeen, ProcessedIndividual,
        ProtocolCombo, RollingStats, TopCity, TopCountry, TopDaily, TopHourly, TopIp, TopLocation,
        TopOrg, TopPassword, TopPostal, TopProtocol, TopRegion, TopSubnet, TopTimezone,
        TopUsername, TopUsrPassCombo, TopWeekly, TopYearly,
    },
    traits::database::BruteDb,
};
use sqlx::{Pool, Postgres};

/// PostgreSQL implementation of `BruteDb`.
#[derive(Clone)]
pub struct PostgresDb {
    pub pool: Pool<Postgres>,
}

impl PostgresDb {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BruteDb for PostgresDb {
    async fn insert_individual(&self, individual: &Individual) -> Result<Individual, BruteError> {
        let query = r#"
            INSERT INTO individual (id, username, password, ip, protocol, timestamp)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        "#;
        sqlx::query_as::<_, Individual>(query)
            .bind(&individual.id)
            .bind(&individual.username)
            .bind(&individual.password)
            .bind(&individual.ip)
            .bind(&individual.protocol)
            .bind(individual.timestamp)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn insert_processed_individual(
        &self,
        p: &ProcessedIndividual,
    ) -> Result<ProcessedIndividual, BruteError> {
        let query = r#"
            INSERT INTO processed_individual (
                id, username, password, ip, protocol, hostname, city, region, country, loc, org, postal,
                asn, asn_name, asn_domain, asn_route, asn_type,
                company_name, company_domain, company_type,
                vpn, proxy, tor, relay, hosting, service,
                abuse_address, abuse_country, abuse_email, abuse_name, abuse_network, abuse_phone,
                domain_ip, domain_total, domains, timestamp, timezone
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15, $16, $17,
                $18, $19, $20,
                $21, $22, $23, $24, $25, $26,
                $27, $28, $29, $30, $31, $32,
                $33, $34, $35, $36, $37
            ) RETURNING *;
        "#;
        sqlx::query_as::<_, ProcessedIndividual>(query)
            .bind(&p.id)
            .bind(&p.username)
            .bind(&p.password)
            .bind(&p.ip)
            .bind(&p.protocol)
            .bind(&p.hostname)
            .bind(&p.city)
            .bind(&p.region)
            .bind(&p.country)
            .bind(&p.loc)
            .bind(&p.org)
            .bind(&p.postal)
            .bind(&p.asn)
            .bind(&p.asn_name)
            .bind(&p.asn_domain)
            .bind(&p.asn_route)
            .bind(&p.asn_type)
            .bind(&p.company_name)
            .bind(&p.company_domain)
            .bind(&p.company_type)
            .bind(p.vpn)
            .bind(p.proxy)
            .bind(p.tor)
            .bind(p.relay)
            .bind(p.hosting)
            .bind(&p.service)
            .bind(&p.abuse_address)
            .bind(&p.abuse_country)
            .bind(&p.abuse_email)
            .bind(&p.abuse_name)
            .bind(&p.abuse_network)
            .bind(&p.abuse_phone)
            .bind(&p.domain_ip)
            .bind(p.domain_total)
            .bind(&p.domains)
            .bind(p.timestamp)
            .bind(&p.timezone)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_username(&self, username: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_username (username, amount) VALUES ($1, 1)
               ON CONFLICT (username) DO UPDATE SET amount = top_username.amount + 1"#,
        )
        .bind(username)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_password(&self, password: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_password (password, amount) VALUES ($1, 1)
               ON CONFLICT (password) DO UPDATE SET amount = top_password.amount + 1"#,
        )
        .bind(password)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_ip(&self, ip: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_ip (ip, amount) VALUES ($1, 1)
               ON CONFLICT (ip) DO UPDATE SET amount = top_ip.amount + 1"#,
        )
        .bind(ip)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_protocol(&self, protocol: &str, amount: i32) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_protocol (protocol, amount) VALUES ($1, $2)
               ON CONFLICT (protocol) DO UPDATE SET amount = top_protocol.amount + EXCLUDED.amount"#,
        )
        .bind(protocol)
        .bind(amount)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_country(&self, country: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_country (country, amount) VALUES ($1, 1)
               ON CONFLICT (country) DO UPDATE SET amount = top_country.amount + 1"#,
        )
        .bind(country)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_city(&self, city: &str, country: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_city (city, country, amount) VALUES ($1, $2, 1)
               ON CONFLICT (city, country) DO UPDATE SET amount = top_city.amount + 1"#,
        )
        .bind(city)
        .bind(country)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_region(&self, region: &str, country: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_region (region, country, amount) VALUES ($1, $2, 1)
               ON CONFLICT (region, country) DO UPDATE SET amount = top_region.amount + 1"#,
        )
        .bind(region)
        .bind(country)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_timezone(&self, timezone: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_timezone (timezone, amount) VALUES ($1, 1)
               ON CONFLICT (timezone) DO UPDATE SET amount = top_timezone.amount + 1"#,
        )
        .bind(timezone)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_org(&self, org: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_org (org, amount) VALUES ($1, 1)
               ON CONFLICT (org) DO UPDATE SET amount = top_org.amount + 1"#,
        )
        .bind(org)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_postal(&self, postal: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_postal (postal, amount) VALUES ($1, 1)
               ON CONFLICT (postal) DO UPDATE SET amount = top_postal.amount + 1"#,
        )
        .bind(postal)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_location(&self, loc: &str) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_loc (loc, amount) VALUES ($1, 1)
               ON CONFLICT (loc) DO UPDATE SET amount = top_loc.amount + 1"#,
        )
        .bind(loc)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_top_combo(
        &self,
        id: &str,
        username: &str,
        password: &str,
    ) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO top_usr_pass_combo (id, username, password, amount) VALUES ($1, $2, $3, 1)
               ON CONFLICT (username, password) DO UPDATE SET amount = top_usr_pass_combo.amount + 1"#,
        )
        .bind(id)
        .bind(username)
        .bind(password)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn update_ip_seen(&self, ip: &str, now: i64) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO ip_seen (ip, first_seen, last_seen, total_sessions) VALUES ($1, $2, $2, 1)
               ON CONFLICT (ip) DO UPDATE SET last_seen = $2, total_sessions = ip_seen.total_sessions + 1"#,
        )
        .bind(ip)
        .bind(now)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn update_attack_hourly(&self, now: i64) -> Result<(), BruteError> {
        let bucket = (now / 3_600_000) * 3_600_000;
        sqlx::query(
            r#"INSERT INTO top_hourly (timestamp, amount) VALUES ($1, 1)
               ON CONFLICT (timestamp) DO UPDATE SET amount = top_hourly.amount + 1"#,
        )
        .bind(bucket)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn update_attack_daily(&self, now: i64) -> Result<(), BruteError> {
        let bucket = (now / 86_400_000) * 86_400_000;
        sqlx::query(
            r#"INSERT INTO top_daily (timestamp, amount) VALUES ($1, 1)
               ON CONFLICT (timestamp) DO UPDATE SET amount = top_daily.amount + 1"#,
        )
        .bind(bucket)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn update_attack_weekly(&self, now: i64) -> Result<(), BruteError> {
        // Align to Monday of the current week (ms)
        let days_since_epoch = now / 86_400_000;
        let day_of_week = (days_since_epoch + 3) % 7; // 0 = Monday
        let week_start = (days_since_epoch - day_of_week) * 86_400_000;
        sqlx::query(
            r#"INSERT INTO top_weekly (timestamp, amount) VALUES ($1, 1)
               ON CONFLICT (timestamp) DO UPDATE SET amount = top_weekly.amount + 1"#,
        )
        .bind(week_start)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn update_attack_yearly(&self, now: i64) -> Result<(), BruteError> {
        // Align to Jan 1 of the current year using chrono
        use chrono::{Datelike, TimeZone, Utc};
        let dt = Utc.timestamp_millis_opt(now).single().unwrap_or_default();
        let year_start = Utc
            .with_ymd_and_hms(dt.year(), 1, 1, 0, 0, 0)
            .single()
            .unwrap_or_default()
            .timestamp_millis();
        sqlx::query(
            r#"INSERT INTO top_yearly (timestamp, amount) VALUES ($1, 1)
               ON CONFLICT (timestamp) DO UPDATE SET amount = top_yearly.amount + 1"#,
        )
        .bind(year_start)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn upsert_ip_abuse(
        &self,
        ip: &str,
        confidence_score: i32,
        total_reports: i32,
        checked_at: i64,
    ) -> Result<(), BruteError> {
        sqlx::query(
            r#"INSERT INTO ip_abuse (ip, confidence_score, total_reports, checked_at)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (ip) DO UPDATE SET
                   confidence_score = EXCLUDED.confidence_score,
                   total_reports = EXCLUDED.total_reports,
                   checked_at = EXCLUDED.checked_at"#,
        )
        .bind(ip)
        .bind(confidence_score)
        .bind(total_reports)
        .bind(checked_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn update_password_breached(&self, password: &str) -> Result<(), BruteError> {
        sqlx::query("UPDATE top_password SET is_breached = TRUE WHERE password = $1")
            .bind(password)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    // ---- read operations ----

    async fn get_attacks(&self, limit: i64) -> Result<Vec<ProcessedIndividual>, BruteError> {
        sqlx::query_as::<_, ProcessedIndividual>(
            "SELECT * FROM processed_individual ORDER BY timestamp DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_username(&self, limit: i64) -> Result<Vec<TopUsername>, BruteError> {
        sqlx::query_as::<_, TopUsername>(
            "SELECT * FROM top_username ORDER BY amount DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_password(&self, limit: i64) -> Result<Vec<TopPassword>, BruteError> {
        sqlx::query_as::<_, TopPassword>(
            "SELECT * FROM top_password WHERE password !~ '^X{2,}$' ORDER BY amount DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_ip(&self, limit: i64) -> Result<Vec<TopIp>, BruteError> {
        sqlx::query_as::<_, TopIp>("SELECT * FROM top_ip ORDER BY amount DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_protocol(&self, limit: i64) -> Result<Vec<TopProtocol>, BruteError> {
        sqlx::query_as::<_, TopProtocol>(
            "SELECT * FROM top_protocol ORDER BY amount DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_country(&self, limit: i64) -> Result<Vec<TopCountry>, BruteError> {
        sqlx::query_as::<_, TopCountry>("SELECT * FROM top_country ORDER BY amount DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_city(&self, limit: i64) -> Result<Vec<TopCity>, BruteError> {
        sqlx::query_as::<_, TopCity>("SELECT * FROM top_city ORDER BY amount DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_region(&self, limit: i64) -> Result<Vec<TopRegion>, BruteError> {
        sqlx::query_as::<_, TopRegion>("SELECT * FROM top_region ORDER BY amount DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_timezone(&self, limit: i64) -> Result<Vec<TopTimezone>, BruteError> {
        sqlx::query_as::<_, TopTimezone>(
            "SELECT * FROM top_timezone ORDER BY amount DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_org(&self, limit: i64) -> Result<Vec<TopOrg>, BruteError> {
        sqlx::query_as::<_, TopOrg>("SELECT * FROM top_org ORDER BY amount DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_postal(&self, limit: i64) -> Result<Vec<TopPostal>, BruteError> {
        sqlx::query_as::<_, TopPostal>(
            "SELECT * FROM top_postal WHERE postal !~ '^\\s*$' ORDER BY amount DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_location(&self, limit: i64) -> Result<Vec<TopLocation>, BruteError> {
        sqlx::query_as::<_, TopLocation>("SELECT * FROM top_loc ORDER BY amount DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_top_combo(&self, limit: i64) -> Result<Vec<TopUsrPassCombo>, BruteError> {
        sqlx::query_as::<_, TopUsrPassCombo>(
            "SELECT * FROM top_usr_pass_combo WHERE password !~ '^X{2,}$' ORDER BY amount DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_hourly(&self, limit: i64) -> Result<Vec<TopHourly>, BruteError> {
        sqlx::query_as::<_, TopHourly>(
            "SELECT * FROM top_hourly ORDER BY timestamp DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_daily(&self, limit: i64) -> Result<Vec<TopDaily>, BruteError> {
        sqlx::query_as::<_, TopDaily>("SELECT * FROM top_daily ORDER BY timestamp DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_weekly(&self, limit: i64) -> Result<Vec<TopWeekly>, BruteError> {
        sqlx::query_as::<_, TopWeekly>(
            "SELECT * FROM top_weekly ORDER BY timestamp DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_yearly(&self, limit: i64) -> Result<Vec<TopYearly>, BruteError> {
        sqlx::query_as::<_, TopYearly>(
            "SELECT * FROM top_yearly ORDER BY timestamp DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_heatmap(&self) -> Result<Vec<HeatmapCell>, BruteError> {
        sqlx::query_as::<_, HeatmapCell>(
            r#"SELECT
                EXTRACT(DOW FROM to_timestamp(timestamp / 1000.0))::int AS day_of_week,
                EXTRACT(HOUR FROM to_timestamp(timestamp / 1000.0))::int AS hour_of_day,
                COUNT(*)::bigint AS amount
            FROM processed_individual
            GROUP BY day_of_week, hour_of_day
            ORDER BY day_of_week, hour_of_day"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_velocity(&self, since: i64, limit: i64) -> Result<Vec<AttackVelocity>, BruteError> {
        sqlx::query_as::<_, AttackVelocity>(
            r#"SELECT
                (timestamp / 60000) * 60000 AS minute_bucket,
                COUNT(*)::bigint AS amount
            FROM processed_individual
            WHERE timestamp > $1
            GROUP BY minute_bucket
            ORDER BY minute_bucket DESC
            LIMIT $2"#,
        )
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_summary(&self) -> Result<RollingStats, BruteError> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM individual")
            .fetch_one(&self.pool)
            .await
            .unwrap_or(0);
        let last_hour: i32 = sqlx::query_scalar(
            "SELECT COALESCE(amount, 0) FROM top_hourly ORDER BY timestamp DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None)
        .unwrap_or(0);
        let top_protocol: Option<String> = sqlx::query_scalar(
            "SELECT protocol FROM top_protocol ORDER BY amount DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None);
        let top_country: Option<String> = sqlx::query_scalar(
            "SELECT country FROM top_country ORDER BY amount DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None);
        Ok(RollingStats {
            total_attacks: total,
            attacks_last_hour: last_hour,
            top_protocol,
            top_country,
        })
    }

    async fn get_subnet(&self, limit: i64) -> Result<Vec<TopSubnet>, BruteError> {
        sqlx::query_as::<_, TopSubnet>(
            r#"SELECT
                regexp_replace(ip, '(\d+\.\d+\.\d+)\.\d+', '\1.0/24') AS subnet,
                COUNT(*)::bigint AS amount
            FROM processed_individual
            WHERE ip ~ '^\d+\.\d+\.\d+\.\d+$'
            GROUP BY subnet
            ORDER BY amount DESC
            LIMIT $1"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_ip_seen(&self, limit: i64) -> Result<Vec<IpSeen>, BruteError> {
        sqlx::query_as::<_, IpSeen>(
            "SELECT * FROM ip_seen ORDER BY total_sessions DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_ip_abuse(&self, limit: i64) -> Result<Vec<IpAbuse>, BruteError> {
        sqlx::query_as::<_, IpAbuse>(
            "SELECT * FROM ip_abuse ORDER BY confidence_score DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_blocklist(&self, limit: i64) -> Result<Vec<TopIp>, BruteError> {
        sqlx::query_as::<_, TopIp>("SELECT * FROM top_ip ORDER BY amount DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_ip_seen_checked_at(&self, ip: &str) -> Result<Option<i64>, BruteError> {
        sqlx::query_scalar("SELECT checked_at FROM ip_abuse WHERE ip = $1")
            .bind(ip)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| BruteError::Database(e.to_string()))
    }

    async fn get_protocol_combo(
        &self,
        protocol: &str,
        limit: i64,
    ) -> Result<Vec<ProtocolCombo>, BruteError> {
        sqlx::query_as::<_, ProtocolCombo>(
            r#"SELECT username, password, COUNT(*)::bigint AS amount
               FROM individual
               WHERE protocol = $1
               GROUP BY username, password
               ORDER BY amount DESC
               LIMIT $2"#,
        )
        .bind(protocol)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| BruteError::Database(e.to_string()))
    }
}
