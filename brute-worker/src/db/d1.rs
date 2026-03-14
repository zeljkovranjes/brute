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
use worker::D1Database;

/// Cloudflare D1 (SQLite) implementation of `BruteDb`.
///
/// Uses the workers-rs D1 binding. Queries use SQLite-compatible syntax.
/// Notable differences from PostgreSQL:
///   - No UUID type — stored as TEXT
///   - No SERIAL — use INTEGER PRIMARY KEY
///   - No JSONB — arrays stored as JSON text
///   - No regex operators — pattern matching via LIKE or GLOB
///   - Timestamps as INTEGER (Unix ms)
pub struct D1Db {
    pub db: D1Database,
}

impl D1Db {
    pub fn new(db: D1Database) -> Self {
        Self { db }
    }

    fn map_err(e: worker::Error) -> BruteError {
        BruteError::Database(e.to_string())
    }
}

#[async_trait(?Send)]
impl BruteDb for D1Db {
    async fn insert_individual(&self, individual: &Individual) -> Result<Individual, BruteError> {
        self.db
            .prepare(
                "INSERT INTO individual (id, username, password, ip, protocol, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&[
                individual.id.clone().into(),
                individual.username.clone().into(),
                individual.password.clone().into(),
                individual.ip.clone().into(),
                individual.protocol.clone().into(),
                individual.timestamp.into(),
            ])
            .map_err(Self::map_err)?
            .run()
            .await
            .map_err(Self::map_err)?;
        Ok(individual.clone())
    }

    async fn insert_processed_individual(
        &self,
        p: &ProcessedIndividual,
    ) -> Result<ProcessedIndividual, BruteError> {
        // SQLite does not support TEXT[] — serialize domains as JSON
        let domains_json = p
            .domains
            .as_ref()
            .map(|d| serde_json::to_string(d).unwrap_or_default());

        self.db
            .prepare(
                "INSERT INTO processed_individual (
                    id, username, password, ip, protocol, hostname, city, region,
                    country, loc, org, postal, asn, asn_name, asn_domain, asn_route, asn_type,
                    company_name, company_domain, company_type,
                    vpn, proxy, tor, relay, hosting, service,
                    abuse_address, abuse_country, abuse_email, abuse_name, abuse_network, abuse_phone,
                    domain_ip, domain_total, domains, timestamp, timezone
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                    ?21, ?22, ?23, ?24, ?25, ?26,
                    ?27, ?28, ?29, ?30, ?31, ?32,
                    ?33, ?34, ?35, ?36, ?37
                )",
            )
            .bind(&[
                p.id.clone().into(),
                p.username.clone().into(),
                p.password.clone().into(),
                p.ip.clone().into(),
                p.protocol.clone().into(),
                p.hostname.clone().unwrap_or_default().into(),
                p.city.clone().unwrap_or_default().into(),
                p.region.clone().unwrap_or_default().into(),
                p.country.clone().unwrap_or_default().into(),
                p.loc.clone().unwrap_or_default().into(),
                p.org.clone().unwrap_or_default().into(),
                p.postal.clone().unwrap_or_default().into(),
                p.asn.clone().unwrap_or_default().into(),
                p.asn_name.clone().unwrap_or_default().into(),
                p.asn_domain.clone().unwrap_or_default().into(),
                p.asn_route.clone().unwrap_or_default().into(),
                p.asn_type.clone().unwrap_or_default().into(),
                p.company_name.clone().unwrap_or_default().into(),
                p.company_domain.clone().unwrap_or_default().into(),
                p.company_type.clone().unwrap_or_default().into(),
                (p.vpn.unwrap_or(false) as i32).into(),
                (p.proxy.unwrap_or(false) as i32).into(),
                (p.tor.unwrap_or(false) as i32).into(),
                (p.relay.unwrap_or(false) as i32).into(),
                (p.hosting.unwrap_or(false) as i32).into(),
                p.service.clone().unwrap_or_default().into(),
                p.abuse_address.clone().unwrap_or_default().into(),
                p.abuse_country.clone().unwrap_or_default().into(),
                p.abuse_email.clone().unwrap_or_default().into(),
                p.abuse_name.clone().unwrap_or_default().into(),
                p.abuse_network.clone().unwrap_or_default().into(),
                p.abuse_phone.clone().unwrap_or_default().into(),
                p.domain_ip.clone().unwrap_or_default().into(),
                p.domain_total.unwrap_or(0).into(),
                domains_json.unwrap_or_default().into(),
                p.timestamp.into(),
                p.timezone.clone().into(),
            ])
            .map_err(Self::map_err)?
            .run()
            .await
            .map_err(Self::map_err)?;
        Ok(p.clone())
    }

    async fn upsert_top_username(&self, username: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_username (username, amount) VALUES (?1, 1)
                 ON CONFLICT(username) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[username.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_password(&self, password: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_password (password, amount) VALUES (?1, 1)
                 ON CONFLICT(password) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[password.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_ip(&self, ip: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_ip (ip, amount) VALUES (?1, 1)
                 ON CONFLICT(ip) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[ip.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_protocol(&self, protocol: &str, amount: i32) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_protocol (protocol, amount) VALUES (?1, ?2)
                 ON CONFLICT(protocol) DO UPDATE SET amount = amount + excluded.amount",
            )
            .bind(&[protocol.into(), amount.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_country(&self, country: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_country (country, amount) VALUES (?1, 1)
                 ON CONFLICT(country) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[country.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_city(&self, city: &str, country: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_city (city, country, amount) VALUES (?1, ?2, 1)
                 ON CONFLICT(city, country) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[city.into(), country.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_region(&self, region: &str, country: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_region (region, country, amount) VALUES (?1, ?2, 1)
                 ON CONFLICT(region, country) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[region.into(), country.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_timezone(&self, timezone: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_timezone (timezone, amount) VALUES (?1, 1)
                 ON CONFLICT(timezone) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[timezone.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_org(&self, org: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_org (org, amount) VALUES (?1, 1)
                 ON CONFLICT(org) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[org.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_postal(&self, postal: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_postal (postal, amount) VALUES (?1, 1)
                 ON CONFLICT(postal) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[postal.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_location(&self, loc: &str) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_loc (loc, amount) VALUES (?1, 1)
                 ON CONFLICT(loc) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[loc.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_top_combo(
        &self,
        id: &str,
        username: &str,
        password: &str,
    ) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO top_usr_pass_combo (id, username, password, amount) VALUES (?1, ?2, ?3, 1)
                 ON CONFLICT(username, password) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[id.into(), username.into(), password.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn update_ip_seen(&self, ip: &str, now: i64) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO ip_seen (ip, first_seen, last_seen, total_sessions) VALUES (?1, ?2, ?2, 1)
                 ON CONFLICT(ip) DO UPDATE SET last_seen = ?2, total_sessions = total_sessions + 1",
            )
            .bind(&[ip.into(), now.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn update_attack_hourly(&self, now: i64) -> Result<(), BruteError> {
        let bucket = (now / 3_600_000) * 3_600_000;
        self.db
            .prepare(
                "INSERT INTO top_hourly (timestamp, amount) VALUES (?1, 1)
                 ON CONFLICT(timestamp) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[bucket.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn update_attack_daily(&self, now: i64) -> Result<(), BruteError> {
        let bucket = (now / 86_400_000) * 86_400_000;
        self.db
            .prepare(
                "INSERT INTO top_daily (timestamp, amount) VALUES (?1, 1)
                 ON CONFLICT(timestamp) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[bucket.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn update_attack_weekly(&self, now: i64) -> Result<(), BruteError> {
        let days_since_epoch = now / 86_400_000;
        let day_of_week = (days_since_epoch + 3) % 7; // 0 = Monday
        let week_start = (days_since_epoch - day_of_week) * 86_400_000;
        self.db
            .prepare(
                "INSERT INTO top_weekly (timestamp, amount) VALUES (?1, 1)
                 ON CONFLICT(timestamp) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[week_start.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn update_attack_yearly(&self, now: i64) -> Result<(), BruteError> {
        // Compute Jan 1 of the current year in ms
        // SQLite: use strftime to compute year boundary from epoch seconds
        // Here we do a simple integer approximation: strip to year via division
        // TODO: replace with proper calendar math if precision matters
        let days = now / 86_400_000;
        // Approximate year: days since 1970-01-01
        let year = 1970 + days / 365;
        // Approx Jan 1 of that year in ms
        let year_start_days = (year - 1970) * 365 + (year - 1969) / 4; // rough leap-year count
        let year_start = year_start_days * 86_400_000;
        self.db
            .prepare(
                "INSERT INTO top_yearly (timestamp, amount) VALUES (?1, 1)
                 ON CONFLICT(timestamp) DO UPDATE SET amount = amount + 1",
            )
            .bind(&[year_start.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn upsert_ip_abuse(
        &self,
        ip: &str,
        confidence_score: i32,
        total_reports: i32,
        checked_at: i64,
    ) -> Result<(), BruteError> {
        self.db
            .prepare(
                "INSERT INTO ip_abuse (ip, confidence_score, total_reports, checked_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(ip) DO UPDATE SET
                     confidence_score = excluded.confidence_score,
                     total_reports = excluded.total_reports,
                     checked_at = excluded.checked_at",
            )
            .bind(&[
                ip.into(),
                confidence_score.into(),
                total_reports.into(),
                checked_at.into(),
            ])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    async fn update_password_breached(&self, password: &str) -> Result<(), BruteError> {
        self.db
            .prepare("UPDATE top_password SET is_breached = 1 WHERE password = ?1")
            .bind(&[password.into()])
            .map_err(Self::map_err)?
            .run()
            .await
            .map(|_| ())
            .map_err(Self::map_err)
    }

    // ---- read operations ----

    async fn get_attacks(&self, limit: i64) -> Result<Vec<ProcessedIndividual>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM processed_individual ORDER BY timestamp DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results
            .results::<ProcessedIndividual>()
            .map_err(Self::map_err)
    }

    async fn get_top_username(&self, limit: i64) -> Result<Vec<TopUsername>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_username ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopUsername>().map_err(Self::map_err)
    }

    async fn get_top_password(&self, limit: i64) -> Result<Vec<TopPassword>, BruteError> {
        // TODO: SQLite doesn't support regex — filter X-masked passwords client-side or via LIKE
        let results = self.db
            .prepare("SELECT * FROM top_password WHERE password NOT LIKE 'XX%' ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopPassword>().map_err(Self::map_err)
    }

    async fn get_top_ip(&self, limit: i64) -> Result<Vec<TopIp>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_ip ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopIp>().map_err(Self::map_err)
    }

    async fn get_top_protocol(&self, limit: i64) -> Result<Vec<TopProtocol>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_protocol ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopProtocol>().map_err(Self::map_err)
    }

    async fn get_top_country(&self, limit: i64) -> Result<Vec<TopCountry>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_country ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopCountry>().map_err(Self::map_err)
    }

    async fn get_top_city(&self, limit: i64) -> Result<Vec<TopCity>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_city ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopCity>().map_err(Self::map_err)
    }

    async fn get_top_region(&self, limit: i64) -> Result<Vec<TopRegion>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_region ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopRegion>().map_err(Self::map_err)
    }

    async fn get_top_timezone(&self, limit: i64) -> Result<Vec<TopTimezone>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_timezone ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopTimezone>().map_err(Self::map_err)
    }

    async fn get_top_org(&self, limit: i64) -> Result<Vec<TopOrg>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_org ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopOrg>().map_err(Self::map_err)
    }

    async fn get_top_postal(&self, limit: i64) -> Result<Vec<TopPostal>, BruteError> {
        // TODO: SQLite GLOB can filter blank postals: WHERE postal NOT GLOB '[ ]*'
        let results = self.db
            .prepare("SELECT * FROM top_postal WHERE trim(postal) != '' ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopPostal>().map_err(Self::map_err)
    }

    async fn get_top_location(&self, limit: i64) -> Result<Vec<TopLocation>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_loc ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopLocation>().map_err(Self::map_err)
    }

    async fn get_top_combo(&self, limit: i64) -> Result<Vec<TopUsrPassCombo>, BruteError> {
        // TODO: filter X-masked passwords — use NOT LIKE 'XX%' as SQLite approximation
        let results = self.db
            .prepare("SELECT * FROM top_usr_pass_combo WHERE password NOT LIKE 'XX%' ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopUsrPassCombo>().map_err(Self::map_err)
    }

    async fn get_hourly(&self, limit: i64) -> Result<Vec<TopHourly>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_hourly ORDER BY timestamp DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopHourly>().map_err(Self::map_err)
    }

    async fn get_daily(&self, limit: i64) -> Result<Vec<TopDaily>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_daily ORDER BY timestamp DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopDaily>().map_err(Self::map_err)
    }

    async fn get_weekly(&self, limit: i64) -> Result<Vec<TopWeekly>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_weekly ORDER BY timestamp DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopWeekly>().map_err(Self::map_err)
    }

    async fn get_yearly(&self, limit: i64) -> Result<Vec<TopYearly>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_yearly ORDER BY timestamp DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopYearly>().map_err(Self::map_err)
    }

    async fn get_heatmap(&self) -> Result<Vec<HeatmapCell>, BruteError> {
        // SQLite equivalent: use strftime to extract day-of-week and hour
        let results = self.db
            .prepare(
                r#"SELECT
                    CAST(strftime('%w', timestamp / 1000, 'unixepoch') AS INTEGER) AS day_of_week,
                    CAST(strftime('%H', timestamp / 1000, 'unixepoch') AS INTEGER) AS hour_of_day,
                    COUNT(*) AS amount
                FROM processed_individual
                GROUP BY day_of_week, hour_of_day
                ORDER BY day_of_week, hour_of_day"#,
            )
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<HeatmapCell>().map_err(Self::map_err)
    }

    async fn get_velocity(&self, since: i64, limit: i64) -> Result<Vec<AttackVelocity>, BruteError> {
        let results = self.db
            .prepare(
                r#"SELECT
                    (timestamp / 60000) * 60000 AS minute_bucket,
                    COUNT(*) AS amount
                FROM processed_individual
                WHERE timestamp > ?1
                GROUP BY minute_bucket
                ORDER BY minute_bucket DESC
                LIMIT ?2"#,
            )
            .bind(&[since.into(), limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<AttackVelocity>().map_err(Self::map_err)
    }

    async fn get_summary(&self) -> Result<RollingStats, BruteError> {
        let total_result = self.db
            .prepare("SELECT COUNT(*) AS cnt FROM individual")
            .first::<serde_json::Value>(None)
            .await
            .map_err(Self::map_err)?;
        let total = total_result
            .and_then(|v| v.get("cnt").and_then(|n| n.as_i64()))
            .unwrap_or(0);

        let hour_result = self.db
            .prepare("SELECT amount FROM top_hourly ORDER BY timestamp DESC LIMIT 1")
            .first::<serde_json::Value>(None)
            .await
            .map_err(Self::map_err)?;
        let attacks_last_hour = hour_result
            .and_then(|v| v.get("amount").and_then(|n| n.as_i64()))
            .unwrap_or(0) as i32;

        let protocol_result = self.db
            .prepare("SELECT protocol FROM top_protocol ORDER BY amount DESC LIMIT 1")
            .first::<serde_json::Value>(None)
            .await
            .map_err(Self::map_err)?;
        let top_protocol = protocol_result
            .and_then(|v| v.get("protocol").and_then(|s| s.as_str()).map(|s| s.to_string()));

        let country_result = self.db
            .prepare("SELECT country FROM top_country ORDER BY amount DESC LIMIT 1")
            .first::<serde_json::Value>(None)
            .await
            .map_err(Self::map_err)?;
        let top_country = country_result
            .and_then(|v| v.get("country").and_then(|s| s.as_str()).map(|s| s.to_string()));

        Ok(RollingStats {
            total_attacks: total,
            attacks_last_hour,
            top_protocol,
            top_country,
        })
    }

    async fn get_subnet(&self, limit: i64) -> Result<Vec<TopSubnet>, BruteError> {
        // SQLite: use substr to extract the /24 subnet from IPv4 addresses
        // TODO: this only handles IPv4 addresses; IPv6 subnets need additional logic
        let results = self.db
            .prepare(
                r#"SELECT
                    substr(ip, 1, instr(ip, '.') + length(substr(ip, instr(ip, '.') + 1, instr(substr(ip, instr(ip, '.') + 1), '.') + 1))) || '0/24' AS subnet,
                    COUNT(*) AS amount
                FROM processed_individual
                WHERE ip LIKE '%.%.%.%'
                GROUP BY subnet
                ORDER BY amount DESC
                LIMIT ?1"#,
            )
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopSubnet>().map_err(Self::map_err)
    }

    async fn get_ip_seen(&self, limit: i64) -> Result<Vec<IpSeen>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM ip_seen ORDER BY total_sessions DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<IpSeen>().map_err(Self::map_err)
    }

    async fn get_ip_abuse(&self, limit: i64) -> Result<Vec<IpAbuse>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM ip_abuse ORDER BY confidence_score DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<IpAbuse>().map_err(Self::map_err)
    }

    async fn get_blocklist(&self, limit: i64) -> Result<Vec<TopIp>, BruteError> {
        let results = self.db
            .prepare("SELECT * FROM top_ip ORDER BY amount DESC LIMIT ?1")
            .bind(&[limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<TopIp>().map_err(Self::map_err)
    }

    async fn get_ip_seen_checked_at(&self, ip: &str) -> Result<Option<i64>, BruteError> {
        let result = self.db
            .prepare("SELECT checked_at FROM ip_abuse WHERE ip = ?1")
            .bind(&[ip.into()])
            .map_err(Self::map_err)?
            .first::<serde_json::Value>(None)
            .await
            .map_err(Self::map_err)?;
        Ok(result.and_then(|v| v.get("checked_at").and_then(|n| n.as_i64())))
    }

    async fn get_protocol_combo(
        &self,
        protocol: &str,
        limit: i64,
    ) -> Result<Vec<ProtocolCombo>, BruteError> {
        let results = self.db
            .prepare(
                r#"SELECT username, password, COUNT(*) AS amount
                   FROM individual
                   WHERE protocol = ?1
                   GROUP BY username, password
                   ORDER BY amount DESC
                   LIMIT ?2"#,
            )
            .bind(&[protocol.into(), limit.into()])
            .map_err(Self::map_err)?
            .all()
            .await
            .map_err(Self::map_err)?;
        results.results::<ProtocolCombo>().map_err(Self::map_err)
    }
}
