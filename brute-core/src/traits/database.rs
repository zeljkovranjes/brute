use async_trait::async_trait;

use crate::error::BruteError;
use crate::model::{
    AttackVelocity, HeatmapCell, Individual, IpAbuse, IpSeen, ProcessedIndividual, ProtocolCombo,
    RollingStats, TopCity, TopCountry, TopDaily, TopHourly, TopIp, TopLocation, TopOrg,
    TopPassword, TopPostal, TopProtocol, TopRegion, TopSubnet, TopTimezone, TopUsername,
    TopUsrPassCombo, TopWeekly, TopYearly,
};

/// Core database trait that all backend implementations must satisfy.
///
/// Implemented by `PostgresDb` (brute-http) and `D1Db` (brute-worker).
#[async_trait]
pub trait BruteDb: Send + Sync {
    // ---- write operations ----

    async fn insert_individual(&self, individual: &Individual) -> Result<Individual, BruteError>;

    async fn insert_processed_individual(
        &self,
        processed: &ProcessedIndividual,
    ) -> Result<ProcessedIndividual, BruteError>;

    async fn upsert_top_username(&self, username: &str) -> Result<(), BruteError>;

    async fn upsert_top_password(&self, password: &str) -> Result<(), BruteError>;

    async fn upsert_top_ip(&self, ip: &str) -> Result<(), BruteError>;

    async fn upsert_top_protocol(&self, protocol: &str, amount: i32) -> Result<(), BruteError>;

    async fn upsert_top_country(&self, country: &str) -> Result<(), BruteError>;

    async fn upsert_top_city(&self, city: &str, country: &str) -> Result<(), BruteError>;

    async fn upsert_top_region(&self, region: &str, country: &str) -> Result<(), BruteError>;

    async fn upsert_top_timezone(&self, timezone: &str) -> Result<(), BruteError>;

    async fn upsert_top_org(&self, org: &str) -> Result<(), BruteError>;

    async fn upsert_top_postal(&self, postal: &str) -> Result<(), BruteError>;

    async fn upsert_top_location(&self, loc: &str) -> Result<(), BruteError>;

    async fn upsert_top_combo(
        &self,
        id: &str,
        username: &str,
        password: &str,
    ) -> Result<(), BruteError>;

    async fn update_ip_seen(&self, ip: &str, now: i64) -> Result<(), BruteError>;

    async fn update_attack_hourly(&self, now: i64) -> Result<(), BruteError>;

    async fn update_attack_daily(&self, now: i64) -> Result<(), BruteError>;

    async fn update_attack_weekly(&self, now: i64) -> Result<(), BruteError>;

    async fn update_attack_yearly(&self, now: i64) -> Result<(), BruteError>;

    async fn upsert_ip_abuse(
        &self,
        ip: &str,
        confidence_score: i32,
        total_reports: i32,
        checked_at: i64,
    ) -> Result<(), BruteError>;

    async fn update_password_breached(&self, password: &str) -> Result<(), BruteError>;

    // ---- read operations ----

    async fn get_attacks(&self, limit: i64) -> Result<Vec<ProcessedIndividual>, BruteError>;

    async fn get_top_username(&self, limit: i64) -> Result<Vec<TopUsername>, BruteError>;

    async fn get_top_password(&self, limit: i64) -> Result<Vec<TopPassword>, BruteError>;

    async fn get_top_ip(&self, limit: i64) -> Result<Vec<TopIp>, BruteError>;

    async fn get_top_protocol(&self, limit: i64) -> Result<Vec<TopProtocol>, BruteError>;

    async fn get_top_country(&self, limit: i64) -> Result<Vec<TopCountry>, BruteError>;

    async fn get_top_city(&self, limit: i64) -> Result<Vec<TopCity>, BruteError>;

    async fn get_top_region(&self, limit: i64) -> Result<Vec<TopRegion>, BruteError>;

    async fn get_top_timezone(&self, limit: i64) -> Result<Vec<TopTimezone>, BruteError>;

    async fn get_top_org(&self, limit: i64) -> Result<Vec<TopOrg>, BruteError>;

    async fn get_top_postal(&self, limit: i64) -> Result<Vec<TopPostal>, BruteError>;

    async fn get_top_location(&self, limit: i64) -> Result<Vec<TopLocation>, BruteError>;

    async fn get_top_combo(&self, limit: i64) -> Result<Vec<TopUsrPassCombo>, BruteError>;

    async fn get_hourly(&self, limit: i64) -> Result<Vec<TopHourly>, BruteError>;

    async fn get_daily(&self, limit: i64) -> Result<Vec<TopDaily>, BruteError>;

    async fn get_weekly(&self, limit: i64) -> Result<Vec<TopWeekly>, BruteError>;

    async fn get_yearly(&self, limit: i64) -> Result<Vec<TopYearly>, BruteError>;

    async fn get_heatmap(&self) -> Result<Vec<HeatmapCell>, BruteError>;

    async fn get_velocity(&self, since: i64, limit: i64) -> Result<Vec<AttackVelocity>, BruteError>;

    async fn get_summary(&self) -> Result<RollingStats, BruteError>;

    async fn get_subnet(&self, limit: i64) -> Result<Vec<TopSubnet>, BruteError>;

    async fn get_ip_seen(&self, limit: i64) -> Result<Vec<IpSeen>, BruteError>;

    async fn get_ip_abuse(&self, limit: i64) -> Result<Vec<IpAbuse>, BruteError>;

    async fn get_blocklist(&self, limit: i64) -> Result<Vec<TopIp>, BruteError>;

    async fn get_ip_seen_checked_at(&self, ip: &str) -> Result<Option<i64>, BruteError>;

    async fn get_protocol_combo(
        &self,
        protocol: &str,
        limit: i64,
    ) -> Result<Vec<ProtocolCombo>, BruteError>;
}
