use brute_core::{
    model::Individual,
    traits::{
        analytics::BruteAnalytics,
        database::BruteDb,
        geo::GeoProvider,
    },
    validator::Validate,
};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use worker::{Env, Request, Response, RouteContext};

use crate::{
    analytics::engine::AnalyticsEngine,
    db::d1::D1Db,
    geo::{cf::CfGeoProvider, ipinfo::IpInfoProvider},
};

#[derive(Deserialize)]
struct IndividualPayload {
    username: String,
    password: String,
    ip_address: String,
    protocol: String,
}

#[derive(Deserialize)]
struct ProtocolPayload {
    protocol: String,
    amount: i32,
}

fn check_bearer(req: &Request, env: &Env) -> bool {
    let expected = env.var("BEARER_TOKEN").map(|v| v.to_string()).unwrap_or_default();
    if expected.is_empty() {
        return false;
    }
    req.headers()
        .get("Authorization")
        .ok()
        .flatten()
        .and_then(|h| h.strip_prefix("Bearer ").map(|t| t.to_string()))
        .map(|token| token == expected)
        .unwrap_or(false)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// POST /brute/attack/add
pub async fn add_attack(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let env = ctx.env;

    if !check_bearer(&req, &env) {
        return Response::error("Unauthorized", 401);
    }

    let payload: IndividualPayload = match req.json().await {
        Ok(p) => p,
        Err(e) => return Response::error(format!("Bad request: {}", e), 400),
    };

    if payload.ip_address == "127.0.0.1" {
        return Response::error("Validation error: local IP not allowed", 400);
    }

    let mut individual = Individual::new_short(
        payload.username,
        payload.password,
        payload.ip_address,
        payload.protocol,
    );

    if let Err(e) = individual.validate() {
        return Response::error(format!("Validation error: {}", e), 400);
    }

    // Build dependencies from Worker bindings
    let d1 = match env.d1("DB") {
        Ok(db) => D1Db::new(db),
        Err(e) => return Response::error(format!("DB binding error: {}", e), 500),
    };

    let analytics_ds = match env.analytics_engine("ANALYTICS") {
        Ok(ds) => AnalyticsEngine::new(ds),
        Err(e) => return Response::error(format!("Analytics binding error: {}", e), 500),
    };

    // Geo lookup — IPinfo first, Cloudflare cf object as fallback.
    //
    // Two ways to enable IPinfo:
    //   IPINFO_BASE_URL set → use that proxy (no token needed, proxy handles auth)
    //   IPINFO_TOKEN set    → use real https://ipinfo.io with that token
    // If neither is set, fall through to CF.
    let ipinfo_base_url = env.var("IPINFO_BASE_URL").map(|v| v.to_string()).unwrap_or_default();
    let ipinfo_token = env.var("IPINFO_TOKEN").map(|v| v.to_string()).unwrap_or_default();

    let geo_data = if !ipinfo_base_url.is_empty() || !ipinfo_token.is_empty() {
        let base_url = if !ipinfo_base_url.is_empty() {
            ipinfo_base_url
        } else {
            "https://ipinfo.io".to_string()
        };
        let ipinfo = IpInfoProvider::new(ipinfo_token, base_url);
        match ipinfo.lookup(&individual.ip).await {
            Ok(data) => data,
            Err(_) => {
                let cf = req.cf().cloned().unwrap_or_default();
                CfGeoProvider::new(cf).lookup(&individual.ip).await.unwrap_or_default()
            }
        }
    } else {
        let cf = req.cf().cloned().unwrap_or_default();
        CfGeoProvider::new(cf).lookup(&individual.ip).await.unwrap_or_default()
    };

    let now = now_ms();
    let new_id = Uuid::new_v4().as_simple().to_string();

    // Insert raw individual
    individual.id = new_id.clone();
    individual.timestamp = now;
    if let Err(e) = d1.insert_individual(&individual).await {
        return Response::error(format!("DB error: {}", e), 500);
    }

    // Build processed individual from geo data
    let processed = brute_core::model::ProcessedIndividual {
        id: Uuid::new_v4().as_simple().to_string(),
        username: individual.username.clone(),
        password: individual.password.clone(),
        ip: individual.ip.clone(),
        protocol: individual.protocol.clone(),
        hostname: geo_data.hostname,
        city: geo_data.city,
        region: geo_data.region,
        country: geo_data.country,
        loc: geo_data.loc,
        org: geo_data.org,
        postal: geo_data.postal,
        timezone: geo_data.timezone.unwrap_or_default(),
        asn: geo_data.asn,
        asn_name: geo_data.asn_name,
        asn_domain: geo_data.asn_domain,
        asn_route: geo_data.asn_route,
        asn_type: geo_data.asn_type,
        company_name: geo_data.company_name,
        company_domain: geo_data.company_domain,
        company_type: geo_data.company_type,
        vpn: geo_data.vpn,
        proxy: geo_data.proxy,
        tor: geo_data.tor,
        relay: geo_data.relay,
        hosting: geo_data.hosting,
        service: geo_data.service,
        abuse_address: geo_data.abuse_address,
        abuse_country: geo_data.abuse_country,
        abuse_email: geo_data.abuse_email,
        abuse_name: geo_data.abuse_name,
        abuse_network: geo_data.abuse_network,
        abuse_phone: geo_data.abuse_phone,
        domain_ip: geo_data.domain_ip,
        domain_total: geo_data.domain_total,
        domains: geo_data.domains,
        timestamp: now,
    };

    if let Err(e) = d1.insert_processed_individual(&processed).await {
        return Response::error(format!("DB error inserting processed: {}", e), 500);
    }

    // Update all aggregation tables
    let _ = d1.upsert_top_username(&individual.username).await;
    let _ = d1.upsert_top_password(&individual.password).await;
    let _ = d1.upsert_top_ip(&individual.ip).await;
    let _ = d1.upsert_top_protocol(&individual.protocol, 1).await;
    let _ = d1.update_ip_seen(&individual.ip, now).await;
    let _ = d1.update_attack_hourly(now).await;
    let _ = d1.update_attack_daily(now).await;
    let _ = d1.update_attack_weekly(now).await;
    let _ = d1.update_attack_yearly(now).await;

    if let Some(country) = &processed.country {
        let _ = d1.upsert_top_country(country).await;
    }
    if let (Some(city), Some(country)) = (&processed.city, &processed.country) {
        let _ = d1.upsert_top_city(city, country).await;
    }
    if let (Some(region), Some(country)) = (&processed.region, &processed.country) {
        let _ = d1.upsert_top_region(region, country).await;
    }
    if !processed.timezone.is_empty() {
        let _ = d1.upsert_top_timezone(&processed.timezone).await;
    }
    if let Some(org) = &processed.org {
        let _ = d1.upsert_top_org(org).await;
    }
    if let Some(postal) = &processed.postal {
        let _ = d1.upsert_top_postal(postal).await;
    }
    if let Some(loc) = &processed.loc {
        let _ = d1.upsert_top_location(loc).await;
    }

    let combo_id = Uuid::new_v4().as_simple().to_string();
    let _ = d1
        .upsert_top_combo(&combo_id, &individual.username, &individual.password)
        .await;

    // Record analytics event
    let _ = analytics_ds.record_attack_event(&individual, &processed).await;

    Response::ok("OK")
}

/// POST /brute/protocol/increment
pub async fn increment_protocol(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let env = ctx.env;

    if !check_bearer(&req, &env) {
        return Response::error("Unauthorized", 401);
    }

    let payload: ProtocolPayload = match req.json().await {
        Ok(p) => p,
        Err(e) => return Response::error(format!("Bad request: {}", e), 400),
    };

    let d1 = match env.d1("DB") {
        Ok(db) => D1Db::new(db),
        Err(e) => return Response::error(format!("DB binding error: {}", e), 500),
    };

    let analytics_ds = match env.analytics_engine("ANALYTICS") {
        Ok(ds) => AnalyticsEngine::new(ds),
        Err(e) => return Response::error(format!("Analytics binding error: {}", e), 500),
    };

    if let Err(e) = d1.upsert_top_protocol(&payload.protocol, payload.amount).await {
        return Response::error(format!("DB error: {}", e), 500);
    }

    let _ = analytics_ds.record_protocol_event(&payload.protocol, payload.amount).await;

    Response::ok("OK")
}
