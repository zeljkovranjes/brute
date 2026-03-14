use worker::*;

mod abuse;
mod analytics;
mod cron;
mod db;
mod geo;
mod routes;

#[allow(unused_must_use)]
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) -> Result<()> {
    cron::retention::run(&env).await
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Log every request in debug builds
    #[cfg(debug_assertions)]
    console_log!(
        "{} {}",
        req.method().to_string(),
        req.url().map(|u| u.to_string()).unwrap_or_default()
    );

    let router = Router::new();

    router
        // Attack ingestion
        .post_async("/brute/attack/add", routes::post::add_attack)
        .post_async("/brute/protocol/increment", routes::post::increment_protocol)
        // Stats — processed individual
        .get_async("/brute/stats/attack", routes::get::get_attacks)
        // Stats — top aggregations
        .get_async("/brute/stats/protocol", routes::get::get_protocol)
        .get_async("/brute/stats/country", routes::get::get_country)
        .get_async("/brute/stats/city", routes::get::get_city)
        .get_async("/brute/stats/region", routes::get::get_region)
        .get_async("/brute/stats/username", routes::get::get_username)
        .get_async("/brute/stats/password", routes::get::get_password)
        .get_async("/brute/stats/ip", routes::get::get_ip)
        .get_async("/brute/stats/combo", routes::get::get_combo)
        .get_async("/brute/stats/timezone", routes::get::get_timezone)
        .get_async("/brute/stats/org", routes::get::get_org)
        .get_async("/brute/stats/postal", routes::get::get_postal)
        .get_async("/brute/stats/loc", routes::get::get_loc)
        // Stats — time-series
        .get_async("/brute/stats/hourly", routes::get::get_hourly)
        .get_async("/brute/stats/daily", routes::get::get_daily)
        .get_async("/brute/stats/weekly", routes::get::get_weekly)
        .get_async("/brute/stats/yearly", routes::get::get_yearly)
        .get_async("/brute/stats/heatmap", routes::get::get_heatmap)
        // Stats — network / advanced
        .get_async("/brute/stats/subnet", routes::get::get_subnet)
        .get_async("/brute/stats/velocity", routes::get::get_velocity)
        .get_async("/brute/stats/ip/seen", routes::get::get_ip_seen)
        .get_async("/brute/stats/ip/abuse", routes::get::get_ip_abuse)
        .get_async("/brute/stats/summary", routes::get::get_summary)
        .get_async("/brute/stats/combo/protocol", routes::get::get_protocol_combo)
        // Export
        .get_async("/brute/export/blocklist", routes::get::get_blocklist)
        // WebSocket
        .get_async("/ws", routes::ws::handle_websocket)
        .run(req, env)
        .await
}
