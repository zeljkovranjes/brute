use brute_core::traits::database::BruteDb;
use worker::{Request, Response, RouteContext};

use crate::db::d1::D1Db;

static MAX_LIMIT: i64 = 100;

fn parse_limit(req: &Request, default: i64, max: i64) -> i64 {
    req.url()
        .ok()
        .and_then(|u| {
            u.query_pairs()
                .find(|(k, _)| k == "limit")
                .and_then(|(_, v)| v.parse::<i64>().ok())
        })
        .unwrap_or(default)
        .min(max)
}

fn parse_str_param(req: &Request, key: &str) -> Option<String> {
    req.url().ok().and_then(|u| {
        u.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
    })
}

fn get_db(ctx: &RouteContext<()>) -> worker::Result<D1Db> {
    ctx.env.d1("worker_brute_d1").map(D1Db::new)
}

fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

/// GET /brute/stats/attack
pub async fn get_attacks(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_attacks(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/protocol
pub async fn get_protocol(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_protocol(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/country
pub async fn get_country(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, 195, 195);
    let db = get_db(&ctx)?;
    match db.get_top_country(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/city
pub async fn get_city(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_city(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/region
pub async fn get_region(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_region(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/username
pub async fn get_username(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_username(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/password
pub async fn get_password(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_password(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/ip
pub async fn get_ip(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_ip(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/combo
pub async fn get_combo(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_combo(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/timezone
pub async fn get_timezone(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_timezone(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/org
pub async fn get_org(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_org(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/postal
pub async fn get_postal(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_postal(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/loc
pub async fn get_loc(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_top_location(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/hourly
pub async fn get_hourly(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_hourly(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/daily
pub async fn get_daily(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_daily(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/weekly
pub async fn get_weekly(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_weekly(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/yearly
pub async fn get_yearly(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_yearly(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/heatmap
pub async fn get_heatmap(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let db = get_db(&ctx)?;
    match db.get_heatmap().await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/subnet
pub async fn get_subnet(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_subnet(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/velocity
pub async fn get_velocity(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, 60, MAX_LIMIT);
    let db = get_db(&ctx)?;
    let since = now_ms() - 3_600_000;
    match db.get_velocity(since, limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/ip/seen
pub async fn get_ip_seen(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_ip_seen(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/ip/abuse
pub async fn get_ip_abuse(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let db = get_db(&ctx)?;
    match db.get_ip_abuse(limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/summary
pub async fn get_summary(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let db = get_db(&ctx)?;
    match db.get_summary().await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/stats/combo/protocol
pub async fn get_protocol_combo(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, MAX_LIMIT, MAX_LIMIT);
    let protocol = match parse_str_param(&req, "protocol") {
        Some(p) => p,
        None => return Response::error("Missing 'protocol' query parameter", 400),
    };
    let db = get_db(&ctx)?;
    match db.get_protocol_combo(&protocol, limit).await {
        Ok(data) => Response::from_json(&data),
        Err(e) => Response::error(e.to_string(), 500),
    }
}

/// GET /brute/export/blocklist
pub async fn get_blocklist(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let limit = parse_limit(&req, 500, 500);
    let format = parse_str_param(&req, "format").unwrap_or_else(|| "plain".to_string());
    let db = get_db(&ctx)?;

    let ips = match db.get_blocklist(limit).await {
        Ok(data) => data,
        Err(e) => return Response::error(e.to_string(), 500),
    };

    let body = match format.as_str() {
        "iptables" => ips
            .iter()
            .map(|r| format!("-A INPUT -s {} -j DROP", r.ip))
            .collect::<Vec<_>>()
            .join("\n"),
        "nginx" => ips
            .iter()
            .map(|r| format!("deny {};", r.ip))
            .collect::<Vec<_>>()
            .join("\n"),
        "fail2ban" => ips
            .iter()
            .map(|r| format!("fail2ban-client set sshd banip {}", r.ip))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => ips.iter().map(|r| r.ip.as_str()).collect::<Vec<_>>().join("\n"),
    };

    Response::ok(body).map(|r| {
        let headers = worker::Headers::new();
        headers.set("Content-Type", "text/plain; charset=utf-8").ok();
        r.with_headers(headers)
    })
}
