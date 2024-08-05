use std::time::Instant;

use actix::Addr;
use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use actix_web_actors::ws;
use serde::Deserialize;

use crate::{
    http::{
        websocket::{BruteServer, BruteSession},
        AppState,
    },
    model::{
        ProcessedIndividual, TopCity, TopCountry, TopHourly, TopIp, TopLocation, TopOrg, TopPassword, TopPostal, TopProtocol, TopRegion, TopTimezone, TopUsername, TopUsrPassCombo
    },
    system::RequestWithLimit,
};

#[derive(Debug, Deserialize)]
struct LimitParameter {
    limit: Option<usize>,
}

static MAX_LIMIT: usize = 100;

////////////
/// GET ///
//////////////////////////////////////////
/// brute/stats/attack?limit={amount} ///
////////////////////////////////////////
#[get("/stats/attack")]
async fn get_brute_attackers(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: ProcessedIndividual::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
////////////////////////////////////////////
/// brute/stats/protocol?limit={amount} ///
//////////////////////////////////////////
#[get("/stats/protocol")]
async fn get_brute_protocol(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopProtocol::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
///////////////////////////////////////////
/// brute/stats/country?limit={amount} ///
/////////////////////////////////////////
#[get("/stats/country")]
async fn get_brute_country(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopCountry::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
////////////////////////////////////////
/// brute/stats/city?limit={amount} ///
//////////////////////////////////////
#[get("/stats/city")]
async fn get_brute_city(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopCity::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
//////////////////////////////////////////
/// brute/stats/region?limit={amount} ///
////////////////////////////////////////
#[get("/stats/region")]
async fn get_brute_region(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopRegion::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
////////////////////////////////////////////
/// brute/stats/username?limit={amount} ///
//////////////////////////////////////////
#[get("/stats/username")]
async fn get_brute_username(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopUsername::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
////////////////////////////////////////////
/// brute/stats/password?limit={amount} ///
//////////////////////////////////////////
#[get("/stats/password")]
async fn get_brute_password(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopPassword::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
//////////////////////////////////////
/// brute/stats/ip?limit={amount} ///
////////////////////////////////////
#[get("/stats/ip")]
async fn get_brute_ip(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopIp::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }

    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
//////////////////////////////////////
/// brute/stats/combo?limit={amount} ///
////////////////////////////////////
#[get("/stats/combo")]
async fn get_brute_usr_pass_combo(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopUsrPassCombo::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
////////////////////////////////////////////
/// brute/stats/timezone?limit={amount} ///
//////////////////////////////////////////
#[get("/stats/timezone")]
async fn get_brute_timezone(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopTimezone::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
//////////////////////////////////////
/// brute/stats/org?limit={amount} ///
//////////////////////////////////////
#[get("/stats/org")]
async fn get_brute_org(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopOrg::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
//////////////////////////////////////////
/// brute/stats/postal?limit={amount} ///
////////////////////////////////////////
#[get("/stats/postal")]
async fn get_brute_postal(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopPostal::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
///////////////////////////////////////
/// brute/stats/loc?limit={amount} ///
/////////////////////////////////////
#[get("/stats/loc")]
async fn get_brute_loc(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopLocation::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
//////////////////////////////////////////
/// brute/stats/hourly?limit={amount} ///
////////////////////////////////////////
#[get("/stats/hourly")]
async fn get_hourly(
    state: web::Data<AppState>,
    params: web::Query<LimitParameter>,
) -> impl Responder {
    // sorted by most recent.
    let limit = params.limit.unwrap_or(MAX_LIMIT);
    let mut request = RequestWithLimit {
        table: TopHourly::default(),
        limit,
        max_limit: MAX_LIMIT,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match state.actor.send(request).await {
        Ok(result) => HttpResponse::Ok().json(result.unwrap()),
        Err(er) => HttpResponse::Ok().body(format!("{}", er.to_string())),
    }
}

////////////
/// GET ///
/////////////////////////////////
/// ws://localhost:7000/ws   ///
/// wss://localhost:7443/ws ///
//////////////////////////////
#[get("/ws")]
#[allow(unused_variables)]
async fn get_websocket(
    req: HttpRequest,
    stream: web::Payload,
    srv: web::Data<Addr<BruteServer>>,
) -> Result<HttpResponse, actix_web::Error> {
    ws::start(
        BruteSession {
            id: String::default(),
            hb: Instant::now(),
            addr: srv.get_ref().clone(),
        },
        &req,
        stream,
    )
}
