use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;

use crate::{http::AppState, model::{ProcessedIndividual, TopCity, TopCountry, TopProtocol, TopRegion}, system::RequestWithLimit};

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