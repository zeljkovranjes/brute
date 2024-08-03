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


/*
#[get("/attack/add")]
async fn post_brute_attack_add(
    actor: web::Data<Addr<BruteSystem>>,
) -> Result<HttpResponse, BruteResponeError> {
    let individual = Individual::new_short(
        payload.username.clone(),
        payload.password.clone(),
        payload.ip_address.clone(),
        payload.protocol.clone(),
    );
    individual.validate()?;
    match actor.send(individual).await {
        Ok(_) => Ok(HttpResponse::Ok().into()),
        Err(er) => Err(BruteResponeError::InternalError(er.to_string())),
    }
}
*/
/*
use std::{env::var, time::Duration};
use actix::Addr;
use axum::{
    error_handling::HandleErrorLayer, extract::Query, http::StatusCode, routing::get, Extension,
    Json, Router,
};
use serde::Deserialize;
use tower::{
    buffer::BufferLayer, limit::RateLimitLayer, BoxError, ServiceBuilder
};

use crate::{
    model::{ProcessedIndividual, TopCity, TopCountry, TopProtocol, TopRegion},
    system::{BruteSystem, RequestWithLimit},
};

pub fn get_router() -> Router {
    let rate_limit: u64 = var("RATE_LIMIT").unwrap().parse().unwrap();
    let rate_limit_duration: u64 = var("RATE_LIMIT_DURATION").unwrap().parse().unwrap();
    Router::new()
        .route("/attack", get(get_attacker))
        .route("/protocol", get(get_protocol))
        .route("/country", get(get_country))
        .route("/city", get(get_city))
        .route("/region", get(get_region))
    .layer(
        ServiceBuilder::new()
            // https://github.com/tokio-rs/axum/discussions/987
            .layer(HandleErrorLayer::new(|err: BoxError| async move {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Unhandled error: {}", err),
                )
            }))
            .layer(BufferLayer::new(1024))
            .layer(RateLimitLayer::new(rate_limit, Duration::from_secs(rate_limit_duration)),
    ))
}

#[derive(Debug, Deserialize)]
struct LimitParameter {
    limit: Option<usize>,
}

////////////
/// GET ///
//////////////////////////////////////////
/// brute/stats/attack?limit={amount} ///
////////////////////////////////////////
async fn get_attacker(
    Extension(actor): Extension<Addr<BruteSystem>>,
    Query(params): Query<LimitParameter>,
) -> Result<Json<Vec<ProcessedIndividual>>, StatusCode> {
    let limit = params.limit.unwrap_or(50);
    let mut request = RequestWithLimit {
        table: ProcessedIndividual::default(),
        limit,
        max_limit: 50,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match actor.send(request).await {
        Ok(result) => Ok(axum::Json(result?)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

////////////
/// GET ///
////////////////////////////////////////////
/// brute/stats/protocol?limit={amount} ///
//////////////////////////////////////////
async fn get_protocol(
    Extension(actor): Extension<Addr<BruteSystem>>,
    Query(params): Query<LimitParameter>,
) -> Result<Json<Vec<TopProtocol>>, StatusCode> {
    let limit = params.limit.unwrap_or(50);
    let mut request = RequestWithLimit {
        table: TopProtocol::default(),
        limit,
        max_limit: 50,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match actor.send(request).await {
        Ok(result) => Ok(Json(result?)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

////////////
/// GET ///
///////////////////////////////////////////
/// brute/stats/country?limit={amount} ///
/////////////////////////////////////////
async fn get_country(
    Extension(actor): Extension<Addr<BruteSystem>>,
    Query(params): Query<LimitParameter>,
) -> Result<Json<Vec<TopCountry>>, StatusCode> {
    let limit = params.limit.unwrap_or(50);
    let mut request = RequestWithLimit {
        table: TopCountry::default(),
        limit,
        max_limit: 50,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match actor.send(request).await {
        Ok(result) => Ok(Json(result?)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

////////////
/// GET ///
////////////////////////////////////////
/// brute/stats/city?limit={amount} ///
//////////////////////////////////////
async fn get_city(
    Extension(actor): Extension<Addr<BruteSystem>>,
    Query(params): Query<LimitParameter>,
) -> Result<Json<Vec<TopCity>>, StatusCode> {
    let limit = params.limit.unwrap_or(50);
    let mut request = RequestWithLimit {
        table: TopCity::default(),
        limit,
        max_limit: 50,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match actor.send(request).await {
        Ok(result) => Ok(Json(result?)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

////////////
/// GET ///
//////////////////////////////////////////
/// brute/stats/region?limit={amount} ///
////////////////////////////////////////
async fn get_region(
    Extension(actor): Extension<Addr<BruteSystem>>,
    Query(params): Query<LimitParameter>,
) -> Result<Json<Vec<TopRegion>>, StatusCode> {
    let limit = params.limit.unwrap_or(50);
    let mut request = RequestWithLimit {
        table: TopRegion::default(),
        limit,
        max_limit: 50,
    };
    if limit > request.max_limit {
        request.limit = request.max_limit;
    }
    match actor.send(request).await {
        Ok(result) => Ok(Json(result?)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
*/
