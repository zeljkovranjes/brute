use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;

use crate::{http::AppState, model::{ProcessedIndividual, TopCity, TopCountry, TopIp, TopOrg, TopPassword, TopPostal, TopProtocol, TopRegion, TopTimezone, TopUsername, TopUsrPassCombo}, system::RequestWithLimit};

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