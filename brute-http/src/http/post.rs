use std::net::{IpAddr, Ipv4Addr};

use actix_web::{post, web, HttpRequest, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::Deserialize;

use crate::{
    error::BruteResponeError,
    http::AppState,
    model::{Individual, TopProtocol},
    validator::{is_private_ip, validate_ip, Validate},
};

/////////////
/// POST ///
/////////////////////////
/// brute/attack/add ///
///////////////////////
#[derive(Deserialize)]
struct IndividualPayload {
    username: String,
    password: String,
    ip_address: String,
    protocol: String,
}
#[post("/attack/add")]
async fn post_brute_attack_add(
    state: web::Data<AppState>,
    payload: web::Json<IndividualPayload>,
    bearer: BearerAuth,
) -> Result<HttpResponse, BruteResponeError> {
    if !bearer.token().eq(&state.bearer) {
        return Ok(HttpResponse::Unauthorized().body("body"));
    }

    if payload.ip_address.eq("127.0.0.1") {
        return Err(BruteResponeError::ValidationError("empty ip or local ip".to_string()));
    }   

    let mut individual = Individual::new_short(
        payload.username.clone(),
        payload.password.clone(),
        payload.ip_address.clone(),
        payload.protocol.clone(),
    );
    individual.validate()?;
    match state.actor.send(individual).await {
        Ok(_) => Ok(HttpResponse::Ok().into()),
        Err(er) => Err(BruteResponeError::InternalError(er.to_string())),
    }
}

/////////////
/// POST ///
/////////////////////////////////
/// brute/protocol/increment ///
///////////////////////////////
#[derive(Deserialize)]
struct ProtocolPayload {
    protocol: String,
    amount: i32,
}
#[post("/protocol/increment")]
async fn post_brute_protocol_increment(
    state: web::Data<AppState>,
    payload: web::Json<ProtocolPayload>,
    bearer: BearerAuth,
) -> Result<HttpResponse, BruteResponeError> {
    if !bearer.token().eq(&state.bearer) {
        return Ok(HttpResponse::Unauthorized().body("body"));
    }

    let individual = TopProtocol::new(payload.protocol.clone(), payload.amount);
    match state.actor.send(individual).await {
        Ok(_) => Ok(HttpResponse::Ok().into()),
        Err(er) => Err(BruteResponeError::InternalError(er.to_string())),
    }
}

///////////////////////
/// HTTPS PROTOCOL ///
/////////////////////
/////////////
/// POST ///
////////////////////
/// auth/login ///
//////////////////
#[derive(Deserialize)]
struct FakeLoginPayload {
    username: String,
    password: String,
}

#[post("/login")]
async fn post_brute_fake_https_login(
    state: web::Data<AppState>,
    payload: web::Json<FakeLoginPayload>,
    req: HttpRequest
) -> Result<HttpResponse, BruteResponeError> {
    let conn = req.connection_info();
    let ip_address = conn.realip_remote_addr();
    if ip_address.is_none() {
        return Err(BruteResponeError::ValidationError("input validation error: ip_address is empty.".to_string()))
    }
    validate_ip(ip_address.unwrap())?;
    is_private_ip(ip_address.unwrap().parse::<IpAddr>().unwrap())?;

    let individual = Individual::new_short(
        payload.username.clone(),
        payload.password.clone(),
        ip_address.unwrap().to_string(),
        "HTTPS".to_string(),
    );

    match state.actor.send(individual).await {
        Ok(_) => Ok(HttpResponse::Ok().into()),
        Err(er) => Err(BruteResponeError::InternalError(er.to_string())),
    }
}

//////////////////////
/// HTTP PROTOCOL ///
////////////////////
#[post("/login")]
async fn post_brute_fake_http_login(
    state: web::Data<AppState>,
    payload: web::Json<FakeLoginPayload>,
    req: HttpRequest
) -> Result<HttpResponse, BruteResponeError> {
    let conn = req.connection_info();
    let ip_address = conn.realip_remote_addr();
    if ip_address.is_none() {
        return Err(BruteResponeError::ValidationError("input validation error: ip_address is empty.".to_string()))
    }
    validate_ip(ip_address.unwrap())?;
    is_private_ip(ip_address.unwrap().parse::<IpAddr>().unwrap())?;

    let individual = Individual::new_short(
        payload.username.clone(),
        payload.password.clone(),
        ip_address.unwrap().to_string(),
        "HTTP".to_string(),
    );

    match state.actor.send(individual).await {
        Ok(_) => Ok(HttpResponse::Ok().into()),
        Err(er) => Err(BruteResponeError::InternalError(er.to_string())),
    }
}