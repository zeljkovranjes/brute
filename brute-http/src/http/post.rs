use actix_web::{post, web, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use serde::Deserialize;

use crate::{
    error::BruteResponeError,
    http::AppState,
    model::{Individual, TopProtocol},
    validator::Validate,
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
