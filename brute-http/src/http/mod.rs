use std::any::Any;

use actix::{Actor, Addr};
use actix_cors::Cors;
use actix_web::{
    body::{BoxBody, EitherBody},
    dev::{ServiceFactory, ServiceRequest, ServiceResponse},
    http::header,
    web::{self, Data},
    App, HttpServer,
};
use get::{
    get_brute_attackers, get_brute_city, get_brute_country, get_brute_ip, get_brute_loc,
    get_brute_org, get_brute_password, get_brute_postal, get_brute_protocol, get_brute_region,
    get_brute_timezone, get_brute_username, get_brute_usr_pass_combo, get_websocket,
};
use log::info;
use post::{
    post_brute_attack_add, post_brute_fake_http_login, post_brute_fake_https_login,
    post_brute_protocol_increment,
};
use rustls::ServerConfig;
use websocket::BruteServer;

use crate::system::BruteSystem;

mod get;
mod post;

///////////////
// APPSTATE //
/////////////

#[derive(Clone)]
pub struct AppState {
    actor: Addr<BruteSystem>,
    bearer: String,
}

//////////////
// NON-TLS //
////////////

pub async fn serve(
    ip: &str,
    port: u16,
    brute_actor: Addr<BruteSystem>,
    bearer_token: String,
) -> anyhow::Result<()> {
    info!("Listening on {}:{}", ip, port);
    HttpServer::new(move || {
        configure_app(brute_actor.clone(), bearer_token.clone())
            .service(web::scope("auth").service(post_brute_fake_http_login))
            .service(get_websocket)
    })
    .bind((ip, port))?
    .run()
    .await?;
    Ok(())
}

//////////
// TLS //
////////

pub async fn serve_tls(
    ip: &str,
    port: u16,
    brute_actor: Addr<BruteSystem>,
    tls_config: ServerConfig,
    bearer_token: String,
) -> anyhow::Result<()> {
    info!("(TLS) Listening on {}:{}", ip, port);
    HttpServer::new(move || {
        configure_app(brute_actor.clone(), bearer_token.clone())
            .service(web::scope("auth").service(post_brute_fake_https_login))
    })
    .bind_rustls_0_23((ip, port), tls_config)?
    .run()
    .await?;
    Ok(())
}

////////////////
// CONFIGURE //
//////////////

fn configure_app(
    brute_actor: Addr<BruteSystem>,
    bearer_token: String,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<EitherBody<BoxBody>>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let cors = Cors::default()
        .allowed_origin_fn(|_origin, _request_head| true) // Allow all origins
        .allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
        ])
        .max_age(3600);

    App::new()
        .app_data(Data::new(AppState {
            actor: brute_actor,
            bearer: bearer_token,
        }))
        .wrap(cors)
        .app_data(web::Data::new(BruteServer.start()))
        .service(
            web::scope("brute")
                .service(post_brute_attack_add)
                .service(post_brute_protocol_increment)
                .service(get_brute_attackers)
                .service(get_brute_protocol)
                .service(get_brute_country)
                .service(get_brute_city)
                .service(get_brute_region)
                .service(get_brute_username)
                .service(get_brute_password)
                .service(get_brute_ip)
                .service(get_brute_usr_pass_combo)
                .service(get_brute_timezone)
                .service(get_brute_org)
                .service(get_brute_postal)
                .service(get_brute_loc),
        )
        .service(get_websocket)
}

///////////////////////////////
// UNIDIRECTIONAL WEBSOCKET //
/////////////////////////////

pub mod websocket {
    use std::{
        collections::HashMap,
        sync::Mutex,
        time::{Duration, Instant},
    };

    use actix::prelude::*;
    use actix_web_actors::ws::{self};
    use log::info;
    use once_cell::sync::Lazy;
    use serde::Serialize;

    #[derive(Clone, Serialize)]
    pub enum ParseType {
        Individual,
        ProcessedIndividual, // u can add more here...
                             // this is used so the client side knows
                             // how to parse the data.
    }

    // todo find another way of doing without using a static
    //
    // I used a static to help maintain a list of clients.
    // If I did it through instantiation it wouldn't increase
    // the client count.

    // Combine TLS + Non
    static CLIENTS: Lazy<Mutex<HashMap<String, Recipient<BruteMessage>>>> =
        Lazy::new(|| Mutex::new(HashMap::new()));

    /////////////
    // SERVER //
    ///////////

    #[derive(Message, Serialize)]
    #[rtype(result = "()")]
    pub struct BruteMessage {
        parse_type: ParseType,
        message: String,
    }

    impl BruteMessage {
        fn new<T: Serialize>(parse_type: ParseType, message: String) -> Self {
            Self {
                parse_type,
                message,
            }
        }
    }

    /// New chat session is created
    #[derive(Message)]
    #[rtype(String)]
    pub struct Connect {
        pub addr: Recipient<BruteMessage>,
    }

    /// Session is disconnected
    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct Disconnect {
        pub id: String,
    }

    #[derive(Debug)]
    pub struct BruteServer;

    impl BruteServer {
        pub fn broadcast<T: Serialize>(parse_type: ParseType, message: T) {
            for (_, session) in CLIENTS.lock().unwrap().clone().into_iter() {
                let message = BruteMessage::new::<T>(
                    parse_type.clone(),
                    serde_json::to_string(&message).unwrap(),
                );
                session.do_send(message)
            }
        }
    }

    impl Actor for BruteServer {
        type Context = Context<Self>;
    }

    impl Handler<Connect> for BruteServer {
        type Result = String;

        fn handle(&mut self, msg: Connect, _: &mut Self::Context) -> Self::Result {
            let id = uuid::Uuid::new_v4().as_simple().to_string();
            CLIENTS.lock().unwrap().insert(id.clone(), msg.addr);
            info!("New connection joined. with the id {:?}", id);
            id
        }
    }

    impl Handler<Disconnect> for BruteServer {
        type Result = ();

        fn handle(&mut self, msg: Disconnect, _: &mut Self::Context) -> Self::Result {
            if CLIENTS.lock().unwrap().remove(&msg.id).is_some() {
                info!("{} has disconnected", msg.id);
            }
        }
    }

    /////////////
    // CLIENT //
    ///////////

    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

    const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

    pub struct BruteSession {
        pub id: String,
        pub hb: Instant,
        pub addr: Addr<BruteServer>,
    }

    impl BruteSession {
        fn hb(&self, ctx: &mut ws::WebsocketContext<Self>) {
            ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
                // check client heartbeats
                if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                    // heartbeat timed out
                    println!("Websocket Client heartbeat failed, disconnecting!");

                    act.addr.do_send(Disconnect { id: act.id.clone() });

                    ctx.stop();

                    // don't try to send a ping
                    return;
                }

                ctx.ping(b"");
            });
        }
    }

    impl Handler<BruteMessage> for BruteSession {
        type Result = ();

        fn handle(&mut self, msg: BruteMessage, ctx: &mut Self::Context) {
            ctx.text(serde_json::to_string(&msg).unwrap());
        }
    }

    impl Actor for BruteSession {
        type Context = ws::WebsocketContext<Self>;

        fn started(&mut self, ctx: &mut Self::Context) {
            self.hb(ctx);

            let addr = ctx.address();
            self.addr
                .send(Connect {
                    addr: addr.recipient(),
                })
                .into_actor(self)
                .then(|res, act, ctx| {
                    match res {
                        Ok(res) => act.id = res,
                        _ => ctx.stop(),
                    }
                    fut::ready(())
                })
                .wait(ctx);
        }

        fn stopping(&mut self, _: &mut Self::Context) -> Running {
            // notify chat server
            self.addr.do_send(Disconnect {
                id: self.id.clone(),
            });
            Running::Stop
        }
    }

    impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for BruteSession {
        fn handle(
            &mut self,
            item: Result<ws::Message, ws::ProtocolError>,
            ctx: &mut Self::Context,
        ) {
            let item = match item {
                Err(_) => {
                    ctx.stop();
                    return;
                }
                Ok(item) => item,
            };
            // log::debug!("WEBSOCKET MESSAGE: {item:?}");

            match item {
                ws::Message::Text(_) => (),
                ws::Message::Binary(_) => println!("Unexpected binary"),
                ws::Message::Continuation(_) => {
                    ctx.stop();
                }
                ws::Message::Ping(msg) => {
                    self.hb = Instant::now();
                    ctx.pong(&msg);
                }
                ws::Message::Pong(_) => {
                    self.hb = Instant::now();
                }
                ws::Message::Close(reason) => {
                    ctx.close(reason);
                    ctx.stop();
                }
                ws::Message::Nop => (),
            }
        }
    }
}
