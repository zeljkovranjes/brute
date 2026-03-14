use worker::{Request, Response, RouteContext, WebSocketPair};

// ── Free tier ─────────────────────────────────────────────────────────────────
// Durable Objects (paid) are required for broadcasting to multiple WebSocket
// clients simultaneously. On the free tier each connection gets its own
// isolated session — events are still streamed but only to that single client.
// Build with `--features paid` to enable cross-client broadcasting via a
// shared Durable Object.

#[cfg(not(feature = "paid"))]
pub async fn handle_websocket(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    use crate::db::d1::D1Db;
    use brute_core::traits::database::BruteDb;

    let pair = WebSocketPair::new()?;
    let server = pair.server;
    server.accept()?;

    if let Ok(raw_db) = ctx.env.d1("worker_brute_d1") {
        let db = D1Db::new(raw_db);
        let ws = server.clone();

        wasm_bindgen_futures::spawn_local(async move {
            let mut last_ts = js_sys::Date::now() as i64;
            loop {
                worker::Delay::from(std::time::Duration::from_secs(2)).await;

                let attacks = match db.get_attacks(50).await {
                    Ok(a) => a,
                    Err(_) => continue,
                };

                let new_attacks: Vec<_> = attacks
                    .into_iter()
                    .filter(|a| a.timestamp > last_ts)
                    .collect();

                if let Some(newest) = new_attacks.iter().map(|a| a.timestamp).max() {
                    last_ts = newest;
                }

                for attack in new_attacks {
                    let msg = serde_json::json!({
                        "parse_type": "ProcessedIndividual",
                        "message": serde_json::to_string(&attack).unwrap_or_default()
                    });
                    if let Ok(text) = serde_json::to_string(&msg) {
                        if ws.send_with_str(&text).is_err() {
                            return; // client disconnected
                        }
                    }
                }
            }
        });
    }

    Response::from_websocket(pair.client)
}

// ── Paid tier ─────────────────────────────────────────────────────────────────
// All Worker instances share one WsBroadcaster Durable Object so every
// connected client receives every event regardless of which Worker handled
// the inbound attack.

#[cfg(feature = "paid")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "paid")]
use worker::{durable_object, DurableObject, Env, State, WebSocket};

#[cfg(feature = "paid")]
pub async fn handle_websocket(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let namespace = ctx.env.durable_object("WS_BROADCASTER")?;
    let stub = namespace.id_from_name("global")?.get_stub()?;
    stub.fetch_with_request(req).await
}

#[cfg(feature = "paid")]
#[derive(Serialize, Deserialize)]
struct BroadcastMessage {
    parse_type: String,
    message: String,
}

#[cfg(feature = "paid")]
#[durable_object]
pub struct WsBroadcaster {
    state: State,
    env: Env,
}

#[cfg(feature = "paid")]
impl DurableObject for WsBroadcaster {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let url = req.url()?;
        let path = url.path();

        match path {
            "/ws" => {
                let pair = WebSocketPair::new()?;
                let server = pair.server;
                self.state.accept_web_socket(&server);
                Response::from_websocket(pair.client)
            }
            "/internal/broadcast" => {
                let msg: BroadcastMessage = req.json().await?;
                let text = serde_json::to_string(&msg).unwrap_or_else(|_| "{}".to_string());
                for ws in self.state.get_websockets() {
                    ws.send_with_str(&text).ok();
                }
                Response::ok("broadcast sent")
            }
            _ => Response::error("Not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        _ws: WebSocket,
        _message: worker::WebSocketIncomingMessage,
    ) -> worker::Result<()> {
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> worker::Result<()> {
        ws.close(Some(1000), Some("bye"))?;
        Ok(())
    }

    async fn websocket_error(
        &self,
        _ws: WebSocket,
        _error: worker::Error,
    ) -> worker::Result<()> {
        Ok(())
    }
}
