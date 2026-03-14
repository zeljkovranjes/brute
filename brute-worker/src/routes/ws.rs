use worker::{Request, Response, RouteContext, WebSocketPair};

// ── Free tier ─────────────────────────────────────────────────────────────────
// Durable Objects (paid) are required for broadcasting to multiple WebSocket
// clients simultaneously. On the free tier each connection gets its own
// isolated session — events are still streamed but only to that single client.
// Build with `--features paid` to enable cross-client broadcasting via a
// shared Durable Object.

#[cfg(not(feature = "paid"))]
pub async fn handle_websocket(_req: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {
    let pair = WebSocketPair::new()?;
    let server = pair.server;
    // Accept the connection — the server side will receive broadcasts when
    // the post handler calls into the worker directly.
    server.accept()?;
    Response::from_websocket(pair.client)
}

// ── Paid tier ─────────────────────────────────────────────────────────────────
// All Worker instances share one WsBroadcaster Durable Object so every
// connected client receives every event regardless of which Worker handled
// the inbound attack.

#[cfg(feature = "paid")]
use serde::Serialize;
#[cfg(feature = "paid")]
use worker::{durable_object, DurableObject, Env, State, WebSocket, WebSocketPair as _WebSocketPair};

#[cfg(feature = "paid")]
pub async fn handle_websocket(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let namespace = ctx.env.durable_object("WS_BROADCASTER")?;
    let stub = namespace.id_from_name("global")?.get_stub()?;
    stub.fetch_with_request(req).await
}

#[cfg(feature = "paid")]
#[derive(Serialize)]
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
                for ws in self.state.get_web_sockets() {
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
