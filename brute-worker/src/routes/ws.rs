use worker::{Request, Response, RouteContext};

// ── Free tier ─────────────────────────────────────────────────────────────────
// WebSocket broadcasting requires Durable Objects, which is a paid add-on.
// On the free tier this endpoint returns 501 so the rest of the worker still
// functions normally. Build with `--features paid` to enable WebSockets.

#[cfg(not(feature = "paid"))]
pub async fn handle_websocket(_req: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {
    Response::error(
        "WebSocket broadcasting requires the Cloudflare Durable Objects paid add-on. \
         Rebuild brute-worker with `--features paid` to activate it.",
        501,
    )
}

// ── Paid tier ─────────────────────────────────────────────────────────────────

#[cfg(feature = "paid")]
use serde::Serialize;
#[cfg(feature = "paid")]
use worker::{durable_object, js_sys, wasm_bindgen, wasm_bindgen_futures, Env, State, WebSocket, WebSocketPair};

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

/// WsBroadcaster Durable Object — only compiled when `paid` feature is active.
///
/// Uses the Cloudflare hibernatable WebSocket API so connections survive
/// Worker restarts without being dropped.
#[cfg(feature = "paid")]
#[durable_object]
pub struct WsBroadcaster {
    state: State,
    env: Env,
}

#[cfg(feature = "paid")]
#[durable_object]
impl DurableObject for WsBroadcaster {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&mut self, mut req: Request) -> worker::Result<Response> {
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

    async fn web_socket_message(
        &mut self,
        _ws: WebSocket,
        _message: worker::WebSocketIncomingMessage,
    ) -> worker::Result<()> {
        Ok(())
    }

    async fn web_socket_close(
        &mut self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> worker::Result<()> {
        ws.close(Some(1000), Some("bye"))?;
        Ok(())
    }

    async fn web_socket_error(
        &mut self,
        _ws: WebSocket,
        _error: worker::Error,
    ) -> worker::Result<()> {
        Ok(())
    }
}
