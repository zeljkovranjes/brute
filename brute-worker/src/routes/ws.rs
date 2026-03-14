use serde::Serialize;
use worker::{
    durable_object, js_sys, wasm_bindgen, wasm_bindgen_futures, Env, Request, Response,
    RouteContext, State, WebSocket, WebSocketPair,
};

/// Handle the initial WebSocket upgrade request.
/// Forwards the connection to the WsBroadcaster Durable Object.
pub async fn handle_websocket(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let namespace = ctx.env.durable_object("WS_BROADCASTER")?;
    // Use a single global instance so all connections share the same broadcaster
    let stub = namespace.id_from_name("global")?.get_stub()?;
    stub.fetch_with_request(req).await
}

#[derive(Serialize)]
struct BroadcastMessage {
    parse_type: String,
    message: String,
}

/// WsBroadcaster Durable Object.
///
/// Uses the Cloudflare hibernatable WebSocket API:
///   - `webSocketMessage` is called when a client sends a message
///   - `webSocketClose` / `webSocketError` handle disconnection
///   - `broadcast` is a custom method called via internal fetch from the worker
///
/// Since all Worker instances share one Durable Object, WebSocket connections
/// from both TLS and non-TLS clients are maintained in the same place.
#[durable_object]
pub struct WsBroadcaster {
    state: State,
    env: Env,
}

#[durable_object]
impl DurableObject for WsBroadcaster {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&mut self, mut req: Request) -> worker::Result<Response> {
        let url = req.url()?;
        let path = url.path();

        match path {
            // WebSocket upgrade endpoint — clients connect here
            "/ws" => {
                let pair = WebSocketPair::new()?;
                let server = pair.server;
                self.state.accept_web_socket(&server);
                Response::from_websocket(pair.client)
            }
            // Internal broadcast endpoint — called by the fetch handler
            "/internal/broadcast" => {
                let msg: BroadcastMessage = req.json().await?;
                let text = serde_json::to_string(&msg)
                    .unwrap_or_else(|_| "{}".to_string());
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
        // This is a unidirectional broadcast socket — clients don't send data.
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
