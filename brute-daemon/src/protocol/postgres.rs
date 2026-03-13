////////////////
// PostgreSQL //
////////////////
// Responds to StartupMessages with AuthenticationCleartextPassword (type 3),
// which causes connecting clients to send the password in plaintext.

use std::collections::HashMap;
use std::env;

use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

/// Parse key=value pairs from a PostgreSQL startup message payload.
/// Format after the 4-byte protocol version: null-terminated key/value pairs
/// terminated by an extra null byte.
fn parse_startup_params(data: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let parts: Vec<&[u8]> = data.split(|&b| b == 0).collect();
    let mut i = 0;
    while i + 1 < parts.len() {
        if parts[i].is_empty() {
            break;
        }
        let key = String::from_utf8_lossy(parts[i]).to_string();
        let val = String::from_utf8_lossy(parts[i + 1]).to_string();
        map.insert(key, val);
        i += 2;
    }
    map
}

/// Build an AuthenticationCleartextPassword message (R + 8 bytes + type 3).
fn auth_cleartext() -> Vec<u8> {
    let mut msg = vec![b'R'];
    msg.extend_from_slice(&8u32.to_be_bytes()); // length = 8 (includes itself)
    msg.extend_from_slice(&3u32.to_be_bytes()); // auth type: cleartext
    msg
}

/// Build an ErrorResponse that rejects the connection.
fn error_response(username: &str) -> Vec<u8> {
    let detail = format!(
        "Spassword authentication failed for user \"{}\"\0",
        username
    );
    let fields = format!("SFATAL\0C28P01\0M{}\0\0", detail);
    let len = (fields.len() + 4) as u32;
    let mut msg = vec![b'E'];
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(fields.as_bytes());
    msg
}

async fn handle_client(mut stream: TcpStream, addr: std::net::SocketAddr) {
    let ip = addr.ip().to_string();
    if ip == "127.0.0.1" || ip == "::1" {
        return;
    }
    let endpoint = match env::var("ADD_ATTACK_ENDPOINT") {
        Ok(v) => v,
        Err(_) => return,
    };

    // Read the 4-byte total length of the startup message
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).await.is_err() {
        return;
    }
    let total_len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check: must be at least 8 bytes (len + protocol version)
    if total_len < 8 || total_len > 65536 {
        return;
    }

    // Read the rest (total_len - 4 already-read bytes)
    let mut body = vec![0u8; total_len - 4];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }

    // First 4 bytes of body: protocol version
    let protocol = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);

    // SSLRequest (80877103) or CancelRequest (80877102) — ignore
    if protocol != 196608 {
        return;
    }

    let params = parse_startup_params(&body[4..]);
    let username = params.get("user").cloned().unwrap_or_default();

    if username.is_empty() {
        return;
    }

    // Ask for cleartext password
    if stream.write_all(&auth_cleartext()).await.is_err() {
        return;
    }

    // Read PasswordMessage: 'p' + 4-byte length + password + null
    let mut msg_type = [0u8; 1];
    if stream.read_exact(&mut msg_type).await.is_err() || msg_type[0] != b'p' {
        return;
    }

    let mut pw_len_buf = [0u8; 4];
    if stream.read_exact(&mut pw_len_buf).await.is_err() {
        return;
    }
    let pw_len = u32::from_be_bytes(pw_len_buf) as usize;

    // Length field includes itself (4 bytes), so payload = pw_len - 4
    if pw_len < 4 || pw_len > 4096 {
        return;
    }

    let mut pw_buf = vec![0u8; pw_len - 4];
    if stream.read_exact(&mut pw_buf).await.is_err() {
        return;
    }

    // Strip trailing null
    let password = String::from_utf8_lossy(
        pw_buf.strip_suffix(b"\0").unwrap_or(&pw_buf)
    )
    .to_string();

    if !password.is_empty() {
        info!("PostgreSQL auth attempt from {} - sending to {}", ip, endpoint);
        payload::Payload::post(&username, &password, &ip, "PostgreSQL").await.ok();
    }

    let _ = stream.write_all(&error_response(&username)).await;
}

pub async fn start_postgres_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:5432").await?;
    info!("PostgreSQL server listening on port 5432");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("PostgreSQL accept error: {}", e);
            }
        }
    }
}
