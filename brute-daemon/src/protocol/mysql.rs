///////////
// MySQL //
///////////
// Sends a MySQL protocol v10 initial handshake advertising the
// mysql_clear_password plugin, which causes compatible clients to transmit
// the password in plaintext.  Falls back to logging whatever auth bytes the
// client sends (as lossy UTF-8) when the client doesn't use the clear-text
// plugin.

use std::env;

use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

// Capability flags (32-bit LE split into two 16-bit halves)
const CAP_LONG_PASSWORD: u16     = 0x0001;
const CAP_PROTOCOL_41: u16       = 0x0200;
const CAP_SECURE_CONNECTION: u16 = 0x8000;
const CAP_HI_PLUGIN_AUTH: u16    = 0x0008; // CLIENT_PLUGIN_AUTH in upper half

fn wrap_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut pkt = vec![
        (len & 0xFF) as u8,
        ((len >> 8) & 0xFF) as u8,
        ((len >> 16) & 0xFF) as u8,
        seq,
    ];
    pkt.extend_from_slice(payload);
    pkt
}

fn initial_handshake() -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.push(10); // protocol version

    // Server version
    p.extend_from_slice(b"8.0.36\0");

    // Connection id
    p.extend_from_slice(&1u32.to_le_bytes());

    // Auth-plugin-data part 1 (8 bytes)
    let auth1 = b"\x52\x7a\x6b\x3c\x2d\x73\x7d\x5e";
    p.extend_from_slice(auth1);
    p.push(0x00); // filler

    // Capability flags (lower)
    let cap_lo = CAP_LONG_PASSWORD | CAP_PROTOCOL_41 | CAP_SECURE_CONNECTION;
    p.extend_from_slice(&cap_lo.to_le_bytes());

    p.push(0x21); // charset: utf8_general_ci
    p.extend_from_slice(&0x0002u16.to_le_bytes()); // status: SERVER_STATUS_AUTOCOMMIT

    // Capability flags (upper)
    p.extend_from_slice(&CAP_HI_PLUGIN_AUTH.to_le_bytes());

    p.push(21); // auth-plugin-data-len
    p.extend_from_slice(&[0u8; 10]); // reserved

    // Auth-plugin-data part 2 (13 bytes, last is null)
    p.extend_from_slice(b"\x6d\x41\x2d\x21\x79\x40\x3e\x5f\x4a\x6b\x3c\x4d\x00");

    // Plugin name
    p.extend_from_slice(b"mysql_clear_password\0");

    wrap_packet(0, &p)
}

fn error_packet(seq: u8) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.push(0xFF); // ERR marker
    p.extend_from_slice(&1045u16.to_le_bytes()); // ER_ACCESS_DENIED_ERROR
    p.push(b'#');
    p.extend_from_slice(b"28000");
    p.extend_from_slice(b"Access denied");
    wrap_packet(seq, &p)
}

/// Parse username and auth bytes from a protocol-41 HandshakeResponse.
fn parse_handshake_response(data: &[u8]) -> Option<(String, Vec<u8>)> {
    if data.len() < 32 {
        return None;
    }
    // Skip: cap(4) + max_packet(4) + charset(1) + reserved(23) = 32 bytes
    let mut pos = 32;

    // Username: null-terminated
    let user_end = data[pos..].iter().position(|&b| b == 0).map(|i| pos + i)?;
    let username = String::from_utf8_lossy(&data[pos..user_end]).to_string();
    pos = user_end + 1;

    if pos >= data.len() {
        return Some((username, vec![]));
    }

    // Auth response length (1 byte for secure connection mode)
    let auth_len = data[pos] as usize;
    pos += 1;

    let auth_bytes = if pos + auth_len <= data.len() {
        data[pos..pos + auth_len].to_vec()
    } else {
        vec![]
    };

    Some((username, auth_bytes))
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

    // Send server handshake
    if stream.write_all(&initial_handshake()).await.is_err() {
        return;
    }

    // Read client handshake response (4-byte header + payload)
    let mut header = [0u8; 4];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let len = (header[0] as usize)
        | ((header[1] as usize) << 8)
        | ((header[2] as usize) << 16);
    let seq = header[3];

    if len == 0 || len > 65536 {
        return;
    }

    let mut payload = vec![0u8; len];
    if stream.read_exact(&mut payload).await.is_err() {
        return;
    }

    if let Some((username, auth_bytes)) = parse_handshake_response(&payload) {
        if !username.is_empty() {
            // mysql_clear_password sends password + null byte
            let password = if auth_bytes.last() == Some(&0) && auth_bytes.len() > 1 {
                String::from_utf8_lossy(&auth_bytes[..auth_bytes.len() - 1]).to_string()
            } else {
                String::from_utf8_lossy(&auth_bytes).to_string()
            };
            info!("MySQL auth attempt from {} - sending to {}", ip, endpoint);
            payload::post(&username, &password, &ip, "MySQL").await;
        }
    }

    let _ = stream.write_all(&error_packet(seq + 1)).await;
}

pub async fn start_mysql_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:3306").await?;
    info!("MySQL server listening on port 3306");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("MySQL accept error: {}", e);
            }
        }
    }
}
