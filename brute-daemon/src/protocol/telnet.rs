////////////
// Telnet //
////////////

use std::env;

use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

const IAC: u8 = 0xFF;

/// Strip telnet IAC command sequences (IAC + cmd + option = 3 bytes).
fn strip_iac(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == IAC && i + 2 < data.len() {
            i += 3;
        } else if data[i] == IAC {
            i += 1;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
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

    // Negotiate echo/suppress-go-ahead + send banner
    let banner = b"\xff\xfd\x01\xff\xfd\x03\xff\xfc\x22\
                   Ubuntu 22.04.3 LTS\r\n\r\nlogin: ";
    if stream.write_all(banner).await.is_err() {
        return;
    }

    let mut buf = [0u8; 512];

    // Read username
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let username = String::from_utf8_lossy(&strip_iac(&buf[..n]))
        .trim()
        .replace(['\r', '\n'], "");

    if username.is_empty() {
        return;
    }

    if stream.write_all(b"Password: ").await.is_err() {
        return;
    }

    // Read password
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let password = String::from_utf8_lossy(&strip_iac(&buf[..n]))
        .trim()
        .replace(['\r', '\n'], "");

    if !password.is_empty() {
        info!("Telnet auth attempt from {} - sending to {}", ip, endpoint);
        payload::Payload::post(&username, &password, &ip, "Telnet").await.ok();
    }

    let _ = stream.write_all(b"\r\nLogin incorrect\r\n\r\n").await;
}

pub async fn start_telnet_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:23").await?;
    info!("Telnet server listening on port 23");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("Telnet accept error: {}", e);
            }
        }
    }
}
