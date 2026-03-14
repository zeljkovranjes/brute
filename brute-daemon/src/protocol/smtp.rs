//////////
// SMTP //
//////////

use std::env;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::info;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::payload;

fn b64_decode(s: &str) -> Option<String> {
    let bytes = STANDARD.decode(s.trim()).ok()?;
    String::from_utf8(bytes).ok()
}

async fn handle_client<S>(stream: S, addr: std::net::SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ip = addr.ip().to_string();
    if ip == "127.0.0.1" || ip == "::1" {
        return;
    }

    let endpoint = match env::var("ADD_ATTACK_ENDPOINT") {
        Ok(v) => v,
        Err(_) => return,
    };

    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    if writer.write_all(b"220 mail.brute.local ESMTP\r\n").await.is_err() {
        return;
    }

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            _ => {}
        }

        let trimmed = line.trim();
        let upper = trimmed.to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let _ = writer
                .write_all(b"250-mail.brute.local\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
                .await;
        } else if upper == "AUTH LOGIN" {
            // Base64("Username:")
            if writer.write_all(b"334 VXNlcm5hbWU6\r\n").await.is_err() {
                return;
            }
            line.clear();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let username = b64_decode(line.trim()).unwrap_or_default();

            // Base64("Password:")
            if writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await.is_err() {
                return;
            }
            line.clear();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let password = b64_decode(line.trim()).unwrap_or_default();

            if !username.is_empty() && !password.is_empty() {
                info!("SMTP AUTH LOGIN attempt from {} - sending to {}", ip, endpoint);
                payload::post(&username, &password, &ip, "SMTP").await;
            }
            let _ = writer
                .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                .await;
            return;
        } else if upper.starts_with("AUTH PLAIN") {
            let inline = trimmed.get(10..).map(str::trim).unwrap_or("").to_string();
            let credentials = if inline.is_empty() {
                if writer.write_all(b"334 \r\n").await.is_err() {
                    return;
                }
                line.clear();
                if reader.read_line(&mut line).await.is_err() {
                    return;
                }
                line.trim().to_string()
            } else {
                inline
            };

            if let Some(decoded) = b64_decode(&credentials) {
                let parts: Vec<&str> = decoded.split('\0').collect();
                let (username, password) = match parts.len() {
                    3 => (parts[1], parts[2]),
                    2 => (parts[0], parts[1]),
                    _ => ("", ""),
                };
                if !username.is_empty() && !password.is_empty() {
                    info!("SMTP AUTH PLAIN attempt from {} - sending to {}", ip, endpoint);
                    payload::post(username, password, &ip, "SMTP").await;
                }
            }
            let _ = writer
                .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                .await;
            return;
        } else if upper == "QUIT" {
            let _ = writer.write_all(b"221 Bye\r\n").await;
            return;
        } else {
            let _ = writer.write_all(b"502 Command not implemented\r\n").await;
        }
    }
}

pub async fn start_smtp_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:25").await?;
    info!("SMTP server listening on port 25");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("SMTP accept error: {}", e);
            }
        }
    }
}

pub async fn start_smtps_server(acceptor: TlsAcceptor) -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:465").await?;
    info!("SMTPS server listening on port 465");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        handle_client(tls, addr).await;
                    }
                });
            }
            Err(e) => {
                log::error!("SMTPS accept error: {}", e);
            }
        }
    }
}
