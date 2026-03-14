//////////
// HTTP //
//////////
// Captures HTTP Basic Auth credentials and HTML form logins.

use std::collections::HashMap;
use std::env;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::info;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

const LOGIN_PAGE: &[u8] = br#"<!DOCTYPE html>
<html><head><title>Admin Login</title></head>
<body>
<h2>Admin Panel</h2>
<form method="POST" action="/login">
  <label>Username: <input name="username" type="text"></label><br>
  <label>Password: <input name="password" type="password"></label><br>
  <input type="submit" value="Login">
</form>
</body></html>"#;

fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                out.push(byte as char);
            }
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            Some((url_decode(k), url_decode(v)))
        })
        .collect()
}

async fn handle_client(stream: TcpStream, addr: std::net::SocketAddr) {
    let ip = addr.ip().to_string();
    if ip == "127.0.0.1" || ip == "::1" {
        return;
    }
    let endpoint = match env::var("ADD_ATTACK_ENDPOINT") {
        Ok(v) => v,
        Err(_) => return,
    };

    let (read_half, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    // Request line
    line.clear();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0].to_ascii_uppercase();

    // Headers
    let mut auth_header: Option<String> = None;
    let mut content_length: usize = 0;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            _ => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("authorization: basic ") {
            auth_header = Some(trimmed[21..].trim().to_string());
        } else if lower.starts_with("content-length: ") {
            content_length = trimmed[16..].trim().parse().unwrap_or(0);
        }
    }

    // Capture Basic Auth header
    if let Some(encoded) = auth_header {
        if let Ok(decoded) = STANDARD.decode(&encoded) {
            if let Ok(creds) = std::str::from_utf8(&decoded) {
                let mut it = creds.splitn(2, ':');
                let username = it.next().unwrap_or("").to_string();
                let password = it.next().unwrap_or("").to_string();
                if !username.is_empty() && !password.is_empty() {
                    info!("HTTP Basic Auth attempt from {} - sending to {}", ip, endpoint);
                    payload::post(&username, &password, &ip, "HTTP").await;
                }
            }
        }
    }

    // Capture POST form body
    if method == "POST" && content_length > 0 && content_length <= 8192 {
        let mut body = vec![0u8; content_length];
        if reader.read_exact(&mut body).await.is_ok() {
            if let Ok(body_str) = std::str::from_utf8(&body) {
                let form = parse_form(body_str);
                let username = form.get("username").or_else(|| form.get("user"))
                    .map(String::as_str).unwrap_or("").to_string();
                let password = form.get("password").or_else(|| form.get("pass"))
                    .map(String::as_str).unwrap_or("").to_string();
                if !username.is_empty() && !password.is_empty() {
                    info!("HTTP form login attempt from {} - sending to {}", ip, endpoint);
                    payload::post(&username, &password, &ip, "HTTP").await;
                }
            }
        }
    }

    // Always respond with 401 + login form
    let resp = format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: Basic realm=\"Admin Panel\"\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        LOGIN_PAGE.len()
    );
    let _ = writer.write_all(resp.as_bytes()).await;
    let _ = writer.write_all(LOGIN_PAGE).await;
}

async fn serve(port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    info!("HTTP server listening on port {}", port);
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("HTTP accept error on port {}: {}", port, e);
            }
        }
    }
}

pub async fn start_http_server() -> anyhow::Result<()> {
    let (a, b) = tokio::join!(serve(80), serve(8080));
    a.and(b)
}
