//////////
// IMAP //
//////////

use std::env;

use log::info;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::payload;

/// Parse: `<tag> LOGIN <user> <pass>` with optional double-quote wrapping.
fn parse_imap_login(line: &str) -> Option<(String, String, String)> {
    let mut parts = line.splitn(4, ' ');
    let tag = parts.next()?.to_string();
    let cmd = parts.next()?;
    if !cmd.eq_ignore_ascii_case("LOGIN") {
        return None;
    }
    let rest = parts.next()?;

    fn unquote(s: &str) -> (&str, &str) {
        let s = s.trim_start();
        if s.starts_with('"') {
            if let Some(end) = s[1..].find('"') {
                return (&s[1..end + 1], s[end + 2..].trim_start());
            }
        }
        match s.find(' ') {
            Some(i) => (&s[..i], s[i..].trim_start()),
            None => (s, ""),
        }
    }
    let (user, remainder) = unquote(rest);
    let (pass, _) = unquote(remainder);
    if user.is_empty() || pass.is_empty() {
        return None;
    }
    Some((tag, user.to_string(), pass.to_string()))
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

    if writer
        .write_all(b"* OK IMAP4rev1 server ready\r\n")
        .await
        .is_err()
    {
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

        if upper.contains("LOGIN") {
            if let Some((tag, username, password)) = parse_imap_login(trimmed) {
                info!("IMAP LOGIN attempt from {} - sending to {}", ip, endpoint);
                payload::Payload::post(&username, &password, &ip, "IMAP").await.ok();
                let resp = format!(
                    "{} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n",
                    tag
                );
                let _ = writer.write_all(resp.as_bytes()).await;
                return;
            }
        } else if upper.contains("CAPABILITY") {
            let tag = trimmed.split_whitespace().next().unwrap_or("*");
            let _ = writer
                .write_all(b"* CAPABILITY IMAP4rev1 AUTH=LOGIN AUTH=PLAIN\r\n")
                .await;
            let resp = format!("{} OK CAPABILITY completed\r\n", tag);
            let _ = writer.write_all(resp.as_bytes()).await;
        } else if upper.contains("LOGOUT") {
            let tag = trimmed.split_whitespace().next().unwrap_or("*");
            let _ = writer.write_all(b"* BYE Logging out\r\n").await;
            let resp = format!("{} OK LOGOUT completed\r\n", tag);
            let _ = writer.write_all(resp.as_bytes()).await;
            return;
        } else {
            let tag = trimmed.split_whitespace().next().unwrap_or("*");
            let resp = format!("{} BAD Command not recognized\r\n", tag);
            let _ = writer.write_all(resp.as_bytes()).await;
        }
    }
}

pub async fn start_imap_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:143").await?;
    info!("IMAP server listening on port 143");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("IMAP accept error: {}", e);
            }
        }
    }
}

pub async fn start_imaps_server(acceptor: TlsAcceptor) -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:993").await?;
    info!("IMAPS server listening on port 993");
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
                log::error!("IMAPS accept error: {}", e);
            }
        }
    }
}
