//////////
// IMAP //
//////////

use std::env;

use log::info;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

/// Parse: <tag> LOGIN <user> <pass>
/// Usernames and passwords may be quoted or unquoted.
fn parse_imap_login(line: &str) -> Option<(String, String, String)> {
    let mut parts = line.splitn(4, ' ');
    let tag = parts.next()?.to_string();
    let cmd = parts.next()?;
    if !cmd.eq_ignore_ascii_case("LOGIN") {
        return None;
    }
    let rest = parts.next()?;
    // Unquote a single token from the front of `s`
    fn unquote(s: &str) -> (&str, &str) {
        let s = s.trim_start();
        if s.starts_with('"') {
            if let Some(end) = s[1..].find('"') {
                return (&s[1..end + 1], s[end + 2..].trim_start());
            }
        }
        // unquoted: split on first space
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

async fn handle_client(stream: TcpStream, addr: std::net::SocketAddr) {
    let ip = addr.ip().to_string();
    if ip == "127.0.0.1" || ip == "::1" {
        return;
    }

    let endpoint = match env::var("ADD_ATTACK_ENDPOINT") {
        Ok(v) => v,
        Err(_) => return,
    };

    let (reader, mut writer) = stream.into_split();
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
