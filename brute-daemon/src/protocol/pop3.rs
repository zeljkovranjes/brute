//////////
// POP3 //
//////////

use std::env;

use log::info;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

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
    let mut username = String::new();

    if writer.write_all(b"+OK POP3 server ready\r\n").await.is_err() {
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

        if upper.starts_with("USER ") {
            username = trimmed[5..].to_string();
            let _ = writer.write_all(b"+OK\r\n").await;
        } else if upper.starts_with("PASS ") {
            let password = trimmed[5..].to_string();
            if !username.is_empty() && !password.is_empty() {
                info!("POP3 auth attempt from {} - sending to {}", ip, endpoint);
                payload::Payload::post(&username, &password, &ip, "POP3").await.ok();
            }
            let _ = writer.write_all(b"-ERR Invalid credentials\r\n").await;
            return;
        } else if upper == "QUIT" {
            let _ = writer.write_all(b"+OK Bye\r\n").await;
            return;
        } else if upper == "CAPA" {
            let _ = writer.write_all(b"+OK\r\nUSER\r\n.\r\n").await;
        } else {
            let _ = writer.write_all(b"-ERR Unknown command\r\n").await;
        }
    }
}

pub async fn start_pop3_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:110").await?;
    info!("POP3 server listening on port 110");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("POP3 accept error: {}", e);
            }
        }
    }
}
