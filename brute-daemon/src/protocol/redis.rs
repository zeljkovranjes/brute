///////////
// Redis //
///////////

use std::env;

use log::info;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

/// Read a RESP bulk string (`$N\r\n<value>\r\n`) and return the value.
async fn read_bulk<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Option<String> {
    let mut line = String::new();
    reader.read_line(&mut line).await.ok()?;
    let trimmed = line.trim();
    trimmed.strip_prefix('$')?.parse::<usize>().ok()?;
    let mut value = String::new();
    reader.read_line(&mut value).await.ok()?;
    Some(value.trim().to_string())
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

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            _ => {}
        }

        let trimmed = line.trim().to_string();

        if let Some(count_str) = trimmed.strip_prefix('*') {
            // RESP array command
            let count: usize = match count_str.parse() {
                Ok(n) => n,
                Err(_) => return,
            };
            if count == 0 {
                continue;
            }

            let cmd = match read_bulk(&mut reader).await {
                Some(s) => s.to_ascii_uppercase(),
                None => return,
            };

            match (cmd.as_str(), count) {
                ("AUTH", 2) => {
                    let password = match read_bulk(&mut reader).await {
                        Some(s) => s,
                        None => return,
                    };
                    info!("Redis AUTH attempt from {} - sending to {}", ip, endpoint);
                    payload::post("default", &password, &ip, "Redis").await;
                    let _ = write_half
                        .write_all(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
                        .await;
                    return;
                }
                ("AUTH", 3) => {
                    let username = match read_bulk(&mut reader).await {
                        Some(s) => s,
                        None => return,
                    };
                    let password = match read_bulk(&mut reader).await {
                        Some(s) => s,
                        None => return,
                    };
                    info!("Redis AUTH attempt from {} - sending to {}", ip, endpoint);
                    payload::post(&username, &password, &ip, "Redis").await;
                    let _ = write_half
                        .write_all(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
                        .await;
                    return;
                }
                ("PING", _) => {
                    let _ = write_half.write_all(b"+PONG\r\n").await;
                    for _ in 1..count {
                        read_bulk(&mut reader).await;
                    }
                }
                _ => {
                    for _ in 1..count {
                        read_bulk(&mut reader).await;
                    }
                    let _ = write_half.write_all(b"-NOAUTH Authentication required.\r\n").await;
                }
            }
        } else {
            // Inline command
            let upper = trimmed.to_ascii_uppercase();
            if upper.starts_with("AUTH ") {
                let rest = trimmed[5..].trim();
                let mut parts = rest.splitn(2, ' ');
                let first = parts.next().unwrap_or("");
                let second = parts.next();
                let (username, password) = match second {
                    Some(p) => (first, p),
                    None => ("default", first),
                };
                info!("Redis AUTH attempt from {} - sending to {}", ip, endpoint);
                payload::post(username, password, &ip, "Redis").await;
                let _ = write_half
                    .write_all(b"-WRONGPASS invalid username-password pair or user is disabled.\r\n")
                    .await;
                return;
            } else if upper == "PING" {
                let _ = write_half.write_all(b"+PONG\r\n").await;
            } else {
                let _ = write_half.write_all(b"-NOAUTH Authentication required.\r\n").await;
            }
        }
    }
}

pub async fn start_redis_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:6379").await?;
    info!("Redis server listening on port 6379");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("Redis accept error: {}", e);
            }
        }
    }
}
