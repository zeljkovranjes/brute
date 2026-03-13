//////////
// MQTT //
//////////
// Captures credentials from MQTT CONNECT packets (v3.1, v3.1.1, v5.0).

use std::env;

use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

/// Decode the MQTT variable-length remaining-length field.
fn decode_varlen(data: &[u8], pos: &mut usize) -> Option<usize> {
    let mut value = 0usize;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() || shift > 21 {
            return None;
        }
        let byte = data[*pos] as usize;
        *pos += 1;
        value |= (byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Some(value)
}

/// Read a 2-byte length-prefixed UTF-8 string.
fn read_mqtt_str(data: &[u8], pos: &mut usize) -> Option<String> {
    if *pos + 2 > data.len() {
        return None;
    }
    let len = ((data[*pos] as usize) << 8) | (data[*pos + 1] as usize);
    *pos += 2;
    if *pos + len > data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[*pos..*pos + len]).to_string();
    *pos += len;
    Some(s)
}

/// Read a 2-byte length-prefixed binary field (used for passwords in v3.x).
fn read_mqtt_bin(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos + 2 > data.len() {
        return None;
    }
    let len = ((data[*pos] as usize) << 8) | (data[*pos + 1] as usize);
    *pos += 2;
    if *pos + len > data.len() {
        return None;
    }
    let bytes = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(bytes)
}

/// Skip a variable-length properties block (MQTT 5.0 only).
fn skip_properties(data: &[u8], pos: &mut usize) -> Option<()> {
    let props_len = decode_varlen(data, pos)?;
    *pos += props_len;
    if *pos > data.len() {
        return None;
    }
    Some(())
}

fn parse_connect(data: &[u8]) -> Option<(String, String)> {
    let mut pos = 0;

    // Protocol name (length-prefixed)
    let proto = read_mqtt_str(data, &mut pos)?;
    if proto != "MQTT" && proto != "MQIsdp" {
        return None;
    }

    // Protocol level
    if pos >= data.len() {
        return None;
    }
    let level = data[pos];
    pos += 1;

    // Connect flags
    if pos >= data.len() {
        return None;
    }
    let flags = data[pos];
    pos += 1;
    let has_will = flags & 0x04 != 0;
    let will_qos = (flags >> 3) & 0x03;
    let has_username = flags & 0x80 != 0;
    let has_password = flags & 0x40 != 0;

    // Keep-alive (2 bytes)
    pos += 2;
    if pos > data.len() {
        return None;
    }

    // MQTT 5.0: skip CONNECT properties
    if level == 5 {
        skip_properties(data, &mut pos)?;
    }

    // Payload: Client ID
    read_mqtt_str(data, &mut pos)?;

    // Will (if set)
    if has_will {
        if level == 5 {
            skip_properties(data, &mut pos)?;
        }
        read_mqtt_str(data, &mut pos)?; // will topic
        // will payload: binary in v3.x, also binary in v5.0
        read_mqtt_bin(data, &mut pos)?;
        let _ = will_qos; // suppress unused warning
    }

    // Username
    let username = if has_username {
        read_mqtt_str(data, &mut pos).unwrap_or_default()
    } else {
        return None; // no credentials to capture
    };

    // Password (binary in v3.x and v5.0)
    let password = if has_password {
        let bytes = read_mqtt_bin(data, &mut pos).unwrap_or_default();
        String::from_utf8_lossy(&bytes).to_string()
    } else {
        return None;
    };

    if username.is_empty() || password.is_empty() {
        return None;
    }

    Some((username, password))
}

/// CONNACK with "bad user name or password" for v3.x (code 4) or v5.0 (code 0x86).
fn build_connack(level: u8) -> Vec<u8> {
    if level == 5 {
        // MQTT 5.0 CONNACK: type=2, remaining=4, session=0, reason=0x86, props_len=0
        vec![0x20, 0x04, 0x00, 0x86, 0x00, 0x00]
    } else {
        // MQTT 3.x CONNACK: type=2, remaining=2, session=0, return=4
        vec![0x20, 0x02, 0x00, 0x04]
    }
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

    // Read fixed header (packet type + remaining length)
    let mut header = [0u8; 1];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let packet_type = header[0] >> 4;
    if packet_type != 1 {
        return; // Not a CONNECT packet
    }

    // Read remaining length (up to 4 bytes)
    let mut remaining_len = 0usize;
    let mut shift = 0u32;
    loop {
        let mut b = [0u8; 1];
        if stream.read_exact(&mut b).await.is_err() || shift > 21 {
            return;
        }
        remaining_len |= ((b[0] & 0x7F) as usize) << shift;
        shift += 7;
        if b[0] & 0x80 == 0 {
            break;
        }
    }

    if remaining_len == 0 || remaining_len > 65536 {
        return;
    }

    let mut body = vec![0u8; remaining_len];
    if stream.read_exact(&mut body).await.is_err() {
        return;
    }

    // Detect protocol level for CONNACK
    let level = if body.len() > 6 { body[6] } else { 4 };

    if let Some((username, password)) = parse_connect(&body) {
        info!("MQTT CONNECT attempt from {} - sending to {}", ip, endpoint);
        payload::Payload::post(&username, &password, &ip, "MQTT").await.ok();
    }

    let _ = stream.write_all(&build_connack(level)).await;
}

pub async fn start_mqtt_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:1883").await?;
    info!("MQTT server listening on port 1883");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("MQTT accept error: {}", e);
            }
        }
    }
}
