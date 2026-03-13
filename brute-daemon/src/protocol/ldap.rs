//////////
// LDAP //
//////////
// Parses LDAP BindRequest (RFC 4511) encoded in ASN.1 BER.
// Only Simple authentication (plaintext password) is captured.

use std::env;

use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::payload;

/// Decode a BER length field starting at `pos`, advancing `pos` past it.
fn read_ber_len(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() {
        return None;
    }
    let first = data[*pos] as usize;
    *pos += 1;
    if first & 0x80 == 0 {
        Some(first)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 || *pos + n > data.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | data[*pos] as usize;
            *pos += 1;
        }
        Some(len)
    }
}

/// Try to parse a Simple BindRequest from a raw LDAP PDU.
/// Returns (messageId, dn, password) on success.
fn parse_bind_request(data: &[u8]) -> Option<(u8, String, String)> {
    let mut p = 0;

    // LDAPMessage ::= SEQUENCE
    if data.get(p)? != &0x30 {
        return None;
    }
    p += 1;
    let _msg_len = read_ber_len(data, &mut p)?;

    // messageID ::= INTEGER
    if data.get(p)? != &0x02 {
        return None;
    }
    p += 1;
    let id_len = read_ber_len(data, &mut p)?;
    if p + id_len > data.len() {
        return None;
    }
    let message_id = *data.get(p)? as u8; // only need the LSB for the response
    p += id_len;

    // BindRequest ::= [APPLICATION 0] SEQUENCE  (tag 0x60)
    if data.get(p)? != &0x60 {
        return None;
    }
    p += 1;
    let _br_len = read_ber_len(data, &mut p)?;

    // version ::= INTEGER (must be 3)
    if data.get(p)? != &0x02 {
        return None;
    }
    p += 1;
    let ver_len = read_ber_len(data, &mut p)?;
    p += ver_len;

    // name ::= LDAPDN (OCTET STRING, tag 0x04)
    if data.get(p)? != &0x04 {
        return None;
    }
    p += 1;
    let dn_len = read_ber_len(data, &mut p)?;
    if p + dn_len > data.len() {
        return None;
    }
    let dn = String::from_utf8_lossy(&data[p..p + dn_len]).to_string();
    p += dn_len;

    // authentication ::= simple [0] IMPLICIT OCTET STRING  (tag 0x80)
    if data.get(p)? != &0x80 {
        return None; // SASL or empty — skip
    }
    p += 1;
    let pw_len = read_ber_len(data, &mut p)?;
    if p + pw_len > data.len() {
        return None;
    }
    let password = String::from_utf8_lossy(&data[p..p + pw_len]).to_string();

    Some((message_id, dn, password))
}

/// Build an LDAP BindResponse with resultCode 49 (invalidCredentials).
fn build_bind_error(message_id: u8) -> Vec<u8> {
    let diag = b"Invalid credentials";
    // BindResponse inner: ENUMERATED(49), OCTET STRING(""), OCTET STRING(diag)
    let mut inner: Vec<u8> = vec![
        0x0a, 0x01, 49,            // resultCode ENUMERATED = 49
        0x04, 0x00,                // matchedDN = ""
        0x04, diag.len() as u8,   // diagnosticMessage
    ];
    inner.extend_from_slice(diag);

    // [APPLICATION 1] = BindResponse
    let mut bind_resp: Vec<u8> = vec![0x61, inner.len() as u8];
    bind_resp.extend_from_slice(&inner);

    // LDAPMessage wrapping
    let mut msg_inner: Vec<u8> = vec![0x02, 0x01, message_id];
    msg_inner.extend_from_slice(&bind_resp);

    let mut pdu: Vec<u8> = vec![0x30, msg_inner.len() as u8];
    pdu.extend_from_slice(&msg_inner);
    pdu
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

    let mut buf = vec![0u8; 4096];

    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };

        if let Some((msg_id, dn, password)) = parse_bind_request(&buf[..n]) {
            if !dn.is_empty() && !password.is_empty() {
                info!("LDAP bind attempt from {} - sending to {}", ip, endpoint);
                payload::Payload::post(&dn, &password, &ip, "LDAP").await.ok();
            }
            let response = build_bind_error(msg_id);
            let _ = stream.write_all(&response).await;
            return;
        }
        // Unknown message — drop connection
        return;
    }
}

pub async fn start_ldap_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:389").await?;
    info!("LDAP server listening on port 389");
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(handle_client(stream, addr));
            }
            Err(e) => {
                log::error!("LDAP accept error: {}", e);
            }
        }
    }
}
