use log::LevelFilter;
use protocol::ftp::start_ftp_server;
use protocol::ssh::start_ssh_server;
use protocol::telnet::start_telnet_server;
use protocol::smtp::start_smtp_server;
use protocol::pop3::start_pop3_server;
use protocol::imap::start_imap_server;
use protocol::ldap::start_ldap_server;
use protocol::redis::start_redis_server;
use protocol::http::start_http_server;
use protocol::mqtt::start_mqtt_server;
use protocol::mysql::start_mysql_server;
use protocol::postgres::start_postgres_server;
use protocol::smtp::start_smtps_server;
use protocol::imap::start_imaps_server;
use protocol::ldap::start_ldaps_server;
use protocol::tls::create_tls_acceptor;

mod protocol;
mod payload;

//////////////////////////
// SUPPORTED PROTOCOLS //
////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSH, FTP, Telnet, SMTP/SMTPS, POP3, IMAP/IMAPS, LDAP/LDAPS, Redis, HTTP/8080, MQTT, MySQL, PostgreSQL    //
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
    .filter_level(LevelFilter::Trace)
    .filter_module("russh", LevelFilter::Off)
    .filter_module("libunftp", LevelFilter::Off)
    .init();

    #[cfg(debug_assertions)]
    dotenvy::dotenv().unwrap();

    // Validate required env vars up front — panics with a clear message if
    // ADD_ATTACK_ENDPOINT or BEARER_TOKEN are missing or empty.
    payload::validate_config();

    let tls_acceptor = create_tls_acceptor().expect("Failed to create TLS acceptor");

    let (ssh, ftp, telnet, smtp, pop3, imap, ldap, redis, http, mqtt, mysql, postgres, smtps, imaps, ldaps) = tokio::join!(
        start_ssh_server(),
        start_ftp_server(),
        start_telnet_server(),
        start_smtp_server(),
        start_pop3_server(),
        start_imap_server(),
        start_ldap_server(),
        start_redis_server(),
        start_http_server(),
        start_mqtt_server(),
        start_mysql_server(),
        start_postgres_server(),
        start_smtps_server(tls_acceptor.clone()),
        start_imaps_server(tls_acceptor.clone()),
        start_ldaps_server(tls_acceptor.clone())
    );

    ssh.unwrap();
    ftp.unwrap();
    telnet.unwrap();
    smtp.unwrap();
    pop3.unwrap();
    imap.unwrap();
    ldap.unwrap();
    redis.unwrap();
    http.unwrap();
    mqtt.unwrap();
    mysql.unwrap();
    postgres.unwrap();
    smtps.unwrap();
    imaps.unwrap();
    ldaps.unwrap();
    Ok(())
}
