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

mod protocol;
mod payload;

//////////////////////////
// SUPPORTED PROTOCOLS //
////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////
// SSH, FTP, Telnet, SMTP, POP3, IMAP, LDAP, Redis, HTTP/8080, MQTT, MySQL, PostgreSQL  //
////////////////////////////////////////////////////////////////////////////////////////////

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
    .filter_level(LevelFilter::Trace)
    .filter_module("russh", LevelFilter::Off)
    .filter_module("libunftp", LevelFilter::Off)
    .init();

    #[cfg(debug_assertions)]
    dotenvy::dotenv().unwrap();
    
    let (ssh, ftp, telnet, smtp, pop3, imap, ldap, redis, http, mqtt, mysql, postgres) = tokio::join!(
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
        start_postgres_server()
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
    Ok(())
}
