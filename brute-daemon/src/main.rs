use log::LevelFilter;
use protocol::ftp::start_ftp_server;
use protocol::ssh::start_ssh_server;
use protocol::telnet::start_telnet_server;
use protocol::smtp::start_smtp_server;
use protocol::pop3::start_pop3_server;

mod protocol;
mod payload;

//////////////////////////
// SUPPORTED PROTOCOLS //
////////////////////////
////////////////////////////////////
// SSH, FTP, Telnet, SMTP, POP3  //
//////////////////////////////////

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
    .filter_level(LevelFilter::Trace)
    .filter_module("russh", LevelFilter::Off)
    .filter_module("libunftp", LevelFilter::Off)
    .init();

    #[cfg(debug_assertions)]
    dotenvy::dotenv().unwrap();
    
    let (ssh, ftp, telnet, smtp, pop3) = tokio::join!(
        start_ssh_server(),
        start_ftp_server(),
        start_telnet_server(),
        start_smtp_server(),
        start_pop3_server()
    );

    ssh.unwrap();
    ftp.unwrap();
    telnet.unwrap();
    smtp.unwrap();
    pop3.unwrap();
    Ok(())
}
