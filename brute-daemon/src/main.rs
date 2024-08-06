use std::sync::Arc;

use libunftp::{Server, ServerBuilder};
use log::LevelFilter;
use protocol::ftp::start_ftp_server;
use protocol::ssh::start_ssh_server;

mod protocol;
mod payload;

//////////////////////////
// SUPPORTED PROTOCOLS //
////////////////////////
///////////////
// SSH, FTP //
/////////////

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
    .filter_level(LevelFilter::Trace)
    .filter_module("russh", LevelFilter::Off)
    .filter_module("libunftp", LevelFilter::Off)
    .init();

    #[cfg(debug_assertions)]
    dotenvy::dotenv().unwrap();
    
    let (ssh, ftp) = tokio::join!(
        start_ssh_server(),
        start_ftp_server()
    );

    ssh.unwrap();
    ftp.unwrap();
    Ok(())
}
