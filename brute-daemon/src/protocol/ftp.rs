//////////
// FTP //
////////

use std::{env, fs};
use std::path::Path;

use libunftp::auth::*;
use libunftp::auth::{AuthenticationError, Authenticator};
use log::info;

use crate::payload;

#[derive(Debug)]
pub struct BruteAuthenticator;

#[async_trait::async_trait]
impl Authenticator<DefaultUser> for BruteAuthenticator {
    async fn authenticate(&self, username: &str, creds: &Credentials) -> Result<DefaultUser, AuthenticationError> {
        let endpoint = env::var("ADD_ATTACK_ENDPOINT").unwrap();
        let ip = creds.source_ip.to_string();

        if !username.is_empty() && creds.password.is_some() && !ip.eq_ignore_ascii_case("127.0.0.1") {
            info!("Recieved an auth request sending to {}", endpoint);
            payload::Payload::post(&username, &<std::option::Option<std::string::String> as Clone>::clone(&creds.password).unwrap(), &ip, "FTP").await.unwrap();
        }
        Err(AuthenticationError::BadUser)
    }
}

fn get_ftp_path() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "C:\\srv\\ftp"
    }
    // unix
    #[cfg(not(target_os = "windows"))]
    {
        "/srv/ftp"
    }
}

pub async fn start_ftp_server() -> anyhow::Result<()> {
    let path = Path::new(get_ftp_path());
    if !path.exists() {
        fs::create_dir_all(path).expect("Failed to create directory");
    }

    info!("FTP server listening on port 21");
    let server = libunftp::ServerBuilder::with_authenticator(
        Box::new(move || { unftp_sbe_fs::Filesystem::new(get_ftp_path())}),
        std::sync::Arc::new(BruteAuthenticator{})
    ).build().unwrap();
    server.listen("0.0.0.0:21").await?;
    Ok(())
}