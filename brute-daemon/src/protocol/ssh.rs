//////////
// SSH //
////////
//////////////////////////////////////////////////////////////////////////////
// https://github.com/Eugeny/russh/blob/main/russh/examples/sftp_server.rs/ //
//////////////////////////////////////////////////////////////////////////////

use std::env;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use log::{info, LevelFilter};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_keys::key::KeyPair;
use tokio::sync::Mutex;

use crate::payload;

#[derive(Clone)]
pub struct Server;

impl russh::server::Server for Server {
    type Handler = SshSession;

    fn new_client(&mut self, client_ip: Option<SocketAddr>) -> Self::Handler {
        let mut ssh = SshSession::default();
        ssh.ip = client_ip;
        ssh
    }
}

pub struct SshSession {
    clients: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    ip: Option<SocketAddr>,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            ip: None,
        }
    }
}

#[async_trait]
impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    #[allow(unused_variables)]
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let binding = self.ip.unwrap();
        let mut ip = binding.ip().to_string();
        let endpoint = env::var("ADD_ATTACK_ENDPOINT")?;
        if !ip.eq("127.0.0.1") {
            info!("Recieved an auth request sending to {}", endpoint);
            payload::Payload::post(&user, &password, &ip, "SSH").await?;
        } else {
            info!("Recieved request but not sending because of debug. {}", endpoint);
        }
        Ok(Auth::Reject { proceed_with_methods: None })
    }

    #[allow(unused_variables)]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::UnsupportedMethod)
    }

    #[allow(unused_variables)]
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert(channel.id(), channel);
        }
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub async fn start_ssh_server() -> anyhow::Result<()> {
    let config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: None,
        keys: vec![KeyPair::generate_ed25519().unwrap()],
        ..Default::default()
    };

    let mut server = Server;

    info!("SSH server listening on port 22");
    server.run_on_address(
            Arc::new(config),
            (
                "0.0.0.0",
                std::env::var("PORT")
                    .unwrap_or("22".to_string())
                    .parse()
                    .unwrap(),
            ),
        )
        .await?;
    Ok(())
}
