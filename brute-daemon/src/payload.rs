use std::env;

use reqwest::Client;
use serde::Serialize;

#[derive(Serialize)]
pub struct Payload {
    username: String,
    password: String,
    ip_address: String,
    protocol: String,
}

pub struct PayloadConfig {
    url: String,
    bearer_token: String,
}

impl Payload {
    pub fn new(
        username: String,
        password: String,
        ip_address: String,
        protocol: String,
        url: String,
        bearer_token: String,
    ) -> anyhow::Result<(Payload, PayloadConfig)> {
        //let client = Client::new();
        let payload = Payload {
            username: username,
            password: password,
            ip_address: ip_address,
            protocol: protocol,
        };

        let config = PayloadConfig {
            url: String::from(url),
            bearer_token: String::from(bearer_token),
        };
        Ok((payload, config))
    }

    pub async fn post(username: &str, password: &str, ip_address: &str, protocol: &str) -> anyhow::Result<()> {
        let url = env::var("ADD_ATTACK_ENDPOINT")?;
        let bearer_token = env::var("BEARER_TOKEN")?;
        let payload = Self::new(
            String::from(username),
            String::from(password),
            String::from(ip_address),
            String::from(protocol),
            url,
            bearer_token,
        )?;
        Self::create_post(payload.0, payload.1).await?;
        Ok(())
    }
    
    async fn create_post(payload: Payload, config: PayloadConfig) -> anyhow::Result<()> {
        let client = Client::new();
        client.post(&config.url).bearer_auth(&config.bearer_token).json(&payload).send().await?;
        Ok(())
    }
}
