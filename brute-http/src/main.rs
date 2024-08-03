use std::{env::var, fs::File, io::BufReader, path::Path};

use actix::Actor;
use brute_http::{config::Config, http::{serve, serve_tls}, system::BruteSystem};
use clap::Parser;
use ipinfo::{IpInfo, IpInfoConfig};
use log::info;
use sqlx::{migrate::Migrator, postgres::PgPoolOptions};

static CERTS_DIRECTORY: &str = "certs";

#[actix_rt::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing.");

    /////////////////////
    // ENV AND LOGGER //
    ///////////////////
    #[cfg(debug_assertions)]
    dotenvy::dotenv().unwrap();

    env_logger::builder()
        .filter_module("async_io", log::LevelFilter::Off)
        .filter_module("async_std", log::LevelFilter::Off)
        .filter_module("polling", log::LevelFilter::Off)
        .filter_module("tracing", log::LevelFilter::Off)
        .filter_module("sqlx", log::LevelFilter::Off)
        .filter_module("actix_server::worker", log::LevelFilter::Off)
        .filter_module("actix_http", log::LevelFilter::Off)
        .filter_module("mio::poll", log::LevelFilter::Off)
        .filter_module("rustls", log::LevelFilter::Off)
        .init();

    ////////////////////
    // ENV VARIABLES //
    //////////////////
    let listen_address = var("LISTEN_ADDRESS").expect("LISTEN_ADDRESS should be set");
    let listen_address_tls = var("LISTEN_ADDRESS_TLS").expect("LISTEN_ADDRESS_TLS should be set");
    let running_in_docker = var("RUNNING_IN_DOCKER").expect("RUNNING_IN_DOCKER should be set");
    let bearer_token = var("BEARER_TOKEN").expect("BEARER_TOKEN should be set");

    //////////
    // TLS //
    ////////
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let mut certs_file =
        BufReader::new(File::open(format!("{}/cert.pem", CERTS_DIRECTORY)).unwrap());
    let mut key_file = BufReader::new(File::open(format!("{}/key.pem", CERTS_DIRECTORY)).unwrap());

    let tls_certs = rustls_pemfile::certs(&mut certs_file)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tls_key = rustls_pemfile::pkcs8_private_keys(&mut key_file)
        .next()
        .unwrap()
        .unwrap();

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls_certs, rustls::pki_types::PrivateKeyDer::Pkcs8(tls_key))
        .unwrap();

    ///////////
    // CLAP //
    /////////
    let config = Config::parse();

    ///////////
    // SQLX //
    /////////
    let db = PgPoolOptions::new()
        .connect(&config.database_url)
        .await
        .map_err(|e| format!("Failed to connect to the database: {}", e))
        .unwrap();

    /////////////////////
    // SQLX MIGRATION //
    ///////////////////
    let migration_path = if running_in_docker.parse::<bool>().unwrap_or(false) {
        Path::new("migrations")
    } else {
        Path::new("..\\migrations\\")
    };

    Migrator::new(migration_path)
        .await
        .map_err(|e| format!("Failed to create migrator: {}", e))
        .unwrap()
        .run(&db)
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))
        .unwrap();

    info!("Migration process completed successfully.");

    /////////////
    // IPINFO //
    ///////////
    let ipinfo_config = IpInfoConfig {
        token: Some(config.ipinfo_token.to_string()),
        ..Default::default()
    };
    let ipinfo_client = IpInfo::new(ipinfo_config)
        .map_err(|e| format!("Failed to create IpInfo client: {}", e))
        .unwrap();

    ////////////
    // ACTOR //
    //////////
    let brute_system = BruteSystem::new_brute(db, ipinfo_client).await;
    let brute_actor = brute_system.start();

    ////////////////////////////////////
    // HTTP SERVER (TLS and NON-TLS) //
    //////////////////////////////////
    let (ip_tls, port_tls) = listen_address_tls
        .split_once(':')
        .expect("Invalid LISTEN_ADDRESS_TLS format. Expected format: IP:PORT");

    let (ip, port) = listen_address
        .split_once(':')
        .expect("Invalid LISTEN_ADDRESS format. Expected format: IP:PORT");

    let serve_tls_future = serve_tls(ip_tls, port_tls.parse::<u16>().unwrap(), brute_actor.clone(), tls_config, bearer_token.clone());
    let serve_future = serve(ip, port.parse::<u16>().unwrap(), brute_actor, bearer_token);
    tokio::try_join!(serve_tls_future, serve_future)?;
    Ok(())
}
