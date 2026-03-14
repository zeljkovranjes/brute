use std::{env::var, fs::File, io::BufReader, path::Path};

use actix::Actor;
use brute_http::{config::Config, geo::ipinfo::IpInfoProvider, http::{serve, serve_tls}, system::BruteSystem};
use clap::Parser;
use log::info;
use sqlx::{migrate::Migrator, postgres::{PgConnectOptions, PgPoolOptions}, Connection, PgConnection};

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

    let tls_config = File::open(format!("{}/cert.pem", CERTS_DIRECTORY))
        .ok()
        .and_then(|cert_file| File::open(format!("{}/key.pem", CERTS_DIRECTORY)).ok().map(|kf| (cert_file, kf)))
        .and_then(|(cert_file, key_file)| {
            let mut certs_reader = BufReader::new(cert_file);
            let mut key_reader = BufReader::new(key_file);
            let certs = rustls_pemfile::certs(&mut certs_reader).collect::<Result<Vec<_>, _>>().ok()?;
            let key_bytes = std::fs::read(format!("{}/key.pem", CERTS_DIRECTORY)).ok()?;
            let key = rustls_pemfile::private_key(&mut key_bytes.as_slice()).ok()??;
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| { log::error!("TLS config error: {:?}", e); e })
                .ok()
        });

    ///////////
    // CLAP //
    /////////
    let config = Config::parse();

    ///////////
    // SQLX //
    /////////
    let db = PgPoolOptions::new()
        .after_connect(|conn, _| Box::pin(async move {
            sqlx::query("DEALLOCATE ALL").execute(conn).await?;
            Ok(())
        }))
        .connect_with(
            config.database_url.parse::<sqlx::postgres::PgConnectOptions>()
                .unwrap()
                .statement_cache_capacity(0),
        )
        .await
        .map_err(|e| format!("Failed to connect to the database: {}", e))
        .unwrap();

    /////////////////////
    // SQLX MIGRATION //
    ///////////////////
    let migration_path = if running_in_docker.parse::<bool>().unwrap_or(false) {
        Path::new("migrations/postgres")
    } else {
        Path::new("../migrations/postgres")
    };

    let pg_opts = config.database_url.parse::<PgConnectOptions>().unwrap().statement_cache_capacity(0);
    let migrator = Migrator::new(migration_path)
        .await
        .map_err(|e| format!("Failed to create migrator: {}", e))
        .unwrap();

    loop {
        let mut migration_conn = PgConnection::connect_with(&pg_opts)
            .await
            .map_err(|e| format!("Failed to connect for migrations: {}", e))
            .unwrap();
        sqlx::query("DEALLOCATE ALL").execute(&mut migration_conn).await.ok();
        match migrator.run(&mut migration_conn).await {
            Ok(_) => break,
            Err(e) if e.to_string().contains("already exists") => {
                log::warn!("Prepared statement conflict during migration, retrying...");
                continue;
            }
            Err(e) => panic!("Failed to run migrations: {}", e),
        }
    }

    info!("Migration process completed successfully.");

    /////////////
    // IPINFO //
    ///////////
    let geo = IpInfoProvider::new(config.ipinfo_token.to_string());

    ////////////
    // ACTOR //
    //////////
    let brute_system = BruteSystem::new_brute(db, geo).await;
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

    let serve_future = serve(ip, port.parse::<u16>().unwrap(), brute_actor.clone(), bearer_token.clone());
    if let Some(tls) = tls_config {
        info!("TLS certificates found, starting TLS server on {}", listen_address_tls);
        let serve_tls_future = serve_tls(ip_tls, port_tls.parse::<u16>().unwrap(), brute_actor, tls, bearer_token);
        tokio::try_join!(serve_tls_future, serve_future)?;
    } else {
        info!("No TLS certificates found, skipping TLS server.");
        serve_future.await?;
    }
    Ok(())
}