#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use daemonize::Daemonize;

use protocol::ssh::listen_on_ssh;

mod protocol;
mod endpoint;

#[cfg(target_os = "windows")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().unwrap();
    listen_on_ssh().await?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().unwrap();
    let daemonize = Daemonize::new()
        .pid_file("/tmp/bruted.pid")
        .chown_pid_file(true)
        .umask(0o777)
        .group("brute")
        .working_directory("/tmp")
        .stdout(File::create("/tmp/brute_daemon.stdout").unwrap())
        .stderr(File::create("/tmp/brute_daemon.stderr").unwrap()); 
    match daemonize.start() {
        Ok(_) => {
            println!("Success, daemonized");
            listen_on_ssh().await?;
        },
        Err(e) => eprintln!("Error, {}", e),
    }
    Ok(())
}
