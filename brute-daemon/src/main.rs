#[cfg(target_os = "linux")]
use std::fs::File;
use std::{fs::File, process};
#[cfg(target_os = "linux")]
use daemonize::Daemonize;

use std::io::{self, Write};  // Import the Write trait here


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
    println!("Initializing!");
    dotenvy::dotenv().unwrap();

    if let Err(e) = create_pid_file() {
        eprintln!("Failed to create PID file: {}", e);
        return Err(anyhow::anyhow!("Failed to create PID file"));
    }

    let stdout = File::create("/tmp/bruted.out").unwrap();
    let stderr = File::create("/tmp/bruted.err").unwrap();

    let daemonize = Daemonize::new()
        .pid_file("/tmp/bruted.pid")
        .chown_pid_file(true)
        .umask(0o777)
        .group("bruted")
        .working_directory("/tmp")
        .stdout(stdout)
        .stderr(stderr);

    match daemonize.start() {
        Ok(_) => {
            println!("Success, daemonized");
            if let Err(e) = listen_on_ssh().await {
                eprintln!("Error listening on SSH: {}", e);
                // Remove PID file if SSH server fails to start
                let _ = remove_pid_file();
                return Err(anyhow::anyhow!("Error listening on SSH"));
            }
        },
        Err(e) => {
            eprintln!("Error daemonizing: {}", e);
            // Attempt to remove PID file if daemonization fails
            let _ = remove_pid_file();
            return Err(anyhow::anyhow!("Error daemonizing"));
        },
    }

    // Remove PID file on successful shutdown
    let _ = remove_pid_file();

    Ok(())
}
#[cfg(target_os = "linux")]

fn remove_pid_file() -> anyhow::Result<()> {
    std::fs::remove_file("/tmp/bruted.pid")?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn create_pid_file() -> std::io::Result<()> {
    let pid = process::id();
    let mut file = File::create("/tmp/bruted.pid")?;
    write!(file, "{}", pid)?;
    Ok(())
}
