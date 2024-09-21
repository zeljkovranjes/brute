# Brute
[<img alt="github" src="https://img.shields.io/badge/%20GitHub-chomnr%2Fbrute-orange" height="20">](https://github.com/chomnr/brute)
[<img alt="os" src="https://img.shields.io/badge/%20OS-Linux,%20Windows,%20MacOS-blue" height="20">](/)
[<img alt="version" src="https://img.shields.io/badge/%20Release-v1.1.0-green" height="20">](https://github.com/chomnr/brute/releases/tag/v1.1.0)

Brute is a project for monitoring authentication attempts on servers using OpenSSH. It tracks and records each attempt
and provides detailed information about the person who made the attempt.

Currently, this project must use a specific version of OpenSSH. Unfortunately, the changes made to 
this may compromise the security of your server, so use with **caution**.

- **Straightforward** — Simply call the endpoint ```/brute/attack/add```, and Brute will log, analyze, and store the credentials for you.

- **Extendable Metrics** — Brute allows developers to easily add or remove metrics as needed. You can easily integrate additional metrics or connect an API with minimal effort to Brute.

- **Location Information** — Information can be easily accessed through the [Ipinfo](https://ipinfo.io//) API, which is integrated into Brute. This integration allows for retrieval of detailed data from the individual's IP address.

- **WebSocket Support** —  Brute supports WebSocket connections for both TLS and non-TLS websites, providing an easy way for you to stream your results in real-time.

<div align="center"> <img src="./docs/img/in_action2.png"> </div>

## Installation
This installation is for <code>brute-http</code> this is the http server that needs to run in order
to collect the traffic from the dummy servers.
```sh
# Download rustup
curl https://sh.rustup.rs -sSf | sh

# Type 1 to proceed with the default installation.
# You might need to restart the shell

# Add Rust to PATH
source "$HOME/.cargo/env"

# Verify the installation
rustc -V
```

Non-docker installation
<details><summary><b>Show instructions</b></summary>

1. Clone the repository:

    ```sh
    git clone https://github.com/chomnr/brute
    ```
2. Go into the repository:
    ```sh
    cd brute-http
    ```
3. Set the following environment variables:
    ```env
    ##############
    # brute_http #
    ##############
    DATABASE_URL=postgresql://postgres:{password}@{host}/{database}
    BEARER_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    IPINFO_TOKEN=xxxxxxxxxxxxxx
    RUST_LOG=trace
    RUST_LOG_STYLE=always
    LISTEN_ADDRESS=0.0.0.0:7000
    LISTEN_ADDRESS_TLS=0.0.0.0:7443
    RUNNING_IN_DOCKER=false

    ################
    # brute_daemon #
    ################
    ADD_ATTACK_ENDPOINT=http://localhost:7000/brute/stats/attack
    ```
4. Add your cert.pem and key.pem to /certs folders:
    ```
    Generate one from cloudflare, letsencrypt or just use the openssl command.
    If you don't want to run with ssl then going into main.rs and remove serve_tls() function and
    make sure you remove everything that is under this header in main.rs
    //////////
    // TLS //
    ////////
    ```
5. Build and run the program
    ```sh
    cargo build --release # then run executable or
    cargo run # run the program
    ```
</details>

Docker installation
<details><summary><b>Show instructions</b></summary>

1. Clone the repository:

    ```sh
    git clone https://github.com/chomnr/brute
    ```
2. Go into your DockerFile
    ```
    Open it with nano or your favorite text editor on windows or macos doesn't matter.
    ```
3. Change the environment variables
    ```
    ENV DATABASE_URL=postgresql://chomnr:{password}@{host}:{port}/brute
    ENV BEARER_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ENV IPINFO_TOKEN=xxxxxxxxxxxxxx
    ENV RUST_LOG=trace
    ENV RUST_LOG_STYLE=alwayss
    ENV LISTEN_ADDRESS=0.0.0.0:7000
    ENV LISTEN_ADDRESS_TLS=0.0.0.0:7443
    ENV RUNNING_IN_DOCKER=true
    ```
4. (Maybe) Go into brute-http and make a .env and paste the following:
    ```
    DATABASE_URL=postgresql://postgres:{password}@{host}/{database}
    BEARER_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    IPINFO_TOKEN=xxxxxxxxxxxxxx
    RUST_LOG=trace
    RUST_LOG_STYLE=always
    LISTEN_ADDRESS=0.0.0.0:7000
    LISTEN_ADDRESS_TLS=0.0.0.0:7443
    RUNNING_IN_DOCKER=false
    ```
5. (Maybe) Copy your cert.pem and key.pem into /brute/brute-http: 
    ```
    If you plan on serving with TLS then you must do this if not
    you can ignore the certs folder. If you would like to remove
    TLS then just click "show instructions" for non-docker.
    ```
5. Go back into /brute folder and build the image.
    ```
    docker build --pull --rm -f "DockerFile" -t brute:latest "."
    ```
6. After the installation finishes run.
    ```sh
    docker run --name brute -p 7000:7000 -p 7443:7443 --restart unless-stopped -d brute  # sqlx will do the migrations for you automatically.
    ```
</details>

## Installation for Traffic
Before installing, please identify where you want to source your traffic. 
There are, of course, multiple ways to do this, but we'll only be discussing two of them.
- OpenSSH
- Daemon (Developing a custom daemon that listens on ports such as SSH, FTP, HTTP/HTTPS, LDAP, etc.)
```sh
# Update package lists
sudo apt update

# Upgrade all installed packages
sudo apt upgrade

# Install essential build tools and libraries
sudo apt install build-essential zlib1g-dev libssl-dev libpq-dev pkg-config

# Install additional development libraries
sudo apt install libcurl4-openssl-dev libpam0g-dev

# Install autoconf for configuration scripts
sudo apt install autoconf
```
### Daemon
Supports SSH and FTP. You can easily integrate your own protocols just call /brute/attack/add then specify the protocol in the payload. This is a great alternative if you don't want to go through the openssh route. But ensure that you use this on a dummy server not a production server. 
https://github.com/chomnr/brute-daemon

Please ensure you have OpenSSH and any FTP server uninstalled before proceeding.

<details><summary><b>Show instructions</b></summary>

1. Clone the repository:

    ```sh
    git clone https://github.com/chomnr/brute-daemon
    ```
2. Go into the repository:
    ```sh
    cd brute-daemon
    ```
3. Build the application:
    ```sh
    cargo build --release
    ```
4. Move the executable into <code>/usr/local/bin/</code>:
    ```sh
    mv ~/brute-daemon/target/release/brute-daemon /usr/local/bin/brute-daemon
    ```
5. Create a daemon file and paste and edit the following contents:
    ```sh
    nano /etc/systemd/system/brute-daemon.service
    ```
    ```diff
    +  [Unit]
    +  Description=Brute Daemon
    +  After=network.target

    +  [Service]
    +  ExecStart=/usr/local/bin/brute-daemon
    +  Restart=always
    +  User=root
    +  WorkingDirectory=/usr/local/bin
    +  StandardOutput=append:/var/log/brute-daemon.log
    +  StandardError=append:/var/log/brute-daemon_error.log

    +  # Environment Variables
    +  Environment="ADD_ATTACK_ENDPOINT=https://example.com/brute/attack/add"
    +  Environment="BEARER_TOKEN=my-secret-token"

    + [Install]
    + WantedBy=multi-user.target
    ```
6. Reload <code>systemd</code>:
    ```
    systemctl daemon-reload
    ```
7. Enable the service:
    ```
    systemctl enable brute-daemon
    ```
8. Start the service:
    ```
    systemctl start brute-daemon
    ```
8. Check the status and it should say the following:
    ```
    systemctl status brute-daemon
    ```
    ```
    Active: active (running) 
    ```s
</details>

### OpenSSH
<details><summary><b>Show instructions</b></summary>

1. Clone the repository:

    ```sh
    git clone https://github.com/chomnr/openssh-9.8-patched
    ```

2. Go into the repository:

    ```sh
    cd openssh-9.8-patched
    ```

3. Configure the repository:

    ```sh
    autoreconf
    ./configure --with-pam --with-privsep-path=/var/lib/sshd/ --sysconfdir=/etc/ssh
    ```
4. Now make and install the server:
    ```sh
    make
    make install
    ```
5. Then go into <code>ssh.service</code>
    ```ssh
    nano /lib/systemd/system/ssh.service
    ```
6. Replace the existing SSH server with the one you just compiled:
    ```diff
    -  ExecStartPre=/usr/sbin/sshd -t
    -  ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
    -  ExecReload=/usr/sbin/sshd -t
    +  ExecStartPre=/usr/local/sbin/sshd -t
    +  ExecStart=/usr/local/sbin/sshd -D $SSHD_OPTS
    +  ExecReload=/usr/local/sbin/sshd -t
    ```
7. Now run <code>ssh -V</code> and it should say the following:
    ```
    (Brute) OpenSSH_9.8...
    ```
8. Ok, now we need to setup the PAM module first clone it:
    ```sh
    git clone https://github.com/chomnr/brute_pam
    ```
8. Make and install the PAM module:
    ```sh
    cmake .
    make # go into lib and rename it to brute_pam.so
    ```
9. Now copy the PAM module into <code>/lib/x86_64-linux-gnu/security/</code>
    ```
    cp brute_pam.so /lib/x86_64-linux-gnu/security/
    ```
10. Now go into <code>/etc/pam.d/common-auth</code>
    ```
    sudo nano /etc/pam.d/common-auth
    ```
11. Now add PAM to the common-auth
    ```diff
    original /etc/pam.d/common-auth
    # here are the per-package modules (the "Primary" block)
    - auth    [success=1 default=ignore]      pam_unix.so nullok
    # here's the fallback if no module succeeds
    auth    requisite 
    # here are the per-package modules (the "Primary" block)
    + auth    [success=2 default=ignore]      pam_unix.so nullok
    + # enable Brute.
    + auth    optional                        pam_brute.so
    # here's the fallback if no module succeeds
    auth    requisite                       pam_deny.so
    ```
</details>

## License
The MIT License (MIT) 2024 - Zeljko Vranjes. Please have a look at the [LICENSE.md](https://github.com/chomnr/brute/blob/main/LICENSE.md) for more details.