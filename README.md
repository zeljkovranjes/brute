# Brute
[<img alt="github" src="https://img.shields.io/badge/%20GitHub-notpointless%2Fbrute-orange" height="20">](https://github.com/notpointless/brute)
[<img alt="os" src="https://img.shields.io/badge/%20OS-Linux,%20Windows,%20MacOS-blue" height="20">](/)
[<img alt="version" src="https://img.shields.io/badge/%20Release-v1.0.0-green" height="20">](https://github.com/notpointless/brute/releases/tag/v1.0.0)

Brute is a project for monitoring authentication attempts on servers using OpenSSH. It tracks and records each attempt
and provides detailed information about the person who made the attempt.

Currently, this project must use a specific version of OpenSSH. Unfortunately, the changes made to 
this may compromise the security of your server, so use with **caution**.

- **Straightforward** — Simply call the endpoint ```/brute/attack/add```, and Brute will log, analyze, and store the credentials for you.

- **Extendable Metrics** — Brute allows developers to easily add or remove metrics as needed. You can easily integrate additional metrics or connect an API with minimal effort to Brute.

- **Location Information** — Information can be easily accessed through the [Ipinfo](https://ipinfo.io//) API, which is integrated into Brute. This integration allows for retrieval of detailed data from the individual's IP address.

<div align="center"> <img src="./docs/img/in_action.png"> </div>

## Installation
Before installing, please identify where you want to source your traffic. 
There are, of course, multiple ways to do this, but we'll only be discussing two of them.
- OpenSSH
- Daemon (Developing a custom daemon that listens on ports such as SSH, FTP, HTTP/HTTPS, LDAP, etc.)
```
# Update package lists
sudo apt update

# Upgrade all installed packages
sudo apt upgrade

# Install essential build tools and libraries
sudo apt install build-essential zlib1g-dev libssl-dev libpq-dev

# Install additional development libraries
sudo apt install libcurl4-openssl-dev libpam0g-dev

# Install autoconf for configuration scripts
sudo apt install autoconf
```
### Daemon
Supports SSH and FTP. You can easily integrate your own protocols just call /brute/attack/add then specify the protocol in the payload. This is a great alternative if you don't want to go through the openssh route. But ensure that you use this on a dummy server not a production server. 
https://github.com/notpointless/brute-daemon

### OpenSSH
<details><summary><b>Show instructions</b></summary>

1. Clone the repository:

    ```sh
    git clone https://github.com/notpointless/openssh-9.8-patched
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
4. Now we're going to make and install the client.
    ```sh
    sudo make
    sudo make install
    ```
</details>