# brute-http

Standalone HTTP server for Brute. Receives credential reports from `brute-daemon`, stores them in PostgreSQL, and serves stats via a REST API and WebSocket stream.

## Setup

### Non-Docker

1. Clone the repository:

    ```sh
    git clone https://github.com/chomnr/brute
    ```

2. Go into the `brute-http` directory:

    ```sh
    cd brute/brute-http
    ```

3. Set the following environment variables:

    ```env
    DATABASE_URL=postgresql://postgres:{password}@{host}/{database}
    BEARER_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    IPINFO_TOKEN=xxxxxxxxxxxxxx
    RUST_LOG=trace
    RUST_LOG_STYLE=always
    LISTEN_ADDRESS=0.0.0.0:7000
    LISTEN_ADDRESS_TLS=0.0.0.0:7443
    RUNNING_IN_DOCKER=false
    # Optional — enables AbuseIPDB reputation scoring
    ABUSEIPDB_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ```

4. Add your `cert.pem` and `key.pem` to the `/certs` folder inside `brute-http/`:

    ```
    Generate one from Cloudflare, Let's Encrypt, or OpenSSL.
    If you don't want TLS, remove serve_tls() from main.rs.
    ```

5. Build and run:

    ```sh
    cargo build --release -p brute-http
    cargo run -p brute-http
    ```

### Docker

1. Clone the repository:

    ```sh
    git clone https://github.com/chomnr/brute
    ```

2. Open the `DockerFile` and edit the environment variables:

    ```env
    ENV DATABASE_URL=postgresql://postgres:{password}@{host}:{port}/brute
    ENV BEARER_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ENV IPINFO_TOKEN=xxxxxxxxxxxxxx
    ENV RUST_LOG=trace
    ENV RUST_LOG_STYLE=always
    ENV LISTEN_ADDRESS=0.0.0.0:7000
    ENV LISTEN_ADDRESS_TLS=0.0.0.0:7443
    ENV RUNNING_IN_DOCKER=true
    ```

3. (Optional) Copy your `cert.pem` and `key.pem` into `brute-http/` for TLS.

4. Build the image from the project root:

    ```sh
    docker build --pull --rm -f "DockerFile" -t brute:latest "."
    ```

5. Run the container:

    ```sh
    docker run --name brute -p 7000:7000 -p 7443:7443 --restart unless-stopped -d brute
    ```

    sqlx will apply migrations automatically on startup.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `BEARER_TOKEN` | Yes | Secret token for API authentication |
| `IPINFO_TOKEN` | Yes | IPinfo.io API token for geo lookup |
| `LISTEN_ADDRESS` | Yes | HTTP bind address, e.g. `0.0.0.0:7000` |
| `LISTEN_ADDRESS_TLS` | Yes | HTTPS bind address, e.g. `0.0.0.0:7443` |
| `RUNNING_IN_DOCKER` | Yes | Set to `true` when running inside Docker |
| `ABUSEIPDB_KEY` | No | AbuseIPDB API key — enables IP reputation scoring |
| `RUST_LOG` | No | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

## API Endpoints

All POST endpoints require an `Authorization: Bearer <BEARER_TOKEN>` header.

### POST

| Endpoint | Description |
|---|---|
| `POST /brute/attack/add` | Record an authentication attempt |
| `POST /brute/protocol/increment` | Increment a protocol counter directly |

### GET — Stats

| Endpoint | Description |
|---|---|
| `GET /brute/stats/attack` | Recent processed attacks |
| `GET /brute/stats/username` | Top usernames |
| `GET /brute/stats/password` | Top passwords |
| `GET /brute/stats/ip` | Top IPs |
| `GET /brute/stats/protocol` | Top protocols |
| `GET /brute/stats/country` | Top countries |
| `GET /brute/stats/city` | Top cities |
| `GET /brute/stats/region` | Top regions |
| `GET /brute/stats/timezone` | Top timezones |
| `GET /brute/stats/org` | Top organizations |
| `GET /brute/stats/postal` | Top postal codes |
| `GET /brute/stats/loc` | Top lat/lon locations |
| `GET /brute/stats/combo` | Top username/password combinations |
| `GET /brute/stats/combo/protocol` | Top combos filtered by protocol |
| `GET /brute/stats/hourly` | Hourly attack counts |
| `GET /brute/stats/daily` | Daily attack counts |
| `GET /brute/stats/weekly` | Weekly attack counts |
| `GET /brute/stats/yearly` | Yearly attack counts |
| `GET /brute/stats/heatmap` | Attack heatmap (day × hour) |
| `GET /brute/stats/subnet` | Top /24 subnets |
| `GET /brute/stats/velocity` | Attack velocity (per minute, last hour) |
| `GET /brute/stats/ip/seen` | IP first/last seen times |
| `GET /brute/stats/ip/abuse` | AbuseIPDB scores |
| `GET /brute/stats/summary` | Rolling stats summary |

### GET — Export

| Endpoint | Description |
|---|---|
| `GET /brute/export/blocklist` | Export top IPs as a blocklist. `?format=plain\|iptables\|nginx\|fail2ban` |

### WebSocket

| Endpoint | Description |
|---|---|
| `GET /ws` | Connect to the real-time broadcast stream |
