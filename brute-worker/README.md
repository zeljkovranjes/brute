# brute-worker

Cloudflare Workers deployment of Brute. Uses D1 (SQLite) for storage, Analytics Engine for aggregated event data, and a Durable Object for WebSocket broadcasting. No external geo API token required — location data is read directly from the Cloudflare `cf` request object.

## Prerequisites

```sh
npm install -g wrangler
```

## Setup

1. Create a D1 database:

    ```sh
    wrangler d1 create worker_brute_d1
    ```

    Copy the `database_id` from the output and paste it into `wrangler.toml`:

    ```toml
    [[d1_databases]]
    binding = "worker_brute_d1"
    database_name = "worker_brute_d1"
    database_id = "YOUR_D1_DATABASE_ID"
    ```

2. Apply the D1 schema:

    ```sh
    wrangler d1 execute worker_brute_d1 --file=../migrations/d1/0001_initial_schema.sql
    ```

3. Set the bearer token secret:

    ```sh
    wrangler secret put BEARER_TOKEN
    ```

4. Deploy:

    ```sh
    npm run deploy
    # or: wrangler deploy
    ```

## Bindings / Variables

| Binding / Variable | Type | Description |
|---|---|---|
| `worker_brute_d1` | D1 binding | SQLite database via Cloudflare D1 |
| `ANALYTICS` | Analytics Engine binding | Writes attack event data points |
| `WS_BROADCASTER` | Durable Object binding | Manages WebSocket connections |
| `BEARER_TOKEN` | Secret | API authentication token |

## Local Development

```sh
wrangler dev
```

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
