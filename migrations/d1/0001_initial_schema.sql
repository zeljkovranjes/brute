-- D1 (SQLite) schema for brute-worker
-- Differences from PostgreSQL:
--   - No UUID type: use TEXT
--   - No BIGSERIAL/SERIAL: use INTEGER PRIMARY KEY AUTOINCREMENT
--   - No BOOLEAN: use INTEGER (0/1)
--   - No TEXT[]: use TEXT (JSON-encoded)
--   - No BIGINT: use INTEGER (SQLite INTEGER is up to 64-bit)
--   - No ON CONFLICT ... DO UPDATE with table prefix: use excluded.*

-- Raw individual attack attempts
CREATE TABLE IF NOT EXISTS individual (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);

-- Geo-enriched, processed attack records
CREATE TABLE IF NOT EXISTS processed_individual (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    hostname TEXT,
    city TEXT,
    region TEXT,
    timezone TEXT NOT NULL DEFAULT '',
    country TEXT,
    loc TEXT,
    org TEXT,
    postal TEXT,
    asn TEXT,
    asn_name TEXT,
    asn_domain TEXT,
    asn_route TEXT,
    asn_type TEXT,
    company_name TEXT,
    company_domain TEXT,
    company_type TEXT,
    vpn INTEGER,    -- 0/1 boolean
    proxy INTEGER,
    tor INTEGER,
    relay INTEGER,
    hosting INTEGER,
    service TEXT,
    abuse_address TEXT,
    abuse_country TEXT,
    abuse_email TEXT,
    abuse_name TEXT,
    abuse_network TEXT,
    abuse_phone TEXT,
    domain_ip TEXT,
    domain_total INTEGER,
    domains TEXT,   -- JSON-encoded string array
    timestamp INTEGER NOT NULL
);

-- Aggregation tables (top_*)

CREATE TABLE IF NOT EXISTS top_username (
    username TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_password (
    password TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1,
    is_breached INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS top_ip (
    ip TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_protocol (
    protocol TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_country (
    country TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_city (
    city TEXT NOT NULL,
    country TEXT NOT NULL,
    amount INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (city, country)
);

CREATE TABLE IF NOT EXISTS top_region (
    region TEXT NOT NULL,
    country TEXT NOT NULL,
    amount INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (region, country)
);

CREATE TABLE IF NOT EXISTS top_timezone (
    timezone TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_org (
    org TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_postal (
    postal TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_loc (
    loc TEXT PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_usr_pass_combo (
    id TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    amount INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (username, password)
);

-- Time-series aggregation tables
-- timestamp = epoch-millisecond bucket aligned to the period boundary

CREATE TABLE IF NOT EXISTS top_hourly (
    timestamp INTEGER PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_daily (
    timestamp INTEGER PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_weekly (
    timestamp INTEGER PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS top_yearly (
    timestamp INTEGER PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 1
);

-- IP tracking tables

CREATE TABLE IF NOT EXISTS ip_seen (
    ip TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    total_sessions INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ip_abuse (
    ip TEXT PRIMARY KEY,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    total_reports INTEGER NOT NULL DEFAULT 0,
    checked_at INTEGER NOT NULL
);

-- Indexes for common query patterns

CREATE INDEX IF NOT EXISTS idx_individual_timestamp ON individual(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_processed_timestamp ON processed_individual(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_processed_ip ON processed_individual(ip);
CREATE INDEX IF NOT EXISTS idx_ip_seen_sessions ON ip_seen(total_sessions DESC);
CREATE INDEX IF NOT EXISTS idx_ip_abuse_score ON ip_abuse(confidence_score DESC);
