-- Add up migration script here
CREATE TABLE processed_individual (
    id VARCHAR(32) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    ip VARCHAR(39) NOT NULL, -- to support both ipv4 and ipv6
    protocol VARCHAR(50) NOT NULL,    
    hostname VARCHAR(255),
    city VARCHAR(255),
    region VARCHAR(255),
    timezone VARCHAR(255),
    country VARCHAR(3),
    loc VARCHAR(255),
    org VARCHAR(255),
    postal VARCHAR(20),
    -- ASN fields
    asn VARCHAR(50),
    asn_name VARCHAR(255),
    asn_domain VARCHAR(255),
    asn_route VARCHAR(255),
    asn_type VARCHAR(50),
    -- Company fields
    company_name VARCHAR(255),
    company_domain VARCHAR(255),
    company_type VARCHAR(50),
    -- Privacy fields
    vpn BOOLEAN,
    proxy BOOLEAN,
    tor BOOLEAN,
    relay BOOLEAN,
    hosting BOOLEAN,
    service VARCHAR(255),
    -- Abuse fields
    abuse_address VARCHAR(255),
    abuse_country VARCHAR(255),
    abuse_email VARCHAR(255),
    abuse_name VARCHAR(255),
    abuse_network VARCHAR(255),
    abuse_phone VARCHAR(50),
    -- Domain fields
    domain_ip VARCHAR(255),
    domain_total BIGINT,
    domains TEXT[],
    timestamp BIGINT NOT NULL
);