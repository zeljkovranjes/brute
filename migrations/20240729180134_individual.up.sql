-- Add up migration script here
CREATE TABLE individual (
    id VARCHAR(32) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    ip VARCHAR(39) NOT NULL,
    protocol VARCHAR(50) NOT NULL,
    timestamp BIGINT NOT NULL
);