-- Add up migration script here
CREATE TABLE top_ip (
    ip VARCHAR(39) PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 0
);