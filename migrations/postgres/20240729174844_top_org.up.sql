-- Add up migration script here
CREATE TABLE top_org (
    org VARCHAR(255) PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 0
);