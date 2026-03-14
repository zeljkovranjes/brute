-- Add up migration script here
CREATE TABLE top_country (
    country VARCHAR(3) PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 0
);