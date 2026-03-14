-- Add up migration script here
CREATE TABLE top_daily (
    timestamp BIGINT PRIMARY KEY,
    amount INTEGER NOT NULL
)