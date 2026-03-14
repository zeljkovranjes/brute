-- Add up migration script here
CREATE TABLE top_hourly (
    timestamp BIGINT PRIMARY KEY,
    amount INTEGER NOT NULL
)