-- Add up migration script here
CREATE TABLE top_weekly (
    timestamp BIGINT PRIMARY KEY,
    amount INTEGER NOT NULL
)