-- Add up migration script here
CREATE TABLE top_yearly (
    timestamp BIGINT PRIMARY KEY,
    amount INTEGER NOT NULL
)