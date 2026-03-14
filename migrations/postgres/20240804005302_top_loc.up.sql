-- Add up migration script here
CREATE TABLE top_loc (
    loc VARCHAR(255) PRIMARY KEY,
    amount INTEGER NOT NULL DEFAULT 0
);