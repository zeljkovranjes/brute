-- Add up migration script here
CREATE TABLE top_usr_pass_combo (
    id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    amount INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT unique_username_password UNIQUE (username, password)
);