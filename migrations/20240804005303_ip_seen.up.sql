CREATE TABLE ip_seen (
    ip VARCHAR(39) PRIMARY KEY,
    first_seen BIGINT NOT NULL,
    last_seen BIGINT NOT NULL,
    total_sessions BIGINT NOT NULL DEFAULT 1
);
