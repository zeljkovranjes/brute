CREATE TABLE ip_abuse (
    ip VARCHAR(39) PRIMARY KEY,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    total_reports INTEGER NOT NULL DEFAULT 0,
    checked_at BIGINT NOT NULL
);
