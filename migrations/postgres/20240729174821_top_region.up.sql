-- Add up migration script here
CREATE TABLE top_region (
    region VARCHAR(255) NOT NULL,
    country VARCHAR(255) NOT NULL,
    amount INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT unique_region_country UNIQUE (region, country)
);