-- Add up migration script here
CREATE TABLE top_city (
    city VARCHAR(255) NOT NULL,
    country VARCHAR(255) NOT NULL,
    amount INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT unique_city_country UNIQUE (city, country)
);