CREATE DATABASE IF NOT EXISTS csv_warehouse;

CREATE TABLE IF NOT EXISTS csv_warehouse.raw_data
(
    source_file String,
    email String,
    email_hash String,
    data String
)
ENGINE = MergeTree()
ORDER BY email_hash;

CREATE TABLE IF NOT EXISTS csv_warehouse.ingestion_log
(
    filename String,
    file_hash String,
    row_count UInt64,
    timestamp DateTime DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY timestamp;
