CREATE TABLE IF NOT EXISTS traffic_flows (
    id SERIAL PRIMARY KEY,
    src_ip VARCHAR NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip VARCHAR NOT NULL,
    dst_port INTEGER NOT NULL,
    ja3_hash VARCHAR,
    ja3_string VARCHAR,
    sni VARCHAR,
    app_name VARCHAR DEFAULT 'Unknown',
    category_name VARCHAR DEFAULT 'Traffic',
    confidence FLOAT DEFAULT 0.0
);
