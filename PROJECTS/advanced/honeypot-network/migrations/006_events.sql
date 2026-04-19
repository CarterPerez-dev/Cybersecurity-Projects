-- ©AngelaMos | 2026
-- 006_events.sql

-- +goose Up
CREATE TABLE events (
    id             TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    sensor_id      TEXT NOT NULL,
    timestamp      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service_type   service_type NOT NULL,
    event_type     event_type NOT NULL,
    source_ip      TEXT NOT NULL,
    source_port    INTEGER NOT NULL,
    dest_port      INTEGER NOT NULL,
    protocol       protocol_type NOT NULL DEFAULT 'tcp',
    schema_version INTEGER NOT NULL DEFAULT 1,
    country_code   TEXT,
    country        TEXT,
    city           TEXT,
    latitude       DOUBLE PRECISION,
    longitude      DOUBLE PRECISION,
    asn            INTEGER,
    org            TEXT,
    tags           TEXT[] NOT NULL DEFAULT '{}',
    service_data   JSONB,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE INDEX idx_events_session ON events (session_id);
CREATE INDEX idx_events_source_ip ON events (source_ip);
CREATE INDEX idx_events_service ON events (service_type);
CREATE INDEX idx_events_type ON events (event_type);
CREATE INDEX idx_events_timestamp ON events (timestamp DESC);

-- +goose Down
DROP TABLE IF EXISTS events;
