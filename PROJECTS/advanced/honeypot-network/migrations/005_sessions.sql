-- ©AngelaMos | 2026
-- 005_sessions.sql

-- +goose Up
CREATE TABLE sessions (
    id               TEXT NOT NULL,
    sensor_id        TEXT NOT NULL REFERENCES sensors(id),
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at         TIMESTAMPTZ,
    service_type     service_type NOT NULL,
    source_ip        TEXT NOT NULL,
    source_port      INTEGER NOT NULL,
    dest_port        INTEGER NOT NULL,
    client_version   TEXT,
    login_success    BOOLEAN NOT NULL DEFAULT FALSE,
    username         TEXT,
    command_count    INTEGER NOT NULL DEFAULT 0,
    mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
    threat_score     INTEGER NOT NULL DEFAULT 0,
    tags             TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (id, started_at)
) PARTITION BY RANGE (started_at);

CREATE INDEX idx_sessions_source_ip ON sessions (source_ip);
CREATE INDEX idx_sessions_service ON sessions (service_type);
CREATE INDEX idx_sessions_started ON sessions (started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS sessions;
