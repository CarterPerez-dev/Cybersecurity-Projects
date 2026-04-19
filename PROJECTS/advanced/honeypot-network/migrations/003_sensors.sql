-- ©AngelaMos | 2026
-- 003_sensors.sql

-- +goose Up
CREATE TABLE sensors (
    id         TEXT PRIMARY KEY,
    hostname   TEXT NOT NULL,
    region     TEXT NOT NULL DEFAULT 'local',
    public_ip  TEXT,
    services   TEXT[] NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status     TEXT NOT NULL DEFAULT 'active'
);

-- +goose Down
DROP TABLE IF EXISTS sensors;
