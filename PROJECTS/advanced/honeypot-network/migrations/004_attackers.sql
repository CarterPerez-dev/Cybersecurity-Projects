-- ©AngelaMos | 2026
-- 004_attackers.sql

-- +goose Up
CREATE TABLE attackers (
    id             BIGSERIAL PRIMARY KEY,
    ip             TEXT NOT NULL UNIQUE,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_events   BIGINT NOT NULL DEFAULT 0,
    total_sessions INTEGER NOT NULL DEFAULT 0,
    country_code   TEXT,
    country        TEXT,
    city           TEXT,
    latitude       DOUBLE PRECISION,
    longitude      DOUBLE PRECISION,
    asn            INTEGER,
    org            TEXT,
    threat_score   INTEGER NOT NULL DEFAULT 0,
    tool_family    TEXT,
    tags           TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_attackers_last_seen ON attackers (last_seen DESC);
CREATE INDEX idx_attackers_threat_score ON attackers (threat_score DESC);
CREATE INDEX idx_attackers_country ON attackers (country_code);

-- +goose Down
DROP TABLE IF EXISTS attackers;
