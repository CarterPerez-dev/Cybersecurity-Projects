-- ©AngelaMos | 2026
-- 009_iocs.sql

-- +goose Up
CREATE TABLE iocs (
    id          BIGSERIAL PRIMARY KEY,
    type        ioc_type NOT NULL,
    value       TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sight_count INTEGER NOT NULL DEFAULT 1,
    confidence  INTEGER NOT NULL DEFAULT 50,
    source      TEXT NOT NULL DEFAULT 'honeypot',
    tags        TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (type, value)
);

CREATE INDEX idx_iocs_type ON iocs (type);
CREATE INDEX idx_iocs_last_seen ON iocs (last_seen DESC);
CREATE INDEX idx_iocs_confidence ON iocs (confidence DESC);

-- +goose Down
DROP TABLE IF EXISTS iocs;
