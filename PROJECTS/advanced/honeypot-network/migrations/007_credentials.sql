-- ©AngelaMos | 2026
-- 007_credentials.sql

-- +goose Up
CREATE TABLE credentials (
    id           BIGSERIAL,
    session_id   TEXT NOT NULL,
    timestamp    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service_type service_type NOT NULL,
    source_ip    TEXT NOT NULL,
    username     TEXT NOT NULL,
    password     TEXT NOT NULL DEFAULT '',
    public_key   TEXT,
    auth_method  TEXT NOT NULL DEFAULT 'password',
    success      BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE INDEX idx_creds_source_ip ON credentials (source_ip);
CREATE INDEX idx_creds_username ON credentials (username);
CREATE INDEX idx_creds_session ON credentials (session_id);
CREATE INDEX idx_creds_timestamp ON credentials (timestamp DESC);

-- +goose Down
DROP TABLE IF EXISTS credentials;
