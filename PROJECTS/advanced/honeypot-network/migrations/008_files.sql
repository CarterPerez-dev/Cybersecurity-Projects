-- ©AngelaMos | 2026
-- 008_files.sql

-- +goose Up
CREATE TABLE captured_files (
    id         BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip  TEXT NOT NULL,
    service    service_type NOT NULL,
    filename   TEXT NOT NULL,
    size       BIGINT NOT NULL DEFAULT 0,
    sha256     TEXT NOT NULL,
    md5        TEXT NOT NULL,
    mime_type  TEXT,
    content    BYTEA
);

CREATE INDEX idx_files_sha256 ON captured_files (sha256);
CREATE INDEX idx_files_session ON captured_files (session_id);
CREATE INDEX idx_files_timestamp ON captured_files (timestamp DESC);

-- +goose Down
DROP TABLE IF EXISTS captured_files;
