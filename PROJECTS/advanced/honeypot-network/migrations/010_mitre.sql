-- ©AngelaMos | 2026
-- 010_mitre.sql

-- +goose Up
CREATE TABLE mitre_detections (
    id           BIGSERIAL PRIMARY KEY,
    session_id   TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    confidence   INTEGER NOT NULL DEFAULT 50,
    source_ip    TEXT NOT NULL,
    service_type service_type NOT NULL,
    evidence     TEXT,
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mitre_technique ON mitre_detections (technique_id);
CREATE INDEX idx_mitre_tactic ON mitre_detections (tactic);
CREATE INDEX idx_mitre_session ON mitre_detections (session_id);
CREATE INDEX idx_mitre_detected ON mitre_detections (detected_at DESC);

-- +goose Down
DROP TABLE IF EXISTS mitre_detections;
