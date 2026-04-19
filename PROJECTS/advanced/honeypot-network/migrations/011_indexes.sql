-- ©AngelaMos | 2026
-- 011_indexes.sql

-- +goose Up
CREATE INDEX idx_events_service_data ON events USING GIN (service_data);
CREATE INDEX idx_events_tags ON events USING GIN (tags);
CREATE INDEX idx_sessions_mitre ON sessions USING GIN (mitre_techniques);
CREATE INDEX idx_sessions_tags ON sessions USING GIN (tags);
CREATE INDEX idx_attackers_tags ON attackers USING GIN (tags);
CREATE INDEX idx_iocs_tags ON iocs USING GIN (tags);

-- +goose Down
DROP INDEX IF EXISTS idx_iocs_tags;
DROP INDEX IF EXISTS idx_attackers_tags;
DROP INDEX IF EXISTS idx_sessions_tags;
DROP INDEX IF EXISTS idx_sessions_mitre;
DROP INDEX IF EXISTS idx_events_tags;
DROP INDEX IF EXISTS idx_events_service_data;
