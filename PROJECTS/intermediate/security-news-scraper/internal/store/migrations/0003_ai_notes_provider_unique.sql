-- ©AngelaMos | 2026
-- 0003_ai_notes_provider_unique.sql

CREATE UNIQUE INDEX idx_ai_notes_cluster_provider ON ai_notes(cluster_id, provider);
