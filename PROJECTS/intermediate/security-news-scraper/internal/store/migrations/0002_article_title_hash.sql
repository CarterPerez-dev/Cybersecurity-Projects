-- ©AngelaMos | 2026
-- 0002_article_title_hash.sql

ALTER TABLE articles ADD COLUMN title_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_articles_title_hash ON articles(title_hash);
