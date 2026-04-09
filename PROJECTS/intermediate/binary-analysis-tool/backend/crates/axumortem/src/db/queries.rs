// ©AngelaMos | 2026
// queries.rs
//
// PostgreSQL query functions
//
// find_slug_by_sha256 checks for an existing analysis by
// SHA-256 hash and returns the slug if cached.
// find_by_slug retrieves a full AnalysisRow by its
// URL-friendly slug. find_pass_results fetches all
// PassResultRow entries for an analysis_id ordered by
// pass_name. insert_analysis and insert_pass_result
// perform transactional inserts within a caller-provided
// Transaction, returning the created AnalysisRow and
// committing pass result rows respectively.
//
// Connects to:
//   db/models.rs       - AnalysisRow, PassResultRow,
//                          NewAnalysis, NewPassResult
//   routes/upload.rs   - insert_analysis, insert_pass_result
//   routes/analysis.rs - find_by_slug, find_pass_results

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::models::{
    AnalysisRow, NewAnalysis, NewPassResult,
    PassResultRow,
};

pub async fn find_slug_by_sha256(
    pool: &PgPool,
    sha256: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT slug FROM analyses WHERE sha256 = $1",
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_slug(
    pool: &PgPool,
    slug: &str,
) -> Result<Option<AnalysisRow>, sqlx::Error> {
    sqlx::query_as::<_, AnalysisRow>(
        "SELECT * FROM analyses WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await
}

pub async fn find_pass_results(
    pool: &PgPool,
    analysis_id: Uuid,
) -> Result<Vec<PassResultRow>, sqlx::Error> {
    sqlx::query_as::<_, PassResultRow>(
        "SELECT * FROM pass_results \
         WHERE analysis_id = $1 \
         ORDER BY pass_name",
    )
    .bind(analysis_id)
    .fetch_all(pool)
    .await
}

pub async fn insert_analysis(
    tx: &mut Transaction<'_, Postgres>,
    new: &NewAnalysis,
) -> Result<AnalysisRow, sqlx::Error> {
    sqlx::query_as::<_, AnalysisRow>(
        "INSERT INTO analyses \
         (sha256, file_name, file_size, format, \
          architecture, entry_point, threat_score, \
          risk_level, slug) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING *",
    )
    .bind(&new.sha256)
    .bind(&new.file_name)
    .bind(new.file_size)
    .bind(&new.format)
    .bind(&new.architecture)
    .bind(new.entry_point)
    .bind(new.threat_score)
    .bind(&new.risk_level)
    .bind(&new.slug)
    .fetch_one(tx.as_mut())
    .await
}

pub async fn insert_pass_result(
    tx: &mut Transaction<'_, Postgres>,
    new: &NewPassResult,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO pass_results \
         (analysis_id, pass_name, result, duration_ms) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(new.analysis_id)
    .bind(&new.pass_name)
    .bind(&new.result)
    .bind(new.duration_ms)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}
