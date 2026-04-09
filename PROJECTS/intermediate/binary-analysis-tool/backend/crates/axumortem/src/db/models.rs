// ©AngelaMos | 2026
// models.rs
//
// Database row and input structs
//
// AnalysisRow maps to the analyses table with UUID id,
// sha256 hash, file_name, file_size, format, architecture,
// entry_point, threat_score, risk_level, slug, and
// created_at timestamp. PassResultRow maps to the
// pass_results table with analysis_id foreign key,
// pass_name, JSON result blob, and duration_ms.
// NewAnalysis and NewPassResult are input structs for
// insert operations without server-generated fields.
//
// Connects to:
//   db/queries.rs      - used by insert and select queries
//   routes/upload.rs   - NewAnalysis built from engine output
//   routes/analysis.rs - AnalysisRow returned to client

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow, Serialize)]
pub struct AnalysisRow {
    pub id: Uuid,
    pub sha256: String,
    pub file_name: String,
    pub file_size: i64,
    pub format: String,
    pub architecture: String,
    pub entry_point: Option<i64>,
    pub threat_score: Option<i32>,
    pub risk_level: Option<String>,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
pub struct PassResultRow {
    pub id: Uuid,
    pub analysis_id: Uuid,
    pub pass_name: String,
    pub result: serde_json::Value,
    pub duration_ms: Option<i32>,
}

pub struct NewAnalysis {
    pub sha256: String,
    pub file_name: String,
    pub file_size: i64,
    pub format: String,
    pub architecture: String,
    pub entry_point: Option<i64>,
    pub threat_score: Option<i32>,
    pub risk_level: Option<String>,
    pub slug: String,
}

pub struct NewPassResult {
    pub analysis_id: Uuid,
    pub pass_name: String,
    pub result: serde_json::Value,
    pub duration_ms: Option<i32>,
}
