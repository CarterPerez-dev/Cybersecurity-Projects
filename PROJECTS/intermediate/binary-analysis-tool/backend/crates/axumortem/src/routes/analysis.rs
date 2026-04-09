// ©AngelaMos | 2026
// analysis.rs
//
// Analysis result retrieval endpoint
//
// get_by_slug extracts the slug path parameter, queries
// the analysis row by slug, fetches all associated pass
// result rows, and assembles an AnalysisResponse with
// metadata fields and a passes HashMap mapping pass names
// to their JSON result blobs. Returns 404 via
// ApiError::NotFound if the slug does not exist.
//
// Connects to:
//   state.rs      - AppState
//   db/queries.rs - find_by_slug, find_pass_results
//   error.rs      - ApiError

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::db::queries;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Serialize)]
pub(crate) struct AnalysisResponse {
    id: Uuid,
    sha256: String,
    file_name: String,
    file_size: i64,
    format: String,
    architecture: String,
    entry_point: Option<i64>,
    threat_score: Option<i32>,
    risk_level: Option<String>,
    slug: String,
    created_at: DateTime<Utc>,
    passes: HashMap<String, serde_json::Value>,
}

pub async fn get_by_slug(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<AnalysisResponse>, ApiError> {
    let row = queries::find_by_slug(&state.db, &slug)
        .await?
        .ok_or_else(|| ApiError::NotFound {
            resource: format!("analysis '{slug}'"),
        })?;

    let pass_rows =
        queries::find_pass_results(&state.db, row.id)
            .await?;

    let passes: HashMap<String, serde_json::Value> =
        pass_rows
            .into_iter()
            .map(|p| (p.pass_name, p.result))
            .collect();

    Ok(Json(AnalysisResponse {
        id: row.id,
        sha256: row.sha256,
        file_name: row.file_name,
        file_size: row.file_size,
        format: row.format,
        architecture: row.architecture,
        entry_point: row.entry_point,
        threat_score: row.threat_score,
        risk_level: row.risk_level,
        slug: row.slug,
        created_at: row.created_at,
        passes,
    }))
}
