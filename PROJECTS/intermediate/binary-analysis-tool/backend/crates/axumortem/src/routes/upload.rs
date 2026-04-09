// ©AngelaMos | 2026
// upload.rs
//
// Binary upload and analysis endpoint
//
// handle accepts a multipart file upload, computes
// SHA-256, and checks for a cached analysis by hash via
// find_slug_by_sha256. On cache miss it spawns
// AnalysisEngine::analyze on a blocking thread, builds a
// NewAnalysis from the format and threat results, generates
// a 12-character slug from the SHA-256 prefix, and
// transactionally inserts the analysis row and all six
// pass result rows. build_pass_results serializes each
// context field (format, imports, strings, entropy,
// disassembly, threat) to JSON with duration metadata.
// PASS_NAME_MAP renames "disasm" to "disassembly" for the
// API. extract_file iterates multipart fields looking for
// the "file" field name.
//
// Connects to:
//   state.rs       - AppState (engine, db, config)
//   db/queries.rs  - find_slug_by_sha256, insert_analysis,
//                     insert_pass_result
//   db/models.rs   - NewAnalysis, NewPassResult
//   error.rs       - ApiError

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Multipart, State};
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use axumortem_engine::context::AnalysisContext;
use axumortem_engine::pass::PassReport;

use crate::db::models::{NewAnalysis, NewPassResult};
use crate::db::queries;
use crate::error::ApiError;
use crate::state::AppState;

const SLUG_LENGTH: usize = 12;

const PASS_NAME_MAP: &[(&str, &str)] = &[
    ("disasm", "disassembly"),
];

#[derive(Serialize)]
pub(crate) struct UploadResponse {
    slug: String,
    cached: bool,
}

pub async fn handle(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, ApiError> {
    let (file_name, data) =
        extract_file(&mut multipart).await?;

    let sha256 =
        axumortem_engine::sha256_hex(&data);

    if let Some(slug) =
        queries::find_slug_by_sha256(
            &state.db, &sha256,
        )
        .await?
    {
        return Ok(Json(UploadResponse {
            slug,
            cached: true,
        }));
    }

    let engine = Arc::clone(&state.engine);
    let name_clone = file_name.clone();

    let (ctx, report) =
        tokio::task::spawn_blocking(move || {
            engine.analyze(&data, &name_clone)
        })
        .await?;

    let fmt = ctx.format_result.as_ref();
    let threat = ctx.threat_result.as_ref();
    let slug = sha256[..SLUG_LENGTH].to_string();

    let new_analysis = NewAnalysis {
        sha256,
        file_name,
        file_size: ctx.file_size as i64,
        format: fmt
            .map(|f| f.format.to_string())
            .unwrap_or_default(),
        architecture: fmt
            .map(|f| f.architecture.to_string())
            .unwrap_or_default(),
        entry_point: fmt
            .map(|f| f.entry_point as i64),
        threat_score: threat
            .map(|t| t.total_score as i32),
        risk_level: threat
            .map(|t| t.risk_level.to_string()),
        slug: slug.clone(),
    };

    let mut tx = state.db.begin().await?;

    let row =
        queries::insert_analysis(&mut tx, &new_analysis)
            .await?;

    let pass_results =
        build_pass_results(&ctx, &report, row.id)?;
    for pr in &pass_results {
        queries::insert_pass_result(&mut tx, pr).await?;
    }

    tx.commit().await?;

    Ok(Json(UploadResponse {
        slug,
        cached: false,
    }))
}

async fn extract_file(
    multipart: &mut Multipart,
) -> Result<(String, Vec<u8>), ApiError> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::Internal {
            reason: e.to_string(),
        })?
    {
        if field.name() == Some("file") {
            let name = field
                .file_name()
                .unwrap_or("unknown")
                .to_string();
            let data = field
                .bytes()
                .await
                .map_err(|e| ApiError::Internal {
                    reason: e.to_string(),
                })?;
            return Ok((name, data.to_vec()));
        }
    }

    Err(ApiError::NoFile)
}

fn api_name(engine_name: &str) -> &str {
    for &(from, to) in PASS_NAME_MAP {
        if engine_name == from {
            return to;
        }
    }
    engine_name
}

fn build_pass_results(
    ctx: &AnalysisContext,
    report: &PassReport,
    analysis_id: Uuid,
) -> Result<Vec<NewPassResult>, serde_json::Error> {
    let durations: HashMap<&str, u64> = report
        .outcomes
        .iter()
        .map(|o| (o.name, o.duration_ms))
        .collect();

    let mut results = Vec::new();

    macro_rules! add_pass {
        ($field:ident, $name:expr) => {
            if let Some(ref r) = ctx.$field {
                results.push(NewPassResult {
                    analysis_id,
                    pass_name: api_name($name)
                        .to_string(),
                    result: serde_json::to_value(r)?,
                    duration_ms: durations
                        .get($name)
                        .map(|&d| d as i32),
                });
            }
        };
    }

    add_pass!(format_result, "format");
    add_pass!(import_result, "imports");
    add_pass!(string_result, "strings");
    add_pass!(entropy_result, "entropy");
    add_pass!(disassembly_result, "disasm");
    add_pass!(threat_result, "threat");

    Ok(results)
}
