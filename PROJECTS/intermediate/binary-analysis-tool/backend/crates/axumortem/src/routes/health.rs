// ©AngelaMos | 2026
// health.rs
//
// Health check endpoint
//
// check executes a SELECT 1 probe against the PostgreSQL
// pool and returns a JSON HealthResponse with status "ok"
// and database connectivity as "connected" or
// "disconnected".
//
// Connects to:
//   state.rs - AppState.db

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub(crate) struct HealthResponse {
    status: &'static str,
    database: &'static str,
}

pub async fn check(
    State(state): State<AppState>,
) -> Json<HealthResponse> {
    let db_status =
        match sqlx::query("SELECT 1").execute(&state.db).await
        {
            Ok(_) => "connected",
            Err(_) => "disconnected",
        };

    Json(HealthResponse {
        status: "ok",
        database: db_status,
    })
}
