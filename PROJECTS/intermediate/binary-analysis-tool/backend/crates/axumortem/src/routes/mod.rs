// ©AngelaMos | 2026
// mod.rs
//
// Route module exports and API router construction
//
// api_router assembles the Axum Router with three
// endpoints: GET /api/health (health check), POST
// /api/upload (binary upload and analysis), and GET
// /api/analysis/{slug} (analysis result retrieval).
//
// Connects to:
//   routes/health.rs   - check handler
//   routes/upload.rs   - handle handler
//   routes/analysis.rs - get_by_slug handler
//   state.rs           - AppState

mod analysis;
mod health;
mod upload;

use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

pub fn api_router() -> Router<AppState> {
    Router::new()
        .route("/api/health", get(health::check))
        .route("/api/upload", post(upload::handle))
        .route(
            "/api/analysis/{slug}",
            get(analysis::get_by_slug),
        )
}
