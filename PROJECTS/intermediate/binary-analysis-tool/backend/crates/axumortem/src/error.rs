// ©AngelaMos | 2026
// error.rs
//
// API error types and HTTP response mapping
//
// ApiError enumerates six error variants: NoFile (400),
// FileTooLarge (400), InvalidBinary (400),
// AnalysisFailed (500), NotFound (404), and Internal
// (500). Each variant maps to a JSON response body with
// an error code string and human-readable message via the
// IntoResponse implementation. From impls convert
// sqlx::Error, serde_json::Error, and
// tokio::task::JoinError into Internal variants.
//
// Connects to:
//   routes/upload.rs   - returned from upload handler
//   routes/analysis.rs - returned from analysis lookup

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

pub enum ApiError {
    NoFile,
    FileTooLarge { max_bytes: usize },
    InvalidBinary { reason: String },
    AnalysisFailed { reason: String },
    NotFound { resource: String },
    Internal { reason: String },
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal {
            reason: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        Self::Internal {
            reason: e.to_string(),
        }
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::Internal {
            reason: e.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::NoFile => (
                StatusCode::BAD_REQUEST,
                "NO_FILE",
                "No file was provided in the upload"
                    .to_string(),
            ),
            Self::FileTooLarge { max_bytes } => (
                StatusCode::BAD_REQUEST,
                "FILE_TOO_LARGE",
                format!(
                    "File exceeds maximum allowed size of {} bytes",
                    max_bytes
                ),
            ),
            Self::InvalidBinary { reason } => (
                StatusCode::BAD_REQUEST,
                "INVALID_BINARY",
                reason,
            ),
            Self::AnalysisFailed { reason } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "ANALYSIS_FAILED",
                reason,
            ),
            Self::NotFound { resource } => (
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                format!("{resource} not found"),
            ),
            Self::Internal { reason } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                reason,
            ),
        };

        (
            status,
            Json(ErrorBody {
                error: ErrorDetail { code, message },
            }),
        )
            .into_response()
    }
}
