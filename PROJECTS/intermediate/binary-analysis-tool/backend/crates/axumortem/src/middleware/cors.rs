// ©AngelaMos | 2026
// cors.rs
//
// CORS middleware configuration
//
// layer() builds a tower-http CorsLayer allowing GET,
// POST, and OPTIONS methods with Content-Type and Accept
// headers. When cors_origin is "*" the layer permits any
// origin; otherwise it parses the configured origin string
// into a single allowed HeaderValue.
//
// Connects to:
//   config.rs - AppConfig.cors_origin
//   main.rs   - applied as tower layer

use axum::http::header::{HeaderName, ACCEPT, CONTENT_TYPE};
use axum::http::Method;
use tower_http::cors::{Any, CorsLayer};

use crate::config::AppConfig;

const ALLOWED_METHODS: [Method; 3] =
    [Method::GET, Method::POST, Method::OPTIONS];

const ALLOWED_HEADERS: [HeaderName; 2] =
    [CONTENT_TYPE, ACCEPT];

pub fn layer(config: &AppConfig) -> CorsLayer {
    let base = CorsLayer::new()
        .allow_methods(ALLOWED_METHODS)
        .allow_headers(ALLOWED_HEADERS);

    if config.cors_origin == "*" {
        base.allow_origin(Any)
    } else {
        base.allow_origin([config
            .cors_origin
            .parse()
            .expect("invalid CORS origin header value")])
    }
}
