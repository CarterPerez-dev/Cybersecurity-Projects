// ©AngelaMos | 2026
// main.rs
//
// Axumortem web server entry point
//
// Bootstraps the Axum HTTP server with clap-driven CLI
// configuration, tracing subscriber initialization with
// EnvFilter, PostgreSQL connection pool (max 20
// connections) via SQLx PgPoolOptions, automatic database
// migrations, and AnalysisEngine initialization. Assembles
// AppState from the pool, engine, and config, then applies
// tower layers for HTTP tracing, CORS, and body size
// limits before binding a TCP listener. Graceful shutdown
// is handled via ctrl_c signal.
//
// Connects to:
//   config.rs     - AppConfig (clap Parser)
//   state.rs      - AppState
//   db/mod.rs     - run_migrations
//   middleware/    - cors::layer
//   routes/mod.rs - api_router

mod config;
mod db;
mod error;
mod middleware;
mod routes;
mod state;

use std::sync::Arc;

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use config::AppConfig;
use state::AppState;

const DB_MAX_CONNECTIONS: u32 = 20;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = AppConfig::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    EnvFilter::new(
                        "info,tower_http=debug",
                    )
                }),
        )
        .init();

    let db = PgPoolOptions::new()
        .max_connections(DB_MAX_CONNECTIONS)
        .connect(&config.database_url)
        .await
        .context("failed to connect to database")?;

    db::run_migrations(&db)
        .await
        .context("failed to run database migrations")?;

    let engine = axumortem_engine::AnalysisEngine::new()
        .context(
            "failed to initialize analysis engine",
        )?;

    let config = Arc::new(config);

    let state = AppState {
        db,
        engine: Arc::new(engine),
        config: Arc::clone(&config),
    };

    let layers = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(middleware::cors::layer(&config))
        .layer(DefaultBodyLimit::max(
            config.max_upload_size,
        ));

    let app =
        routes::api_router().layer(layers).with_state(state);

    let bind_address = config.bind_address();
    let listener =
        tokio::net::TcpListener::bind(&bind_address)
            .await
            .context("failed to bind TCP listener")?;

    tracing::info!("listening on {}", bind_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl+c handler");
    tracing::info!("shutdown signal received");
}
