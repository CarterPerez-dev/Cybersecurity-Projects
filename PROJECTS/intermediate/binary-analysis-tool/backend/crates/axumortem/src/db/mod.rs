// ©AngelaMos | 2026
// mod.rs
//
// Database module exports and migration runner
//
// Re-exports the models and queries submodules.
// run_migrations executes embedded SQLx migrations from
// the ./migrations directory against the provided PgPool.
//
// Connects to:
//   main.rs      - called at startup
//   db/models.rs - row and input structs
//   db/queries.rs - SQL query functions

pub mod models;
pub mod queries;

use sqlx::PgPool;

pub async fn run_migrations(
    pool: &PgPool,
) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}
