// ©AngelaMos | 2026
// config.rs
//
// Application configuration via CLI arguments and
// environment variables
//
// AppConfig derives clap::Parser to accept database_url,
// host (default 0.0.0.0), port (default 3000),
// max_upload_size (default 50 MiB), and cors_origin
// (default wildcard). Each field maps to both a --long
// flag and an environment variable. bind_address formats
// the host:port string for the TCP listener.
//
// Connects to:
//   main.rs          - parsed at startup
//   state.rs         - stored as Arc<AppConfig>
//   middleware/cors.rs - cors_origin read by layer()

use clap::Parser;

const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 3000;
const DEFAULT_MAX_UPLOAD_BYTES: usize = 52_428_800;
const DEFAULT_CORS_ORIGIN: &str = "*";

#[derive(Parser, Debug)]
pub struct AppConfig {
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,

    #[arg(long, env = "HOST", default_value = DEFAULT_HOST)]
    pub host: String,

    #[arg(long, env = "PORT", default_value_t = DEFAULT_PORT)]
    pub port: u16,

    #[arg(long, env = "MAX_UPLOAD_SIZE", default_value_t = DEFAULT_MAX_UPLOAD_BYTES)]
    pub max_upload_size: usize,

    #[arg(long, env = "CORS_ORIGIN", default_value = DEFAULT_CORS_ORIGIN)]
    pub cors_origin: String,
}

impl AppConfig {
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
