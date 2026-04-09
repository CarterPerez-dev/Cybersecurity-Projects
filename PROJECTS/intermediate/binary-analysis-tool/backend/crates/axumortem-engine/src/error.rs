// ©AngelaMos | 2026
// error.rs
//
// Engine error type hierarchy
//
// EngineError is a thiserror enum covering all failure modes
// in the analysis pipeline: InvalidBinary for unparseable
// input, UnsupportedFormat and UnsupportedArchitecture for
// recognized but unhandled binaries, MissingDependency when
// a pass requires results from an earlier pass that did not
// run, PassFailed wrapping the source error from any pass,
// Yara for rule compilation or scan failures, and Io for
// filesystem operations. The From<std::io::Error> impl
// enables transparent propagation with the ? operator.

#[derive(thiserror::Error, Debug)]
pub enum EngineError {
    #[error("invalid binary: {reason}")]
    InvalidBinary { reason: String },

    #[error("unsupported format: {format}")]
    UnsupportedFormat { format: String },

    #[error("unsupported architecture: {arch}")]
    UnsupportedArchitecture { arch: String },

    #[error("pass '{pass}' missing dependency: {dependency}")]
    MissingDependency {
        pass: String,
        dependency: String,
    },

    #[error("pass '{pass}' failed")]
    PassFailed {
        pass: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("yara error: {0}")]
    Yara(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
