// ©AngelaMos | 2026
// lib.rs
//
// Analysis engine entry point and binary pipeline coordinator
//
// Declares the AnalysisEngine struct which wires together six
// analysis passes (format, imports, strings, entropy, disasm,
// threat) via the PassManager's topological execution order.
// analyze() takes raw binary bytes and a filename, computes a
// SHA-256 digest, constructs an AnalysisContext backed by an
// Arc'd buffer, runs all passes sequentially, and returns the
// populated context alongside a PassReport of per-pass
// outcomes. sha256_hex is re-exported for callers that need
// hashing without a full analysis run.
//
// Connects to:
//   context.rs        - AnalysisContext, BinarySource
//   error.rs          - EngineError
//   pass.rs           - PassManager, PassReport, AnalysisPass
//   passes/format.rs  - FormatPass
//   passes/imports.rs - ImportPass
//   passes/strings.rs - StringPass
//   passes/entropy.rs - EntropyPass
//   passes/disasm.rs  - DisasmPass
//   passes/threat.rs  - ThreatPass

pub mod context;
pub mod error;
pub mod formats;
pub mod pass;
pub mod passes;
pub mod types;
pub mod yara;

use std::sync::Arc;

use sha2::{Digest, Sha256};

use context::{AnalysisContext, BinarySource};
use error::EngineError;
use pass::{PassManager, PassReport};
use passes::disasm::DisasmPass;
use passes::entropy::EntropyPass;
use passes::format::FormatPass;
use passes::imports::ImportPass;
use passes::strings::StringPass;
use passes::threat::ThreatPass;

pub struct AnalysisEngine {
    pass_manager: PassManager,
}

impl AnalysisEngine {
    pub fn new() -> Result<Self, EngineError> {
        let passes: Vec<Box<dyn pass::AnalysisPass>> =
            vec![
                Box::new(FormatPass),
                Box::new(ImportPass),
                Box::new(StringPass),
                Box::new(EntropyPass),
                Box::new(DisasmPass),
                Box::new(ThreatPass),
            ];

        let pass_manager = PassManager::new(passes);

        Ok(Self { pass_manager })
    }

    pub fn analyze(
        &self,
        data: &[u8],
        file_name: &str,
    ) -> (AnalysisContext, PassReport) {
        let sha256 = compute_sha256(data);
        let file_size = data.len() as u64;
        let mut ctx = AnalysisContext::new(
            BinarySource::Buffered(Arc::from(
                data.to_vec(),
            )),
            sha256,
            file_name.to_string(),
            file_size,
        );
        let report =
            self.pass_manager.run_all(&mut ctx);
        (ctx, report)
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    compute_sha256(data)
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
