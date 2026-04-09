// ©AngelaMos | 2026
// context.rs
//
// Analysis context holding binary data and accumulated pass results
//
// BinarySource is a two-variant enum: Mapped wraps a memmap2
// Mmap for disk-backed files, Buffered wraps an Arc<[u8]> for
// in-memory data received over the network. Both implement
// AsRef<[u8]> so passes access the binary through a uniform
// data() method. AnalysisContext is constructed with a source,
// SHA-256 digest, filename, and file size. Each analysis pass
// populates its corresponding Option field (format_result,
// import_result, string_result, entropy_result,
// disassembly_result, threat_result) as it runs, building up
// the full analysis incrementally.
//
// Connects to:
//   formats/mod.rs     - FormatResult
//   passes/disasm.rs   - DisassemblyResult
//   passes/entropy.rs  - EntropyResult
//   passes/imports.rs  - ImportResult
//   passes/strings.rs  - StringResult
//   passes/threat.rs   - ThreatResult

use std::sync::Arc;

use memmap2::Mmap;

use crate::formats::FormatResult;
use crate::passes::disasm::DisassemblyResult;
use crate::passes::entropy::EntropyResult;
use crate::passes::imports::ImportResult;
use crate::passes::strings::StringResult;
use crate::passes::threat::ThreatResult;

pub enum BinarySource {
    Mapped(Mmap),
    Buffered(Arc<[u8]>),
}

impl AsRef<[u8]> for BinarySource {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Mapped(mmap) => mmap,
            Self::Buffered(buf) => buf,
        }
    }
}

pub struct AnalysisContext {
    source: BinarySource,
    pub sha256: String,
    pub file_name: String,
    pub file_size: u64,
    pub format_result: Option<FormatResult>,
    pub import_result: Option<ImportResult>,
    pub string_result: Option<StringResult>,
    pub entropy_result: Option<EntropyResult>,
    pub disassembly_result: Option<DisassemblyResult>,
    pub threat_result: Option<ThreatResult>,
}

impl AnalysisContext {
    pub fn new(
        source: BinarySource,
        sha256: String,
        file_name: String,
        file_size: u64,
    ) -> Self {
        Self {
            source,
            sha256,
            file_name,
            file_size,
            format_result: None,
            import_result: None,
            string_result: None,
            entropy_result: None,
            disassembly_result: None,
            threat_result: None,
        }
    }

    pub fn data(&self) -> &[u8] {
        self.source.as_ref()
    }
}
