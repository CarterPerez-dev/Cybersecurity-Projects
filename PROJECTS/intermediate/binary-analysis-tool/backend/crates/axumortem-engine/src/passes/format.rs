// ©AngelaMos | 2026
// format.rs
//
// Format analysis pass (binary header parsing)
//
// FormatPass is the first pass in the pipeline with no
// dependencies. It delegates to formats::parse_format which
// dispatches to the ELF, PE, or Mach-O parser and stores the
// resulting FormatResult in the context. All subsequent passes
// depend on this pass for section layout, architecture, and
// entry point information. Unit tests verify ELF metadata
// extraction, section and segment presence, stripped binary
// detection, ELF info population, section hash computation,
// invalid binary rejection, and context population.
//
// Connects to:
//   formats/mod.rs - parse_format, FormatResult
//   pass.rs        - AnalysisPass trait, Sealed
//   context.rs     - AnalysisContext

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::formats;
use crate::pass::{AnalysisPass, Sealed};

pub struct FormatPass;

impl Sealed for FormatPass {}

impl AnalysisPass for FormatPass {
    fn name(&self) -> &'static str {
        "format"
    }

    fn dependencies(&self) -> &[&'static str] {
        &[]
    }

    fn run(
        &self,
        ctx: &mut AnalysisContext,
    ) -> Result<(), EngineError> {
        let result =
            formats::parse_format(ctx.data())?;
        ctx.format_result = Some(result);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::context::{AnalysisContext, BinarySource};
    use crate::formats::{self, FormatAnomaly};
    use crate::types::{Architecture, BinaryFormat, Endianness};

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR"),
        );
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!("fixture {path}: {e}")
        })
    }

    fn make_ctx(data: Vec<u8>) -> AnalysisContext {
        let size = data.len() as u64;
        AnalysisContext::new(
            BinarySource::Buffered(Arc::from(data)),
            "deadbeef".into(),
            "test.bin".into(),
            size,
        )
    }

    #[test]
    fn parse_elf_basic_metadata() {
        let data = load_fixture("hello_elf");
        let result =
            formats::parse_format(&data).unwrap();

        assert_eq!(result.format, BinaryFormat::Elf);
        assert_eq!(
            result.architecture,
            Architecture::X86_64
        );
        assert_eq!(result.bits, 64);
        assert_eq!(
            result.endianness,
            Endianness::Little
        );
        assert!(result.entry_point > 0);
        assert!(result.is_pie);
        assert!(!result.is_stripped);
    }

    #[test]
    fn parse_elf_sections_present() {
        let data = load_fixture("hello_elf");
        let result =
            formats::parse_format(&data).unwrap();

        assert!(!result.sections.is_empty());
        let text = result
            .sections
            .iter()
            .find(|s| s.name == ".text");
        assert!(text.is_some());
        assert!(text.unwrap().permissions.execute);
    }

    #[test]
    fn parse_elf_segments_present() {
        let data = load_fixture("hello_elf");
        let result =
            formats::parse_format(&data).unwrap();

        assert!(!result.segments.is_empty());
        let load_segments: Vec<_> = result
            .segments
            .iter()
            .filter(|s| {
                s.name.as_deref() == Some("LOAD")
            })
            .collect();
        assert!(!load_segments.is_empty());
    }

    #[test]
    fn parse_elf_stripped_detection() {
        let data =
            load_fixture("hello_elf_stripped");
        let result =
            formats::parse_format(&data).unwrap();

        assert!(result.is_stripped);
        assert!(result.anomalies.iter().any(|a| {
            matches!(
                a,
                FormatAnomaly::StrippedBinary
            )
        }));
    }

    #[test]
    fn parse_elf_info_populated() {
        let data = load_fixture("hello_elf");
        let result =
            formats::parse_format(&data).unwrap();

        let elf_info = result.elf_info.unwrap();
        assert!(!elf_info.os_abi.is_empty());
        assert!(!elf_info.elf_type.is_empty());
        assert!(elf_info.interpreter.is_some());
        assert!(elf_info.gnu_relro);
    }

    #[test]
    fn parse_elf_section_hashes() {
        let data = load_fixture("hello_elf");
        let result =
            formats::parse_format(&data).unwrap();

        let text = result
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .unwrap();
        assert!(
            !text.sha256.is_empty(),
            ".text section should have a hash"
        );
        assert_eq!(text.sha256.len(), 64);
    }

    #[test]
    fn parse_invalid_binary() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = formats::parse_format(&data);
        assert!(result.is_err());
    }

    #[test]
    fn format_pass_populates_context() {
        use crate::pass::AnalysisPass;
        use super::FormatPass;

        let data = load_fixture("hello_elf");
        let mut ctx = make_ctx(data);
        assert!(ctx.format_result.is_none());

        FormatPass.run(&mut ctx).unwrap();
        assert!(ctx.format_result.is_some());

        let fmt = ctx.format_result.unwrap();
        assert_eq!(fmt.format, BinaryFormat::Elf);
    }
}
