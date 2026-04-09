// ©AngelaMos | 2026
// integration.rs
//
// Full pipeline integration tests
//
// Exercises the AnalysisEngine end-to-end against test
// fixture binaries. full_pipeline_elf loads hello_elf and
// asserts all six passes succeed, format result is ELF
// with non-empty sections, all context slots are populated,
// disassembly finds functions and instructions, and threat
// score has 8 categories capped at 100.
// full_pipeline_stripped_elf verifies stripped binary
// detection and full pipeline completion.
// sha256_computed_correctly asserts the context SHA-256 is
// a valid 64-character hex string. invalid_binary_handled
// feeds 4 bytes of garbage and asserts the format pass
// fails while the engine does not panic.
//
// Connects to:
//   lib.rs   - AnalysisEngine
//   types.rs - BinaryFormat

use axumortem_engine::types::BinaryFormat;
use axumortem_engine::AnalysisEngine;

fn load_fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR"),
    );
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("fixture {path}: {e}"))
}

#[test]
fn full_pipeline_elf() {
    let engine = AnalysisEngine::new().unwrap();
    let data = load_fixture("hello_elf");
    let (ctx, report) =
        engine.analyze(&data, "hello_elf");

    assert!(
        report.all_succeeded(),
        "all passes should succeed: {:?}",
        report
            .failed_passes()
            .iter()
            .map(|p| (p.name, p.error_message.as_deref()))
            .collect::<Vec<_>>()
    );

    let fmt = ctx.format_result.as_ref().unwrap();
    assert_eq!(fmt.format, BinaryFormat::Elf);
    assert!(!fmt.sections.is_empty());

    assert!(ctx.import_result.is_some());
    assert!(ctx.string_result.is_some());
    assert!(ctx.entropy_result.is_some());
    assert!(ctx.disassembly_result.is_some());

    let disasm =
        ctx.disassembly_result.as_ref().unwrap();
    assert!(disasm.total_functions > 0);
    assert!(disasm.total_instructions > 0);

    let threat = ctx.threat_result.as_ref().unwrap();
    assert!(threat.total_score <= 100);
    assert_eq!(threat.categories.len(), 8);
    assert!(!threat.summary.is_empty());
}

#[test]
fn full_pipeline_stripped_elf() {
    let engine = AnalysisEngine::new().unwrap();
    let data = load_fixture("hello_elf_stripped");
    let (ctx, report) =
        engine.analyze(&data, "hello_elf_stripped");

    assert!(report.all_succeeded());

    let fmt = ctx.format_result.as_ref().unwrap();
    assert!(fmt.is_stripped);

    assert!(ctx.threat_result.is_some());
}

#[test]
fn sha256_computed_correctly() {
    let engine = AnalysisEngine::new().unwrap();
    let data = load_fixture("hello_elf");
    let (ctx, _) = engine.analyze(&data, "test.bin");

    assert_eq!(ctx.sha256.len(), 64);
    assert!(ctx.sha256.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn invalid_binary_handled() {
    let engine = AnalysisEngine::new().unwrap();
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let (_, report) =
        engine.analyze(&data, "garbage.bin");

    assert!(
        !report.all_succeeded(),
        "invalid binary should cause format pass failure"
    );
    assert!(report
        .failed_passes()
        .iter()
        .any(|p| p.name == "format"));
}
