// ©AngelaMos | 2026
// mod.rs
//
// Analysis pass module exports
//
// Re-exports the six analysis pass submodules: format
// (binary header parsing), imports (import/export table
// extraction and suspicious API detection), strings
// (ASCII/UTF-16LE extraction and categorization), entropy
// (Shannon entropy per section and packing detection),
// disasm (recursive descent disassembly with CFG
// construction), and threat (weighted scoring across all
// pass results plus YARA rule matching).

pub mod disasm;
pub mod entropy;
pub mod format;
pub mod imports;
pub mod strings;
pub mod threat;
