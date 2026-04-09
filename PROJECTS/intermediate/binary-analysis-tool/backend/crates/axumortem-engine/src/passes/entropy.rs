// ©AngelaMos | 2026
// entropy.rs
//
// Shannon entropy analysis and packing detection pass
//
// EntropyPass depends on format and computes Shannon
// entropy for the overall binary and each section
// individually. shannon_entropy calculates bits-per-byte
// over a 256-bucket frequency distribution.
// classify_entropy maps values to five bands: Plaintext
// (<3.5), NativeCode (<6.0), Compressed (<7.0), Packed
// (<7.2), and Encrypted (>=7.2). Per-section analysis
// flags anomalies via EntropyFlag: HighEntropy (>7.0),
// HighVirtualToRawRatio (>10x), EmptyRawData (raw=0 with
// virtual>0), Rwx (read+write+execute permissions), and
// PackerSectionName. PACKER_SECTION_NAMES maps 15 known
// section names to packers: UPX (UPX0/1/2), Themida,
// VMProtect (.vmp0/1/2), ASPack (.aspack/.adata),
// PECompact (PEC2TO/PEC2/pec1), MPRESS (.MPRESS1/2),
// and Enigma (.enigma1/2). Structural packing indicators
// track empty-raw-with-executable-virtual sections and
// high virtual-to-raw ratios; two or more structural
// indicators trigger packing_detected. find_ep_section
// locates the entry point section and checks for PUSHAD
// (0x60) as the first byte, a classic packer stub marker.
// Unit tests verify zero-entropy, uniform distribution
// (~8.0 bits), empty data, classification thresholds,
// packer section name detection, high entropy flagging,
// UPX packer detection, ELF entropy analysis, and context
// population.
//
// Connects to:
//   pass.rs        - AnalysisPass trait, Sealed
//   context.rs     - AnalysisContext
//   formats/mod.rs - SectionInfo
//   types.rs       - EntropyClassification, EntropyFlag
//   error.rs       - EngineError

use serde::{Deserialize, Serialize};

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::formats::SectionInfo;
use crate::pass::{AnalysisPass, Sealed};
use crate::types::{
    EntropyClassification, EntropyFlag,
};

const PLAINTEXT_MAX: f64 = 3.5;
const NATIVE_CODE_MAX: f64 = 6.0;
const COMPRESSED_MAX: f64 = 7.0;
const PACKED_MAX: f64 = 7.2;

const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;
const VIRTUAL_RAW_RATIO_THRESHOLD: f64 = 10.0;

const BYTE_RANGE: usize = 256;

const STRUCTURAL_INDICATORS_FOR_PACKING: usize = 2;

const PUSHAD_OPCODE: u8 = 0x60;

const PACKER_SECTION_NAMES: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".themida", "Themida"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    ("PEC2TO", "PECompact"),
    ("PEC2", "PECompact"),
    ("pec1", "PECompact"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub overall_entropy: f64,
    pub sections: Vec<SectionEntropy>,
    pub packing_detected: bool,
    pub packer_name: Option<String>,
    pub packing_indicators: Vec<PackingIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub entropy: f64,
    pub size: u64,
    pub classification: EntropyClassification,
    pub virtual_to_raw_ratio: f64,
    pub is_anomalous: bool,
    pub flags: Vec<EntropyFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackingIndicator {
    pub indicator_type: String,
    pub description: String,
    pub evidence: String,
    pub packer_name: Option<String>,
}

pub struct EntropyPass;

impl Sealed for EntropyPass {}

impl AnalysisPass for EntropyPass {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn dependencies(&self) -> &[&'static str] {
        &["format"]
    }

    fn run(
        &self,
        ctx: &mut AnalysisContext,
    ) -> Result<(), EngineError> {
        let format_result = ctx
            .format_result
            .as_ref()
            .ok_or_else(|| EngineError::MissingDependency {
                pass: "entropy".into(),
                dependency: "format".into(),
            })?;

        let data = ctx.data();
        let result = analyze_entropy(
            data,
            &format_result.sections,
            format_result.entry_point,
        );
        ctx.entropy_result = Some(result);
        Ok(())
    }
}

fn analyze_entropy(
    data: &[u8],
    sections: &[SectionInfo],
    entry_point: u64,
) -> EntropyResult {
    let overall_entropy = shannon_entropy(data);
    let mut section_entropies = Vec::new();
    let mut packing_indicators = Vec::new();
    let mut packer_name: Option<String> = None;
    let mut structural_count = 0;

    for section in sections {
        let section_data = read_section_data(
            data,
            section.raw_offset,
            section.raw_size,
        );
        let entropy = if section_data.is_empty() {
            0.0
        } else {
            shannon_entropy(section_data)
        };
        let classification = classify_entropy(entropy);
        let vr_ratio = if section.raw_size > 0 {
            section.virtual_size as f64
                / section.raw_size as f64
        } else {
            0.0
        };

        let mut flags = Vec::new();

        if entropy > HIGH_ENTROPY_THRESHOLD {
            flags.push(EntropyFlag::HighEntropy);
        }
        if vr_ratio > VIRTUAL_RAW_RATIO_THRESHOLD {
            flags.push(EntropyFlag::HighVirtualToRawRatio);
        }
        if section.raw_size == 0
            && section.virtual_size > 0
        {
            flags.push(EntropyFlag::EmptyRawData);
        }
        if section.permissions.is_rwx() {
            flags.push(EntropyFlag::Rwx);
        }

        if let Some(packer) =
            detect_packer_by_section(&section.name)
        {
            flags.push(EntropyFlag::PackerSectionName);
            packing_indicators.push(PackingIndicator {
                indicator_type: "section_name".into(),
                description: format!(
                    "Section name matches {packer} packer"
                ),
                evidence: section.name.clone(),
                packer_name: Some(packer.into()),
            });
            if packer_name.is_none() {
                packer_name = Some(packer.into());
            }
        }

        if section.raw_size == 0
            && section.virtual_size > 0
            && section.permissions.execute
        {
            structural_count += 1;
            packing_indicators.push(PackingIndicator {
                indicator_type: "structural".into(),
                description:
                    "Empty raw data with executable \
                     virtual section"
                        .into(),
                evidence: format!(
                    "section={} raw=0 virtual={}",
                    section.name, section.virtual_size
                ),
                packer_name: None,
            });
        }

        if vr_ratio > VIRTUAL_RAW_RATIO_THRESHOLD {
            structural_count += 1;
            packing_indicators.push(PackingIndicator {
                indicator_type: "structural".into(),
                description:
                    "High virtual to raw size ratio"
                        .into(),
                evidence: format!(
                    "section={} ratio={vr_ratio:.1}",
                    section.name
                ),
                packer_name: None,
            });
        }

        let is_anomalous = !flags.is_empty();

        section_entropies.push(SectionEntropy {
            name: section.name.clone(),
            entropy,
            size: section.raw_size,
            classification,
            virtual_to_raw_ratio: vr_ratio,
            is_anomalous,
            flags,
        });
    }

    if let Some(ep_section) = find_ep_section(
        sections,
        entry_point,
    ) {
        let ep_file_offset = entry_point
            .wrapping_sub(ep_section.virtual_address)
            .wrapping_add(ep_section.raw_offset);
        if let Some(&first_byte) =
            data.get(ep_file_offset as usize)
        {
            if first_byte == PUSHAD_OPCODE {
                packing_indicators.push(
                    PackingIndicator {
                        indicator_type: "entry_point"
                            .into(),
                        description:
                            "PUSHAD at entry point"
                                .into(),
                        evidence: format!(
                            "byte 0x{PUSHAD_OPCODE:02x} \
                             at EP offset 0x{ep_file_offset:x}"
                        ),
                        packer_name: None,
                    },
                );
            }
        }
    }

    let packing_detected = packer_name.is_some()
        || structural_count
            >= STRUCTURAL_INDICATORS_FOR_PACKING;

    EntropyResult {
        overall_entropy,
        sections: section_entropies,
        packing_detected,
        packer_name,
        packing_indicators,
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; BYTE_RANGE];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn classify_entropy(
    entropy: f64,
) -> EntropyClassification {
    if entropy < PLAINTEXT_MAX {
        EntropyClassification::Plaintext
    } else if entropy < NATIVE_CODE_MAX {
        EntropyClassification::NativeCode
    } else if entropy < COMPRESSED_MAX {
        EntropyClassification::Compressed
    } else if entropy < PACKED_MAX {
        EntropyClassification::Packed
    } else {
        EntropyClassification::Encrypted
    }
}

fn detect_packer_by_section(
    name: &str,
) -> Option<&'static str> {
    PACKER_SECTION_NAMES
        .iter()
        .find(|&&(section_name, _)| section_name == name)
        .map(|&(_, packer)| packer)
}

fn read_section_data(
    data: &[u8],
    offset: u64,
    size: u64,
) -> &[u8] {
    if size == 0 {
        return &[];
    }
    let start = offset as usize;
    let end = start.saturating_add(size as usize);
    if start >= data.len() || end > data.len() {
        return &[];
    }
    &data[start..end]
}

fn find_ep_section(
    sections: &[SectionInfo],
    entry_point: u64,
) -> Option<&SectionInfo> {
    sections.iter().find(|s| {
        entry_point >= s.virtual_address
            && entry_point
                < s.virtual_address + s.virtual_size
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::context::BinarySource;
    use crate::types::SectionPermissions;

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
    fn entropy_all_zeros() {
        let data = vec![0u8; 1024];
        assert!(shannon_entropy(&data) < 0.001);
    }

    #[test]
    fn entropy_uniform_distribution() {
        let data: Vec<u8> =
            (0..=255u8).cycle().take(1024).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "uniform distribution should be ~8.0, got {e}"
        );
    }

    #[test]
    fn entropy_empty_data() {
        assert!(
            shannon_entropy(&[]) < 0.001,
            "empty data should have zero entropy"
        );
    }

    #[test]
    fn entropy_classification_thresholds() {
        assert_eq!(
            classify_entropy(2.0),
            EntropyClassification::Plaintext
        );
        assert_eq!(
            classify_entropy(5.0),
            EntropyClassification::NativeCode
        );
        assert_eq!(
            classify_entropy(6.5),
            EntropyClassification::Compressed
        );
        assert_eq!(
            classify_entropy(7.1),
            EntropyClassification::Packed
        );
        assert_eq!(
            classify_entropy(7.5),
            EntropyClassification::Encrypted
        );
    }

    #[test]
    fn packer_section_name_detection() {
        assert_eq!(
            detect_packer_by_section("UPX0"),
            Some("UPX")
        );
        assert_eq!(
            detect_packer_by_section("UPX1"),
            Some("UPX")
        );
        assert_eq!(
            detect_packer_by_section(".vmp0"),
            Some("VMProtect")
        );
        assert_eq!(
            detect_packer_by_section(".themida"),
            Some("Themida")
        );
        assert_eq!(
            detect_packer_by_section(".text"),
            None
        );
    }

    #[test]
    fn section_flags_high_entropy() {
        let sections = vec![SectionInfo {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_offset: 0,
            raw_size: 256,
            permissions: SectionPermissions {
                read: true,
                write: false,
                execute: true,
            },
            sha256: String::new(),
        }];

        let data: Vec<u8> =
            (0..=255u8).cycle().take(256).collect();
        let result =
            analyze_entropy(&data, &sections, 0x1000);
        let text_section = &result.sections[0];
        assert!(
            text_section.entropy > HIGH_ENTROPY_THRESHOLD
        );
        assert!(text_section
            .flags
            .contains(&EntropyFlag::HighEntropy));
        assert!(text_section.is_anomalous);
    }

    #[test]
    fn packer_detection_by_section_name() {
        let sections = vec![
            SectionInfo {
                name: "UPX0".into(),
                virtual_address: 0x1000,
                virtual_size: 0x10000,
                raw_offset: 0,
                raw_size: 0,
                permissions: SectionPermissions {
                    read: true,
                    write: true,
                    execute: true,
                },
                sha256: String::new(),
            },
            SectionInfo {
                name: "UPX1".into(),
                virtual_address: 0x11000,
                virtual_size: 0x5000,
                raw_offset: 0x200,
                raw_size: 0x4000,
                permissions: SectionPermissions {
                    read: true,
                    write: false,
                    execute: true,
                },
                sha256: String::new(),
            },
        ];

        let data = vec![0u8; 0x4200];
        let result =
            analyze_entropy(&data, &sections, 0x11000);
        assert!(result.packing_detected);
        assert_eq!(
            result.packer_name,
            Some("UPX".into())
        );
        assert!(!result.packing_indicators.is_empty());
    }

    #[test]
    fn elf_entropy_analysis() {
        let data = load_fixture("hello_elf");
        let format_result =
            crate::formats::parse_format(&data)
                .unwrap();
        let result = analyze_entropy(
            &data,
            &format_result.sections,
            format_result.entry_point,
        );

        assert!(result.overall_entropy > 0.0);
        assert!(!result.sections.is_empty());
        assert!(!result.packing_detected);
    }

    #[test]
    fn entropy_pass_populates_context() {
        let data = load_fixture("hello_elf");
        let mut ctx = make_ctx(data);

        crate::passes::format::FormatPass
            .run(&mut ctx)
            .unwrap();
        assert!(ctx.format_result.is_some());

        EntropyPass.run(&mut ctx).unwrap();
        assert!(ctx.entropy_result.is_some());

        let result = ctx.entropy_result.unwrap();
        assert!(result.overall_entropy > 0.0);
    }
}
