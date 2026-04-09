// ©AngelaMos | 2026
// pe.rs
//
// PE (Portable Executable) binary format parser
//
// Parses PE binaries via goblin::pe into a FormatResult.
// Extracts COFF machine type (i386/AMD64/ARM/ARM64),
// bitness, entry point, and optional header fields including
// image base, subsystem name, linker version, and DLL
// characteristics (ASLR, DEP, CFG, SEH, force integrity).
// build_sections maps PE sections with IMAGE_SCN_MEM_*
// permission flags and per-section SHA-256 hashes.
// detect_pe_anomalies flags zeroed, pre-1990, or post-2100
// timestamps, TLS callback presence, empty import tables,
// and overlay data beyond the last section. detect_rich_header
// scans for the "Rich" signature in the DOS stub. Function
// hints are collected from PE export RVAs for disassembly
// seeding.
//
// Connects to:
//   formats/mod.rs - FormatResult, PeInfo,
//                     PeDllCharacteristics, FormatAnomaly,
//                     SectionInfo, detect_common_anomalies,
//                     compute_section_hash
//   types.rs       - Architecture, BinaryFormat, Endianness,
//                     SectionPermissions

use goblin::pe::PE;

use super::{
    compute_section_hash, detect_common_anomalies,
    FormatAnomaly, FormatResult, PeDllCharacteristics, PeInfo,
    SectionInfo, SegmentInfo,
};
use crate::error::EngineError;
use crate::types::{
    Architecture, BinaryFormat, Endianness, SectionPermissions,
};

const COFF_MACHINE_I386: u16 = 0x14c;
const COFF_MACHINE_AMD64: u16 = 0x8664;
const COFF_MACHINE_ARM: u16 = 0x1c0;
const COFF_MACHINE_ARMNT: u16 = 0x1c4;
const COFF_MACHINE_ARM64: u16 = 0xaa64;

const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 =
    0x0080;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const IMAGE_SUBSYSTEM_POSIX_CUI: u16 = 7;
const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: u16 = 9;
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
const IMAGE_SUBSYSTEM_XBOX: u16 = 14;

const PE_TIMESTAMP_MIN_VALID: u32 = 631_152_000;
const PE_TIMESTAMP_MAX_VALID: u32 = 4_102_444_800;

const RICH_SIGNATURE: &[u8] = b"Rich";

pub fn parse_pe(
    pe: &PE,
    data: &[u8],
) -> Result<FormatResult, EngineError> {
    let architecture = map_architecture(
        pe.header.coff_header.machine,
    );
    let bits = if pe.is_64 { 64 } else { 32 };
    let endianness = Endianness::Little;
    let entry_point = pe.entry as u64;

    let is_stripped = pe.debug_data.is_none();
    let optional = pe.header.optional_header.as_ref();
    let dll_chars = optional.map_or(0, |oh| {
        oh.windows_fields.dll_characteristics
    });
    let is_pie = (dll_chars
        & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        != 0;
    let has_debug_info = pe.debug_data.is_some();

    let sections = build_sections(pe, data);
    let segments = build_segments(pe);

    let timestamp =
        pe.header.coff_header.time_date_stamp;
    let image_base = optional
        .map_or(0, |oh| oh.windows_fields.image_base);
    let subsystem_raw = optional
        .map_or(0, |oh| oh.windows_fields.subsystem);
    let linker_version = optional.map_or_else(
        || "0.0".into(),
        |oh| {
            format!(
                "{}.{}",
                oh.standard_fields.major_linker_version,
                oh.standard_fields.minor_linker_version,
            )
        },
    );

    let has_tls = pe.tls_data.is_some();
    let tls_callback_count = usize::from(has_tls);

    let max_section_end = pe
        .sections
        .iter()
        .map(|s| {
            s.pointer_to_raw_data as u64
                + s.size_of_raw_data as u64
        })
        .max()
        .unwrap_or(0);
    let file_size = data.len() as u64;
    let has_overlay =
        max_section_end > 0 && max_section_end < file_size;
    let overlay_size = if has_overlay {
        file_size - max_section_end
    } else {
        0
    };

    let pe_offset =
        pe.header.dos_header.pe_pointer as usize;
    let rich_header_present = detect_rich_header(
        data,
        pe_offset,
    );

    let pe_info = PeInfo {
        image_base,
        subsystem: subsystem_name(subsystem_raw),
        dll_characteristics: PeDllCharacteristics {
            aslr: (dll_chars
                & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                != 0,
            dep: (dll_chars
                & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
                != 0,
            cfg: (dll_chars
                & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
                != 0,
            no_seh: (dll_chars
                & IMAGE_DLLCHARACTERISTICS_NO_SEH)
                != 0,
            force_integrity: (dll_chars
                & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
                != 0,
        },
        timestamp,
        linker_version,
        tls_callback_count,
        has_overlay,
        overlay_size,
        rich_header_present,
    };

    let mut anomalies = detect_common_anomalies(
        &sections,
        entry_point,
        is_stripped,
    );
    detect_pe_anomalies(
        &mut anomalies,
        pe,
        timestamp,
        has_tls,
        has_overlay,
        max_section_end,
        file_size,
    );

    let function_hints: Vec<u64> = pe
        .exports
        .iter()
        .filter(|e| e.rva != 0)
        .map(|e| image_base + e.rva as u64)
        .filter(|&addr| addr != entry_point)
        .collect();

    Ok(FormatResult {
        format: BinaryFormat::Pe,
        architecture,
        bits,
        endianness,
        entry_point,
        is_stripped,
        is_pie,
        has_debug_info,
        sections,
        segments,
        anomalies,
        pe_info: Some(pe_info),
        elf_info: None,
        macho_info: None,
        function_hints,
    })
}

fn map_architecture(machine: u16) -> Architecture {
    match machine {
        COFF_MACHINE_I386 => Architecture::X86,
        COFF_MACHINE_AMD64 => Architecture::X86_64,
        COFF_MACHINE_ARM | COFF_MACHINE_ARMNT => {
            Architecture::Arm
        }
        COFF_MACHINE_ARM64 => Architecture::Aarch64,
        other => {
            Architecture::Other(format!(
                "pe-machine-{other:#x}"
            ))
        }
    }
}

fn subsystem_name(subsystem: u16) -> String {
    match subsystem {
        IMAGE_SUBSYSTEM_UNKNOWN => "Unknown".into(),
        IMAGE_SUBSYSTEM_NATIVE => "Native".into(),
        IMAGE_SUBSYSTEM_WINDOWS_GUI => "GUI".into(),
        IMAGE_SUBSYSTEM_WINDOWS_CUI => "Console".into(),
        IMAGE_SUBSYSTEM_POSIX_CUI => "POSIX".into(),
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => {
            "Windows CE".into()
        }
        IMAGE_SUBSYSTEM_EFI_APPLICATION => {
            "EFI Application".into()
        }
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => {
            "EFI Boot Service Driver".into()
        }
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => {
            "EFI Runtime Driver".into()
        }
        IMAGE_SUBSYSTEM_XBOX => "Xbox".into(),
        other => format!("Unknown({other})"),
    }
}

fn build_sections(
    pe: &PE,
    data: &[u8],
) -> Vec<SectionInfo> {
    pe.sections
        .iter()
        .map(|section| {
            let name = section
                .name()
                .unwrap_or_default()
                .to_string();
            let raw_offset =
                section.pointer_to_raw_data as u64;
            let raw_size =
                section.size_of_raw_data as u64;
            let chars = section.characteristics;
            let permissions = SectionPermissions {
                read: (chars & IMAGE_SCN_MEM_READ) != 0,
                write: (chars & IMAGE_SCN_MEM_WRITE) != 0,
                execute: (chars & IMAGE_SCN_MEM_EXECUTE)
                    != 0,
            };
            let sha256 = compute_section_hash(
                data, raw_offset, raw_size,
            );

            SectionInfo {
                name,
                virtual_address: section.virtual_address
                    as u64,
                virtual_size: section.virtual_size as u64,
                raw_offset,
                raw_size,
                permissions,
                sha256,
            }
        })
        .collect()
}

fn build_segments(_pe: &PE) -> Vec<SegmentInfo> {
    Vec::new()
}

fn detect_rich_header(
    data: &[u8],
    pe_offset: usize,
) -> bool {
    let end = pe_offset.min(data.len());
    data[..end]
        .windows(RICH_SIGNATURE.len())
        .any(|w| w == RICH_SIGNATURE)
}

fn detect_pe_anomalies(
    anomalies: &mut Vec<FormatAnomaly>,
    pe: &PE,
    timestamp: u32,
    has_tls: bool,
    has_overlay: bool,
    overlay_offset: u64,
    file_size: u64,
) {
    if timestamp == 0 {
        anomalies.push(
            FormatAnomaly::SuspiciousTimestamp {
                value: timestamp,
                reason: "zeroed timestamp".into(),
            },
        );
    } else if timestamp < PE_TIMESTAMP_MIN_VALID {
        anomalies.push(
            FormatAnomaly::SuspiciousTimestamp {
                value: timestamp,
                reason: "timestamp before 1990".into(),
            },
        );
    } else if timestamp > PE_TIMESTAMP_MAX_VALID {
        anomalies.push(
            FormatAnomaly::SuspiciousTimestamp {
                value: timestamp,
                reason: "timestamp after 2100".into(),
            },
        );
    }

    if has_tls {
        anomalies.push(
            FormatAnomaly::TlsCallbacksPresent {
                count: 1,
            },
        );
    }

    if pe.imports.is_empty() {
        anomalies.push(FormatAnomaly::NoImportTable);
    }

    if has_overlay {
        anomalies.push(FormatAnomaly::OverlayData {
            offset: overlay_offset,
            size: file_size - overlay_offset,
        });
    }
}
