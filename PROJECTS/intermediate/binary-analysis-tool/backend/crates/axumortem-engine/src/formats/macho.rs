// ©AngelaMos | 2026
// macho.rs
//
// Mach-O binary format parser
//
// Parses Mach-O binaries via goblin::mach into a
// FormatResult. Handles both single-architecture and
// universal (fat) binaries by selecting the first valid
// architecture slice. Extracts CPU type (x86/x86_64/ARM/
// ARM64), bitness, endianness, entry point, symbol
// presence (stripped detection), __DWARF segment (debug
// info), and MH_PIE flag. build_sections walks segments
// and their sections, mapping VM_PROT_* initprot flags to
// SectionPermissions with per-section SHA-256 hashes.
// build_macho_info scans load commands for CodeSignature,
// FunctionStarts, VersionMinMacosx, VersionMinIphoneos,
// BuildVersion, and dylib references. cpu_subtype_name
// decodes x86, ARM, and ARM64 subtypes. Function hints are
// collected from non-stab N_SECT symbols for disassembly
// seeding.
//
// Connects to:
//   formats/mod.rs - FormatResult, MachOInfo, SectionInfo,
//                     SegmentInfo, detect_common_anomalies,
//                     compute_section_hash
//   types.rs       - Architecture, BinaryFormat, Endianness,
//                     SectionPermissions

use goblin::mach::cputype::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86,
    CPU_TYPE_X86_64,
};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};

use super::{
    compute_section_hash, detect_common_anomalies,
    FormatResult, MachOInfo, SectionInfo, SegmentInfo,
};
use crate::error::EngineError;
use crate::types::{
    Architecture, BinaryFormat, Endianness, SectionPermissions,
};

const MH_OBJECT: u32 = 1;
const MH_EXECUTE: u32 = 2;
const MH_DYLIB: u32 = 6;
const MH_BUNDLE: u32 = 8;
const MH_DSYM: u32 = 10;
const MH_KEXT_BUNDLE: u32 = 11;

const VM_PROT_READ: u32 = 0x01;
const VM_PROT_WRITE: u32 = 0x02;
const VM_PROT_EXECUTE: u32 = 0x04;

pub fn parse_macho(
    mach: &Mach,
    data: &[u8],
) -> Result<FormatResult, EngineError> {
    match mach {
        Mach::Binary(macho) => {
            parse_single_macho(macho, data, false)
        }
        Mach::Fat(fat) => {
            for arch in fat.iter_arches() {
                let arch = arch.map_err(|e| {
                    EngineError::InvalidBinary {
                        reason: e.to_string(),
                    }
                })?;
                let offset = arch.offset as usize;
                let size = arch.size as usize;
                let end = offset.saturating_add(size);
                if end <= data.len() {
                    let macho = MachO::parse(data, offset)
                        .map_err(|e| {
                        EngineError::InvalidBinary {
                            reason: e.to_string(),
                        }
                    })?;
                    return parse_single_macho(
                        &macho, data, true,
                    );
                }
            }
            Err(EngineError::InvalidBinary {
                reason: "no valid architecture in \
                         universal binary"
                    .into(),
            })
        }
    }
}

fn parse_single_macho(
    macho: &MachO,
    data: &[u8],
    is_universal: bool,
) -> Result<FormatResult, EngineError> {
    let architecture =
        map_architecture(macho.header.cputype);
    let bits = if macho.is_64 { 64 } else { 32 };
    let endianness = if macho.little_endian {
        Endianness::Little
    } else {
        Endianness::Big
    };
    let entry_point = macho.entry;

    let symbols: Vec<_> =
        macho.symbols().flatten().collect();
    let is_stripped = symbols.is_empty();

    let has_debug_info = macho.segments.iter().any(|seg| {
        seg.name().is_ok_and(|n| n == "__DWARF")
    });

    let is_pie = macho.header.flags & 0x0020_0000 != 0;

    let sections = build_sections(macho, data);
    let segments = build_segments(macho);
    let anomalies = detect_common_anomalies(
        &sections,
        entry_point,
        is_stripped,
    );
    let macho_info =
        build_macho_info(macho, is_universal);

    let function_hints: Vec<u64> = macho
        .symbols()
        .flatten()
        .filter(|(_, nlist)| {
            !nlist.is_stab()
                && nlist.n_type & 0x0e == 0x0e
                && nlist.n_value != 0
                && nlist.n_value != entry_point
        })
        .map(|(_, nlist)| nlist.n_value)
        .collect();

    Ok(FormatResult {
        format: BinaryFormat::MachO,
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
        pe_info: None,
        elf_info: None,
        macho_info: Some(macho_info),
        function_hints,
    })
}

fn map_architecture(cputype: u32) -> Architecture {
    match cputype {
        CPU_TYPE_X86 => Architecture::X86,
        CPU_TYPE_X86_64 => Architecture::X86_64,
        CPU_TYPE_ARM => Architecture::Arm,
        CPU_TYPE_ARM64 => Architecture::Aarch64,
        other => {
            Architecture::Other(format!(
                "mach-cpu-{other:#x}"
            ))
        }
    }
}

fn file_type_name(filetype: u32) -> String {
    match filetype {
        MH_OBJECT => "Object".into(),
        MH_EXECUTE => "Execute".into(),
        MH_DYLIB => "Dylib".into(),
        MH_BUNDLE => "Bundle".into(),
        MH_DSYM => "Dsym".into(),
        MH_KEXT_BUNDLE => "Kext".into(),
        other => format!("Unknown({other})"),
    }
}

fn cpu_subtype_name(
    cputype: u32,
    cpusubtype: u32,
) -> String {
    let subtype = cpusubtype & 0x00FF_FFFF;
    match cputype {
        CPU_TYPE_X86 | CPU_TYPE_X86_64 => {
            match subtype {
                3 => "ALL".into(),
                4 => "486".into(),
                8 => "PENTIUM_3".into(),
                9 => "PENTIUM_M".into(),
                10 => "PENTIUM_4".into(),
                11 => "ITANIUM".into(),
                12 => "XEON".into(),
                _ => format!("{subtype}"),
            }
        }
        CPU_TYPE_ARM => match subtype {
            6 => "v6".into(),
            9 => "v7".into(),
            11 => "v7f".into(),
            12 => "v7s".into(),
            13 => "v7k".into(),
            _ => format!("{subtype}"),
        },
        CPU_TYPE_ARM64 => match subtype {
            0 => "ALL".into(),
            1 => "v8".into(),
            2 => "E".into(),
            _ => format!("{subtype}"),
        },
        _ => format!("{subtype}"),
    }
}

fn build_sections(
    macho: &MachO,
    data: &[u8],
) -> Vec<SectionInfo> {
    let mut sections = Vec::new();
    for segment in macho.segments.iter() {
        let initprot = segment.initprot;
        let seg_permissions = SectionPermissions {
            read: (initprot & VM_PROT_READ) != 0,
            write: (initprot & VM_PROT_WRITE) != 0,
            execute: (initprot & VM_PROT_EXECUTE)
                != 0,
        };
        for section_result in segment.into_iter() {
            let Ok((section, _section_data)) =
                section_result
            else {
                continue;
            };
            let name = section
                .name()
                .unwrap_or("???")
                .to_string();
            let raw_offset = section.offset as u64;
            let raw_size = section.size;
            let sha256 = compute_section_hash(
                data, raw_offset, raw_size,
            );

            sections.push(SectionInfo {
                name,
                virtual_address: section.addr,
                virtual_size: section.size,
                raw_offset,
                raw_size,
                permissions: seg_permissions.clone(),
                sha256,
            });
        }
    }
    sections
}

fn build_segments(macho: &MachO) -> Vec<SegmentInfo> {
    macho
        .segments
        .iter()
        .map(|seg| {
            let name = seg
                .name()
                .ok()
                .map(|n| n.to_string());
            let initprot = seg.initprot;
            let permissions = SectionPermissions {
                read: (initprot & VM_PROT_READ) != 0,
                write: (initprot & VM_PROT_WRITE) != 0,
                execute: (initprot & VM_PROT_EXECUTE)
                    != 0,
            };

            SegmentInfo {
                name,
                virtual_address: seg.vmaddr,
                virtual_size: seg.vmsize,
                file_offset: seg.fileoff,
                file_size: seg.filesize,
                permissions,
            }
        })
        .collect()
}

fn build_macho_info(
    macho: &MachO,
    is_universal: bool,
) -> MachOInfo {
    let file_type =
        file_type_name(macho.header.filetype);
    let cpu_subtype = cpu_subtype_name(
        macho.header.cputype,
        macho.header.cpusubtype,
    );

    let mut has_code_signature = false;
    let mut has_function_starts = false;
    let mut min_os_version: Option<String> = None;
    let mut sdk_version: Option<String> = None;

    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::CodeSignature(_) => {
                has_code_signature = true;
            }
            CommandVariant::FunctionStarts(_) => {
                has_function_starts = true;
            }
            CommandVariant::VersionMinMacosx(ver) => {
                min_os_version = Some(format!(
                    "{}.{}.{}",
                    ver.version >> 16,
                    (ver.version >> 8) & 0xFF,
                    ver.version & 0xFF,
                ));
                sdk_version = Some(format!(
                    "{}.{}.{}",
                    ver.sdk >> 16,
                    (ver.sdk >> 8) & 0xFF,
                    ver.sdk & 0xFF,
                ));
            }
            CommandVariant::VersionMinIphoneos(ver) => {
                if min_os_version.is_none() {
                    min_os_version = Some(format!(
                        "iOS {}.{}.{}",
                        ver.version >> 16,
                        (ver.version >> 8) & 0xFF,
                        ver.version & 0xFF,
                    ));
                    sdk_version = Some(format!(
                        "{}.{}.{}",
                        ver.sdk >> 16,
                        (ver.sdk >> 8) & 0xFF,
                        ver.sdk & 0xFF,
                    ));
                }
            }
            CommandVariant::BuildVersion(bv) => {
                if min_os_version.is_none() {
                    min_os_version = Some(format!(
                        "{}.{}.{}",
                        bv.minos >> 16,
                        (bv.minos >> 8) & 0xFF,
                        bv.minos & 0xFF,
                    ));
                    sdk_version = Some(format!(
                        "{}.{}.{}",
                        bv.sdk >> 16,
                        (bv.sdk >> 8) & 0xFF,
                        bv.sdk & 0xFF,
                    ));
                }
            }
            _ => {}
        }
    }

    let dylibs = macho
        .libs
        .iter()
        .filter(|lib| !lib.is_empty())
        .map(|lib| lib.to_string())
        .collect();

    MachOInfo {
        file_type,
        cpu_subtype,
        is_universal,
        has_code_signature,
        min_os_version,
        sdk_version,
        dylibs,
        has_function_starts,
    }
}
