// ©AngelaMos | 2026
// elf.rs
//
// ELF binary format parser
//
// Parses ELF binaries via goblin::elf into a FormatResult.
// Extracts architecture (x86/x86_64/ARM/AArch64), bitness,
// endianness, entry point, and checks for symbol table
// presence (stripped detection), PT_INTERP (PIE detection),
// and .debug_ sections. build_sections iterates section
// headers, computing SHA-256 per section and mapping
// SHF_ALLOC/SHF_WRITE/SHF_EXECINSTR flags to
// SectionPermissions. build_segments maps program headers
// with PF_R/PF_W/PF_X flags and named segment types.
// build_elf_info extracts OS ABI, ELF type, interpreter
// path, GNU_RELRO, stack executability, BIND_NOW (via
// DT_BIND_NOW and DF_BIND_NOW), and needed libraries.
// collect_function_hints gathers STT_FUNC symbol addresses
// for disassembly seeding.
//
// Connects to:
//   formats/mod.rs - FormatResult, SectionInfo, SegmentInfo,
//                     ElfInfo, detect_common_anomalies,
//                     compute_section_hash
//   types.rs       - Architecture, BinaryFormat, Endianness,
//                     SectionPermissions

use goblin::elf::dynamic::DT_BIND_NOW;
use goblin::elf::header::{
    EM_386, EM_AARCH64, EM_ARM, EM_X86_64, ET_CORE, ET_DYN,
    ET_EXEC, ET_REL,
};
use goblin::elf::program_header::{
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_EH_FRAME,
    PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_NOTE,
    PT_NULL, PT_PHDR,
};
use goblin::elf::section_header::{
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS,
    SHT_SYMTAB,
};
use goblin::elf::sym::STT_FUNC;
use goblin::elf::Elf;

use super::{
    detect_common_anomalies, compute_section_hash, ElfInfo,
    FormatResult, SectionInfo, SegmentInfo,
};
use crate::error::EngineError;
use crate::types::{
    Architecture, BinaryFormat, Endianness, SectionPermissions,
};

const EI_OSABI: usize = 7;
const ELFOSABI_NONE: u8 = 0;
const ELFOSABI_HPUX: u8 = 1;
const ELFOSABI_NETBSD: u8 = 2;
const ELFOSABI_GNU: u8 = 3;
const ELFOSABI_SOLARIS: u8 = 6;
const ELFOSABI_FREEBSD: u8 = 9;
const ELFOSABI_OPENBSD: u8 = 12;
const ELFOSABI_ARM: u8 = 97;
const ELFOSABI_STANDALONE: u8 = 255;

const DT_FLAGS: u64 = 30;
const DF_BIND_NOW: u64 = 0x8;

pub fn parse_elf(
    elf: &Elf,
    data: &[u8],
) -> Result<FormatResult, EngineError> {
    let architecture =
        map_architecture(elf.header.e_machine);
    let bits = if elf.is_64 { 64 } else { 32 };
    let endianness = if elf.little_endian {
        Endianness::Little
    } else {
        Endianness::Big
    };
    let entry_point = elf.header.e_entry;

    let has_symtab = elf
        .section_headers
        .iter()
        .any(|sh| sh.sh_type == SHT_SYMTAB);
    let is_stripped = !has_symtab;

    let has_interp = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_INTERP);
    let is_pie =
        elf.header.e_type == ET_DYN && has_interp;

    let has_debug_info =
        elf.section_headers.iter().any(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .is_some_and(|name| {
                    name.starts_with(".debug_")
                })
        });

    let sections = build_sections(elf, data);
    let segments = build_segments(elf);
    let anomalies = detect_common_anomalies(
        &sections,
        entry_point,
        is_stripped,
    );
    let elf_info = build_elf_info(elf);
    let function_hints =
        collect_function_hints(elf, entry_point);

    Ok(FormatResult {
        format: BinaryFormat::Elf,
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
        elf_info: Some(elf_info),
        macho_info: None,
        function_hints,
    })
}

fn map_architecture(machine: u16) -> Architecture {
    match machine {
        EM_386 => Architecture::X86,
        EM_X86_64 => Architecture::X86_64,
        EM_ARM => Architecture::Arm,
        EM_AARCH64 => Architecture::Aarch64,
        other => {
            Architecture::Other(format!(
                "elf-machine-{other}"
            ))
        }
    }
}

fn os_abi_name(abi: u8) -> String {
    match abi {
        ELFOSABI_NONE => "SysV".into(),
        ELFOSABI_HPUX => "HP-UX".into(),
        ELFOSABI_NETBSD => "NetBSD".into(),
        ELFOSABI_GNU => "GNU/Linux".into(),
        ELFOSABI_SOLARIS => "Solaris".into(),
        ELFOSABI_FREEBSD => "FreeBSD".into(),
        ELFOSABI_OPENBSD => "OpenBSD".into(),
        ELFOSABI_ARM => "ARM".into(),
        ELFOSABI_STANDALONE => "Standalone".into(),
        other => format!("Unknown({other})"),
    }
}

fn elf_type_name(e_type: u16) -> String {
    match e_type {
        ET_REL => "REL".into(),
        ET_EXEC => "EXEC".into(),
        ET_DYN => "DYN".into(),
        ET_CORE => "CORE".into(),
        other => format!("Unknown({other})"),
    }
}

fn segment_type_name(p_type: u32) -> Option<String> {
    Some(
        match p_type {
            PT_NULL => "NULL",
            PT_LOAD => "LOAD",
            PT_DYNAMIC => "DYNAMIC",
            PT_INTERP => "INTERP",
            PT_NOTE => "NOTE",
            PT_PHDR => "PHDR",
            PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            PT_GNU_STACK => "GNU_STACK",
            PT_GNU_RELRO => "GNU_RELRO",
            _ => return Some(format!("0x{p_type:x}")),
        }
        .into(),
    )
}

fn build_sections(
    elf: &Elf,
    data: &[u8],
) -> Vec<SectionInfo> {
    elf.section_headers
        .iter()
        .skip(1)
        .map(|shdr| {
            let name = elf
                .shdr_strtab
                .get_at(shdr.sh_name)
                .unwrap_or("")
                .to_string();

            let is_nobits = shdr.sh_type == SHT_NOBITS;
            let raw_offset = if is_nobits {
                0
            } else {
                shdr.sh_offset
            };
            let raw_size = if is_nobits {
                0
            } else {
                shdr.sh_size
            };

            let permissions = SectionPermissions {
                read: (shdr.sh_flags
                    & u64::from(SHF_ALLOC))
                    != 0,
                write: (shdr.sh_flags
                    & u64::from(SHF_WRITE))
                    != 0,
                execute: (shdr.sh_flags
                    & u64::from(SHF_EXECINSTR))
                    != 0,
            };

            let sha256 = compute_section_hash(
                data, raw_offset, raw_size,
            );

            SectionInfo {
                name,
                virtual_address: shdr.sh_addr,
                virtual_size: shdr.sh_size,
                raw_offset,
                raw_size,
                permissions,
                sha256,
            }
        })
        .collect()
}

fn build_segments(elf: &Elf) -> Vec<SegmentInfo> {
    elf.program_headers
        .iter()
        .map(|phdr| {
            let name = segment_type_name(phdr.p_type);
            let permissions = SectionPermissions {
                read: (phdr.p_flags & PF_R) != 0,
                write: (phdr.p_flags & PF_W) != 0,
                execute: (phdr.p_flags & PF_X) != 0,
            };

            SegmentInfo {
                name,
                virtual_address: phdr.p_vaddr,
                virtual_size: phdr.p_memsz,
                file_offset: phdr.p_offset,
                file_size: phdr.p_filesz,
                permissions,
            }
        })
        .collect()
}

fn build_elf_info(elf: &Elf) -> ElfInfo {
    let os_abi =
        os_abi_name(elf.header.e_ident[EI_OSABI]);
    let elf_type = elf_type_name(elf.header.e_type);
    let interpreter =
        elf.interpreter.map(|s| s.to_string());

    let gnu_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);

    let stack_executable = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK)
        .is_some_and(|ph| (ph.p_flags & PF_X) != 0);

    let mut bind_now = false;
    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            let tag = dyn_entry.d_tag as u64;
            if tag == DT_BIND_NOW {
                bind_now = true;
            }
            if tag == DT_FLAGS
                && (dyn_entry.d_val & DF_BIND_NOW) != 0
            {
                bind_now = true;
            }
        }
    }

    let needed_libraries = elf
        .libraries
        .iter()
        .map(|s| s.to_string())
        .collect();

    ElfInfo {
        os_abi,
        elf_type,
        interpreter,
        gnu_relro,
        bind_now,
        stack_executable,
        needed_libraries,
    }
}

fn collect_function_hints(
    elf: &Elf,
    entry_point: u64,
) -> Vec<u64> {
    let mut hints: Vec<u64> = elf
        .syms
        .iter()
        .chain(elf.dynsyms.iter())
        .filter(|sym| {
            sym.st_type() == STT_FUNC
                && sym.st_value != 0
                && sym.st_value != entry_point
        })
        .map(|sym| sym.st_value)
        .collect();
    hints.sort_unstable();
    hints.dedup();
    hints
}
