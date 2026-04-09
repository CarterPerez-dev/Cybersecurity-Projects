// ©AngelaMos | 2026
// imports.rs
//
// Import/export table analysis pass
//
// ImportPass depends on format and extracts import tables,
// export tables, and linked library lists from ELF, PE,
// and Mach-O binaries via goblin. SUSPICIOUS_APIS defines
// 22 APIs tagged with MITRE ATT&CK technique IDs covering
// injection (T1055), process hollowing (T1055.012), APC
// injection (T1055.004), anti-debug (T1622), token
// manipulation (T1134), persistence (T1547.001,
// T1543.003), download (T1105), network (T1071),
// deobfuscation (T1140), and Linux-specific APIs (ptrace,
// mprotect, dlopen, dlsym, execve, process_vm_readv/
// writev). SUSPICIOUS_COMBINATIONS defines 15 multi-API
// chain detections including Process Injection Chain,
// Process Hollowing, Credential Theft, APC/DLL Injection,
// Download and Execute, Registry/Service Persistence, and
// Linux-specific chains (ptrace injection, RWX memory, C2
// connection, network listener, dynamic loading, process
// injection). matches_api handles Windows A/W suffix
// variants. extract_elf, extract_pe, and extract_mach
// dispatch to format-specific importers that populate
// ImportEntry with library, function, address, ordinal,
// and threat tags. detect_combinations matches import
// function names against CombinationDef patterns with
// deduplication. collect_mitre_mappings emits per-API
// MITRE technique mappings. Unit tests verify ELF import
// extraction, suspicious API flagging, combination
// detection for injection chains and A/W suffixes, false
// positive rejection, MITRE mapping collection, and
// context population.
//
// Connects to:
//   pass.rs        - AnalysisPass trait, Sealed
//   context.rs     - AnalysisContext
//   types.rs       - Severity
//   error.rs       - EngineError

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::pass::{AnalysisPass, Sealed};
use crate::types::Severity;

pub struct SuspiciousApiDef {
    pub name: &'static str,
    pub tag: &'static str,
    pub mitre_id: &'static str,
}

pub const SUSPICIOUS_APIS: &[SuspiciousApiDef] = &[
    SuspiciousApiDef {
        name: "VirtualAllocEx",
        tag: "injection",
        mitre_id: "T1055",
    },
    SuspiciousApiDef {
        name: "WriteProcessMemory",
        tag: "injection",
        mitre_id: "T1055",
    },
    SuspiciousApiDef {
        name: "CreateRemoteThread",
        tag: "injection",
        mitre_id: "T1055",
    },
    SuspiciousApiDef {
        name: "NtUnmapViewOfSection",
        tag: "hollowing",
        mitre_id: "T1055.012",
    },
    SuspiciousApiDef {
        name: "SetThreadContext",
        tag: "hollowing",
        mitre_id: "T1055.012",
    },
    SuspiciousApiDef {
        name: "QueueUserAPC",
        tag: "apc-injection",
        mitre_id: "T1055.004",
    },
    SuspiciousApiDef {
        name: "IsDebuggerPresent",
        tag: "anti-debug",
        mitre_id: "T1622",
    },
    SuspiciousApiDef {
        name: "NtQueryInformationProcess",
        tag: "anti-debug",
        mitre_id: "T1622",
    },
    SuspiciousApiDef {
        name: "OpenProcessToken",
        tag: "token-manipulation",
        mitre_id: "T1134",
    },
    SuspiciousApiDef {
        name: "AdjustTokenPrivileges",
        tag: "token-manipulation",
        mitre_id: "T1134",
    },
    SuspiciousApiDef {
        name: "RegSetValueEx",
        tag: "persistence",
        mitre_id: "T1547.001",
    },
    SuspiciousApiDef {
        name: "CreateService",
        tag: "persistence",
        mitre_id: "T1543.003",
    },
    SuspiciousApiDef {
        name: "URLDownloadToFile",
        tag: "download",
        mitre_id: "T1105",
    },
    SuspiciousApiDef {
        name: "InternetOpen",
        tag: "network",
        mitre_id: "T1071",
    },
    SuspiciousApiDef {
        name: "CryptDecrypt",
        tag: "deobfuscation",
        mitre_id: "T1140",
    },
    SuspiciousApiDef {
        name: "ptrace",
        tag: "injection",
        mitre_id: "T1055.008",
    },
    SuspiciousApiDef {
        name: "mprotect",
        tag: "memory-manipulation",
        mitre_id: "",
    },
    SuspiciousApiDef {
        name: "dlopen",
        tag: "loading",
        mitre_id: "T1574.006",
    },
    SuspiciousApiDef {
        name: "dlsym",
        tag: "loading",
        mitre_id: "T1574.006",
    },
    SuspiciousApiDef {
        name: "execve",
        tag: "execution",
        mitre_id: "T1059",
    },
    SuspiciousApiDef {
        name: "process_vm_readv",
        tag: "injection",
        mitre_id: "T1055",
    },
    SuspiciousApiDef {
        name: "process_vm_writev",
        tag: "injection",
        mitre_id: "T1055",
    },
];

struct CombinationDef {
    name: &'static str,
    description: &'static str,
    patterns: &'static [&'static str],
    mitre_id: &'static str,
    severity: Severity,
}

const SUSPICIOUS_COMBINATIONS: &[CombinationDef] = &[
    CombinationDef {
        name: "Process Injection Chain",
        description: "VirtualAllocEx + WriteProcessMemory \
                      + CreateRemoteThread",
        patterns: &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ],
        mitre_id: "T1055",
        severity: Severity::Critical,
    },
    CombinationDef {
        name: "Process Hollowing",
        description: "CreateProcess + \
                      NtUnmapViewOfSection + \
                      SetThreadContext + ResumeThread",
        patterns: &[
            "CreateProcess*",
            "NtUnmapViewOfSection",
            "SetThreadContext",
            "ResumeThread",
        ],
        mitre_id: "T1055.012",
        severity: Severity::Critical,
    },
    CombinationDef {
        name: "APC Injection",
        description: "QueueUserAPC + OpenThread",
        patterns: &["QueueUserAPC", "OpenThread"],
        mitre_id: "T1055.004",
        severity: Severity::High,
    },
    CombinationDef {
        name: "DLL Injection",
        description: "LoadLibrary + CreateRemoteThread",
        patterns: &[
            "LoadLibrary*",
            "CreateRemoteThread",
        ],
        mitre_id: "T1055.001",
        severity: Severity::High,
    },
    CombinationDef {
        name: "Credential Theft",
        description: "OpenProcess + ReadProcessMemory",
        patterns: &[
            "OpenProcess",
            "ReadProcessMemory",
        ],
        mitre_id: "T1003",
        severity: Severity::Critical,
    },
    CombinationDef {
        name: "Service Persistence",
        description: "OpenSCManager + CreateService",
        patterns: &[
            "OpenSCManager*",
            "CreateService*",
        ],
        mitre_id: "T1543.003",
        severity: Severity::Medium,
    },
    CombinationDef {
        name: "Registry Persistence",
        description: "RegOpenKeyEx + RegSetValueEx",
        patterns: &[
            "RegOpenKeyEx*",
            "RegSetValueEx*",
        ],
        mitre_id: "T1547.001",
        severity: Severity::Medium,
    },
    CombinationDef {
        name: "Download and Execute",
        description: "URLDownloadToFile + ShellExecute",
        patterns: &[
            "URLDownloadToFile*",
            "ShellExecute*",
        ],
        mitre_id: "T1105",
        severity: Severity::High,
    },
    CombinationDef {
        name: "Download and Execute",
        description: "URLDownloadToFile + WinExec",
        patterns: &["URLDownloadToFile*", "WinExec"],
        mitre_id: "T1105",
        severity: Severity::High,
    },
    CombinationDef {
        name: "Linux ptrace Injection",
        description: "ptrace-based process injection",
        patterns: &["ptrace"],
        mitre_id: "T1055.008",
        severity: Severity::High,
    },
    CombinationDef {
        name: "Linux RWX Memory",
        description: "mmap + mprotect for RWX memory",
        patterns: &["mmap", "mprotect"],
        mitre_id: "",
        severity: Severity::Medium,
    },
    CombinationDef {
        name: "Linux C2 Connection",
        description: "socket + connect + inet_pton \
                      hardcoded C2 address",
        patterns: &[
            "socket",
            "connect",
            "inet_pton",
        ],
        mitre_id: "T1071",
        severity: Severity::High,
    },
    CombinationDef {
        name: "Linux Network Listener",
        description: "socket + bind + listen + accept \
                      backdoor listener",
        patterns: &[
            "socket",
            "bind",
            "listen",
            "accept",
        ],
        mitre_id: "T1571",
        severity: Severity::High,
    },
    CombinationDef {
        name: "Linux Dynamic Loading",
        description: "dlopen + dlsym runtime \
                      API resolution",
        patterns: &["dlopen", "dlsym"],
        mitre_id: "T1574.006",
        severity: Severity::Medium,
    },
    CombinationDef {
        name: "Linux Process Injection",
        description: "process_vm_writev \
                      cross-process memory write",
        patterns: &["process_vm_writev"],
        mitre_id: "T1055",
        severity: Severity::Critical,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub imports: Vec<ImportEntry>,
    pub exports: Vec<ExportEntry>,
    pub libraries: Vec<String>,
    pub suspicious_combinations:
        Vec<SuspiciousCombination>,
    pub mitre_mappings: Vec<MitreMapping>,
    pub statistics: ImportStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEntry {
    pub library: String,
    pub function: String,
    pub address: Option<u64>,
    pub ordinal: Option<u16>,
    pub is_suspicious: bool,
    pub threat_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub address: u64,
    pub ordinal: Option<u16>,
    pub is_forwarded: bool,
    pub forward_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousCombination {
    pub name: String,
    pub description: String,
    pub apis: Vec<String>,
    pub mitre_id: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub api: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportStatistics {
    pub total_imports: usize,
    pub total_exports: usize,
    pub suspicious_count: usize,
    pub library_count: usize,
}

pub struct ImportPass;

impl Sealed for ImportPass {}

impl AnalysisPass for ImportPass {
    fn name(&self) -> &'static str {
        "imports"
    }

    fn dependencies(&self) -> &[&'static str] {
        &["format"]
    }

    fn run(
        &self,
        ctx: &mut AnalysisContext,
    ) -> Result<(), EngineError> {
        let result = analyze_imports(ctx.data())?;
        ctx.import_result = Some(result);
        Ok(())
    }
}

fn analyze_imports(
    data: &[u8],
) -> Result<ImportResult, EngineError> {
    let object =
        goblin::Object::parse(data).map_err(|e| {
            EngineError::InvalidBinary {
                reason: e.to_string(),
            }
        })?;

    let (imports, exports, libraries) = match &object {
        goblin::Object::Elf(elf) => extract_elf(elf),
        goblin::Object::PE(pe) => extract_pe(pe),
        goblin::Object::Mach(mach) => {
            extract_mach(mach, data)?
        }
        _ => (Vec::new(), Vec::new(), Vec::new()),
    };

    let suspicious_combinations =
        detect_combinations(&imports);
    let mitre_mappings =
        collect_mitre_mappings(&imports);
    let suspicious_count = imports
        .iter()
        .filter(|i| i.is_suspicious)
        .count();

    let statistics = ImportStatistics {
        total_imports: imports.len(),
        total_exports: exports.len(),
        suspicious_count,
        library_count: libraries.len(),
    };

    Ok(ImportResult {
        imports,
        exports,
        libraries,
        suspicious_combinations,
        mitre_mappings,
        statistics,
    })
}

fn extract_elf(
    elf: &goblin::elf::Elf,
) -> (Vec<ImportEntry>, Vec<ExportEntry>, Vec<String>) {
    let libraries: Vec<String> = elf
        .libraries
        .iter()
        .map(|s| s.to_string())
        .collect();

    let mut imports = Vec::new();
    for sym in elf.dynsyms.iter() {
        if !sym.is_import() || sym.st_name == 0 {
            continue;
        }
        let name = elf
            .dynstrtab
            .get_at(sym.st_name)
            .unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let (is_suspicious, threat_tags) =
            flag_suspicious(name);
        imports.push(ImportEntry {
            library: String::new(),
            function: name.to_string(),
            address: None,
            ordinal: None,
            is_suspicious,
            threat_tags,
        });
    }

    let mut exports = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.is_import()
            || sym.st_value == 0
            || sym.st_name == 0
        {
            continue;
        }
        let name = elf
            .dynstrtab
            .get_at(sym.st_name)
            .unwrap_or("");
        if name.is_empty() {
            continue;
        }
        exports.push(ExportEntry {
            name: Some(name.to_string()),
            address: sym.st_value,
            ordinal: None,
            is_forwarded: false,
            forward_target: None,
        });
    }

    (imports, exports, libraries)
}

fn extract_pe(
    pe: &goblin::pe::PE,
) -> (Vec<ImportEntry>, Vec<ExportEntry>, Vec<String>) {
    let mut lib_set = HashSet::new();
    let mut imports = Vec::new();

    for import in &pe.imports {
        let dll = import.dll.to_string();
        lib_set.insert(dll.clone());
        let (is_suspicious, threat_tags) =
            flag_suspicious(&import.name);
        imports.push(ImportEntry {
            library: dll,
            function: import.name.to_string(),
            address: Some(import.rva as u64),
            ordinal: Some(import.ordinal),
            is_suspicious,
            threat_tags,
        });
    }

    let mut exports = Vec::new();
    for export in &pe.exports {
        let is_forwarded = export.reexport.is_some();
        let forward_target =
            export.reexport.as_ref().map(|r| match r {
                goblin::pe::export::Reexport::DLLName {
                    export: name,
                    lib,
                } => format!("{lib}!{name}"),
                goblin::pe::export::Reexport::DLLOrdinal {
                    ordinal,
                    lib,
                } => format!("{lib}!#{ordinal}"),
            });
        exports.push(ExportEntry {
            name: export.name.map(|s| s.to_string()),
            address: export.rva as u64,
            ordinal: None,
            is_forwarded,
            forward_target,
        });
    }

    let libraries: Vec<String> =
        lib_set.into_iter().collect();
    (imports, exports, libraries)
}

fn extract_mach(
    mach: &goblin::mach::Mach,
    data: &[u8],
) -> Result<
    (Vec<ImportEntry>, Vec<ExportEntry>, Vec<String>),
    EngineError,
> {
    match mach {
        goblin::mach::Mach::Binary(macho) => {
            Ok(extract_single_macho(macho))
        }
        goblin::mach::Mach::Fat(fat) => {
            for arch in fat.iter_arches() {
                let arch = arch.map_err(|e| {
                    EngineError::InvalidBinary {
                        reason: e.to_string(),
                    }
                })?;
                let macho = goblin::mach::MachO::parse(
                    data,
                    arch.offset as usize,
                )
                .map_err(|e| {
                    EngineError::InvalidBinary {
                        reason: e.to_string(),
                    }
                })?;
                return Ok(extract_single_macho(&macho));
            }
            Ok((Vec::new(), Vec::new(), Vec::new()))
        }
    }
}

fn extract_single_macho(
    macho: &goblin::mach::MachO,
) -> (Vec<ImportEntry>, Vec<ExportEntry>, Vec<String>) {
    let mut imports = Vec::new();
    if let Ok(macho_imports) = macho.imports() {
        for imp in &macho_imports {
            let (is_suspicious, threat_tags) =
                flag_suspicious(imp.name);
            imports.push(ImportEntry {
                library: imp.dylib.to_string(),
                function: imp.name.to_string(),
                address: Some(imp.address),
                ordinal: None,
                is_suspicious,
                threat_tags,
            });
        }
    }

    let mut exports = Vec::new();
    if let Ok(macho_exports) = macho.exports() {
        for exp in &macho_exports {
            exports.push(ExportEntry {
                name: Some(exp.name.clone()),
                address: exp.offset,
                ordinal: None,
                is_forwarded: false,
                forward_target: None,
            });
        }
    }

    let libraries: Vec<String> = macho
        .libs
        .iter()
        .filter(|lib| !lib.is_empty())
        .map(|lib| lib.to_string())
        .collect();

    (imports, exports, libraries)
}

fn flag_suspicious(
    name: &str,
) -> (bool, Vec<String>) {
    let mut tags = Vec::new();
    for api in SUSPICIOUS_APIS {
        if matches_api(name, api.name) {
            tags.push(api.tag.to_string());
        }
    }
    let is_suspicious = !tags.is_empty();
    (is_suspicious, tags)
}

fn matches_api(
    import_name: &str,
    api_name: &str,
) -> bool {
    if import_name == api_name {
        return true;
    }
    if import_name.starts_with(api_name) {
        let suffix = &import_name[api_name.len()..];
        return suffix == "A" || suffix == "W";
    }
    false
}

fn matches_pattern(
    import_name: &str,
    pattern: &str,
) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        import_name.starts_with(prefix)
    } else {
        matches_api(import_name, pattern)
    }
}

fn detect_combinations(
    imports: &[ImportEntry],
) -> Vec<SuspiciousCombination> {
    let function_names: Vec<&str> = imports
        .iter()
        .map(|i| i.function.as_str())
        .collect();
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    for combo in SUSPICIOUS_COMBINATIONS {
        if seen.contains(combo.name) {
            continue;
        }
        let all_matched =
            combo.patterns.iter().all(|pattern| {
                function_names.iter().any(|name| {
                    matches_pattern(name, pattern)
                })
            });
        if !all_matched {
            continue;
        }

        let matched_apis: Vec<String> = combo
            .patterns
            .iter()
            .filter_map(|pattern| {
                function_names
                    .iter()
                    .find(|name| {
                        matches_pattern(name, pattern)
                    })
                    .map(|name| name.to_string())
            })
            .collect();

        results.push(SuspiciousCombination {
            name: combo.name.into(),
            description: combo.description.into(),
            apis: matched_apis,
            mitre_id: combo.mitre_id.into(),
            severity: combo.severity.clone(),
        });
        seen.insert(combo.name);
    }

    results
}

fn collect_mitre_mappings(
    imports: &[ImportEntry],
) -> Vec<MitreMapping> {
    let mut mappings = Vec::new();
    for import in imports {
        if !import.is_suspicious {
            continue;
        }
        for api in SUSPICIOUS_APIS {
            if matches_api(&import.function, api.name)
                && !api.mitre_id.is_empty()
            {
                mappings.push(MitreMapping {
                    technique_id: api.mitre_id.into(),
                    api: import.function.clone(),
                    tag: api.tag.into(),
                });
            }
        }
    }
    mappings
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::context::BinarySource;

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
    fn elf_imports_extracted() {
        let data = load_fixture("hello_elf");
        let result =
            analyze_imports(&data).unwrap();

        assert!(
            !result.imports.is_empty(),
            "ELF binary should have imports"
        );
        assert!(
            !result.libraries.is_empty(),
            "ELF binary should list needed libraries"
        );
        assert!(result.statistics.total_imports > 0);
    }

    #[test]
    fn suspicious_api_flagging() {
        let (is_suspicious, tags) =
            flag_suspicious("VirtualAllocEx");
        assert!(is_suspicious);
        assert!(tags.contains(&"injection".to_string()));

        let (is_suspicious, tags) =
            flag_suspicious("RegSetValueExW");
        assert!(is_suspicious);
        assert!(tags.contains(
            &"persistence".to_string()
        ));

        let (is_suspicious, _) =
            flag_suspicious("printf");
        assert!(!is_suspicious);
    }

    #[test]
    fn combination_detection_injection_chain() {
        let imports = vec![
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "VirtualAllocEx".into(),
                address: None,
                ordinal: None,
                is_suspicious: true,
                threat_tags: vec![
                    "injection".into(),
                ],
            },
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "WriteProcessMemory".into(),
                address: None,
                ordinal: None,
                is_suspicious: true,
                threat_tags: vec![
                    "injection".into(),
                ],
            },
            ImportEntry {
                library: "kernel32.dll".into(),
                function: "CreateRemoteThread".into(),
                address: None,
                ordinal: None,
                is_suspicious: true,
                threat_tags: vec![
                    "injection".into(),
                ],
            },
        ];

        let combos = detect_combinations(&imports);
        assert_eq!(combos.len(), 1);
        assert_eq!(
            combos[0].name,
            "Process Injection Chain"
        );
        assert_eq!(combos[0].mitre_id, "T1055");
        assert_eq!(
            combos[0].severity,
            Severity::Critical
        );
    }

    #[test]
    fn combination_with_aw_suffix() {
        let imports = vec![
            ImportEntry {
                library: "advapi32.dll".into(),
                function: "RegOpenKeyExA".into(),
                address: None,
                ordinal: None,
                is_suspicious: false,
                threat_tags: vec![],
            },
            ImportEntry {
                library: "advapi32.dll".into(),
                function: "RegSetValueExW".into(),
                address: None,
                ordinal: None,
                is_suspicious: true,
                threat_tags: vec![
                    "persistence".into(),
                ],
            },
        ];

        let combos = detect_combinations(&imports);
        assert!(combos
            .iter()
            .any(|c| c.name
                == "Registry Persistence"));
    }

    #[test]
    fn no_false_positive_combinations() {
        let imports = vec![ImportEntry {
            library: "kernel32.dll".into(),
            function: "VirtualAllocEx".into(),
            address: None,
            ordinal: None,
            is_suspicious: true,
            threat_tags: vec!["injection".into()],
        }];

        let combos = detect_combinations(&imports);
        assert!(
            !combos.iter().any(|c| c.name
                == "Process Injection Chain"),
            "should not detect chain with only one API"
        );
    }

    #[test]
    fn mitre_mappings_collected() {
        let imports = vec![
            ImportEntry {
                library: String::new(),
                function: "ptrace".into(),
                address: None,
                ordinal: None,
                is_suspicious: true,
                threat_tags: vec![
                    "injection".into(),
                ],
            },
            ImportEntry {
                library: String::new(),
                function: "printf".into(),
                address: None,
                ordinal: None,
                is_suspicious: false,
                threat_tags: vec![],
            },
        ];

        let mappings =
            collect_mitre_mappings(&imports);
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings[0].technique_id,
            "T1055.008"
        );
        assert_eq!(mappings[0].api, "ptrace");
    }

    #[test]
    fn import_pass_populates_context() {
        let data = load_fixture("hello_elf");
        let mut ctx = make_ctx(data);
        assert!(ctx.import_result.is_none());

        ImportPass.run(&mut ctx).unwrap();
        assert!(ctx.import_result.is_some());
    }
}
