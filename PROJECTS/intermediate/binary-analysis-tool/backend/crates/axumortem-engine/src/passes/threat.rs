// ©AngelaMos | 2026
// threat.rs
//
// Weighted threat scoring and risk classification pass
//
// ThreatPass depends on all five preceding passes (format,
// imports, strings, entropy, disasm) and produces a
// composite threat score across eight capped scoring
// categories: Import/API Analysis (max 20), Entropy
// Analysis (max 15), Packing Indicators (max 15), String
// Analysis (max 10), Section Anomalies (max 10), Entry
// Point Anomalies (max 10), Anti-Analysis Indicators
// (max 10), and YARA Signature Matches (max 10).
// score_imports weights injection chains (15), hollowing
// chains (15), credential access (12), APC injection (8),
// anti-debug APIs (8), download/execute (6), persistence
// (7), very few imports (5), and Linux-specific chains
// (ptrace 8, RWX memory 5, C2 10, network listener 8,
// dynamic loading 5, process injection 15).
// score_entropy flags high-entropy sections (6 pts, cap 2)
// and very high overall entropy (3 pts). score_packing
// checks packer section names (5), signature matches (3),
// empty raw with virtual (4), high VR ratio (3), PUSHAD
// at EP (3), and modified UPX without magic string (5).
// score_strings checks C2 URL patterns with suspicious
// TLDs, shell commands, base64-encoded PE headers, registry
// persistence paths, and crypto wallet addresses.
// score_sections flags RWX sections (5), empty names (3),
// unusual section counts (2), and zero-size code (4).
// score_entry_point flags EP outside .text (5), EP in last
// section (5), EP outside all sections (7), and TLS
// callbacks (3). score_anti_analysis checks
// IsDebuggerPresent (3), NtQueryInformationProcess (5), VM
// detection strings (3), sandbox evasion (3), timing APIs
// (3), Linux ptrace checks (5), and /proc/self analysis
// (3). score_yara weights malware/critical rules (10),
// packer rules (3), and suspicious rules (5). classify_risk
// maps totals to five RiskLevel bands: Benign (0-15), Low
// (16-35), Medium (36-55), High (56-75), Critical (76+).
// MITRE technique mappings are deduplicated from import
// combinations and per-API mappings. generate_summary
// ranks the top 5 findings by points. Unit tests verify
// risk classification thresholds, category capping, empty
// scoring, summary generation, YARA malware/packer
// scoring, entropy scoring, RWX section scoring, and full
// context population through all predecessor passes.
//
// Connects to:
//   pass.rs            - AnalysisPass trait, Sealed
//   context.rs         - AnalysisContext
//   formats/mod.rs     - FormatResult, FormatAnomaly
//   passes/imports.rs  - ImportResult
//   passes/strings.rs  - StringResult
//   passes/entropy.rs  - EntropyResult
//   yara.rs            - YaraScanner, YaraMatch
//   types.rs           - RiskLevel, EntropyFlag,
//                         StringCategory
//   error.rs           - EngineError

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::formats::{FormatAnomaly, FormatResult};
use crate::pass::{AnalysisPass, Sealed};
use crate::passes::entropy::EntropyResult;
use crate::passes::imports::ImportResult;
use crate::passes::strings::StringResult;
use crate::types::{
    EntropyFlag, RiskLevel, StringCategory,
};
use crate::yara::{YaraMatch, YaraScanner};

const IMPORT_MAX: u32 = 20;
const ENTROPY_MAX: u32 = 15;
const PACKING_MAX: u32 = 15;
const STRING_MAX: u32 = 10;
const SECTION_MAX: u32 = 10;
const ENTRY_POINT_MAX: u32 = 10;
const ANTI_ANALYSIS_MAX: u32 = 10;
const YARA_MAX: u32 = 10;

const INJECTION_CHAIN: u32 = 15;
const HOLLOWING_CHAIN: u32 = 15;
const CREDENTIAL_ACCESS: u32 = 12;
const ANTI_DEBUG_API: u32 = 8;
const REGISTRY_RUN_KEYS: u32 = 7;
const NETWORK_DOWNLOAD: u32 = 6;
const VERY_FEW_IMPORTS: u32 = 5;
const APC_INJECTION: u32 = 8;
const LINUX_PTRACE: u32 = 8;
const LINUX_RWX_MEMORY: u32 = 5;
const LINUX_C2_CONNECTION: u32 = 10;
const LINUX_NETWORK_LISTENER: u32 = 8;
const LINUX_DYNAMIC_LOADING: u32 = 5;
const LINUX_PROCESS_INJECTION: u32 = 15;

const HIGH_SECTION_ENTROPY: u32 = 6;
const HIGH_SECTION_ENTROPY_CAP: u32 = 2;
const VERY_HIGH_OVERALL_ENTROPY: u32 = 3;
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;
const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 6.8;

const PACKER_SECTION_NAME: u32 = 5;
const PACKER_SIGNATURE_MATCH: u32 = 3;
const EMPTY_RAW_WITH_VIRTUAL: u32 = 4;
const HIGH_VR_RATIO: u32 = 3;
const PUSHAD_EP: u32 = 3;
const MODIFIED_UPX: u32 = 5;

const C2_PATTERN: u32 = 5;
const SUSPICIOUS_COMMANDS: u32 = 3;
const BASE64_PE_HEADER: u32 = 4;
const REGISTRY_PERSISTENCE: u32 = 3;
const CRYPTO_WALLET: u32 = 3;

const RWX_SECTION: u32 = 5;
const EMPTY_SECTION_NAME: u32 = 3;
const UNUSUAL_SECTION_COUNT: u32 = 2;
const ZERO_SIZE_CODE: u32 = 4;

const EP_OUTSIDE_TEXT: u32 = 5;
const EP_LAST_SECTION: u32 = 5;
const EP_OUTSIDE_ALL: u32 = 7;
const TLS_CALLBACKS: u32 = 3;

const IS_DEBUGGER_PRESENT: u32 = 3;
const NT_QUERY_INFO_PROCESS: u32 = 5;
const VM_DETECTION_STRINGS: u32 = 3;
const TIMING_CHECK_APIS: u32 = 3;
const SANDBOX_EVASION: u32 = 3;
const LINUX_PTRACE_CHECK: u32 = 5;
const PROC_SELF_ANALYSIS: u32 = 3;

const YARA_MALWARE_FAMILY: u32 = 10;
const YARA_PACKER_RULE: u32 = 3;
const YARA_SUSPICIOUS: u32 = 5;

const FEW_IMPORTS_THRESHOLD: usize = 3;
const MAX_NORMAL_SECTIONS: usize = 15;
const BENIGN_MAX: u32 = 15;
const LOW_MAX: u32 = 35;
const MEDIUM_MAX: u32 = 55;
const HIGH_MAX: u32 = 75;
const SUMMARY_TOP_N: usize = 5;

const SUSPICIOUS_TLDS: &[&str] = &[
    ".ru", ".cn", ".tk", ".pw", ".cc", ".top",
    ".xyz", ".buzz", ".onion",
];

const BASE64_MZ_PREFIXES: &[&str] =
    &["TVqQ", "TVpQ", "TVoA", "TVpB"];

const TIMING_CHECK_FUNCTIONS: &[&str] = &[
    "GetTickCount64",
    "GetTickCount",
    "QueryPerformanceCounter",
    "rdtsc",
];

const VM_STRINGS: &[&str] = &[
    "vmware", "virtualbox", "vbox", "qemu",
    "hyper-v", "xen",
];

const SANDBOX_STRINGS: &[&str] = &[
    "sandbox", "cuckoo", "wireshark", "procmon",
    "sandboxie",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResult {
    pub total_score: u32,
    pub risk_level: RiskLevel,
    pub categories: Vec<ScoringCategory>,
    pub mitre_techniques: Vec<MitreMapping>,
    pub yara_matches: Vec<YaraMatch>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringCategory {
    pub name: String,
    pub score: u32,
    pub max_score: u32,
    pub details: Vec<ScoringDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringDetail {
    pub rule: String,
    pub points: u32,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub evidence: String,
}

pub struct ThreatPass;

impl Sealed for ThreatPass {}

impl AnalysisPass for ThreatPass {
    fn name(&self) -> &'static str {
        "threat"
    }

    fn dependencies(&self) -> &[&'static str] {
        &[
            "format", "imports", "strings",
            "entropy", "disasm",
        ]
    }

    fn run(
        &self,
        ctx: &mut AnalysisContext,
    ) -> Result<(), EngineError> {
        let yara_scanner = YaraScanner::new()?;
        let yara_matches =
            yara_scanner.scan(ctx.data())?;

        let format_result = ctx.format_result.as_ref();
        let import_result = ctx.import_result.as_ref();
        let string_result = ctx.string_result.as_ref();
        let entropy_result =
            ctx.entropy_result.as_ref();

        let result = compute_threat_score(
            format_result,
            import_result,
            string_result,
            entropy_result,
            &yara_matches,
        );
        ctx.threat_result = Some(result);
        Ok(())
    }
}

pub fn compute_threat_score(
    format_result: Option<&FormatResult>,
    import_result: Option<&ImportResult>,
    string_result: Option<&StringResult>,
    entropy_result: Option<&EntropyResult>,
    yara_matches: &[YaraMatch],
) -> ThreatResult {
    let cat_import =
        score_imports(import_result, string_result);
    let cat_entropy = score_entropy(entropy_result);
    let cat_packing = score_packing(
        entropy_result,
        format_result,
        string_result,
    );
    let cat_strings = score_strings(string_result);
    let cat_sections = score_sections(format_result);
    let cat_ep = score_entry_point(format_result);
    let cat_anti = score_anti_analysis(
        import_result,
        string_result,
    );
    let cat_yara = score_yara(yara_matches);

    let categories = vec![
        cat_import,
        cat_entropy,
        cat_packing,
        cat_strings,
        cat_sections,
        cat_ep,
        cat_anti,
        cat_yara,
    ];

    let total_score: u32 = categories
        .iter()
        .map(|c| c.score.min(c.max_score))
        .sum();

    let risk_level = classify_risk(total_score);

    let mut mitre_techniques = Vec::new();
    if let Some(ir) = import_result {
        for combo in &ir.suspicious_combinations {
            if !combo.mitre_id.is_empty() {
                mitre_techniques.push(MitreMapping {
                    technique_id: combo
                        .mitre_id
                        .clone(),
                    technique_name: combo
                        .name
                        .clone(),
                    tactic: combo
                        .description
                        .clone(),
                    evidence: combo
                        .apis
                        .join(" + "),
                });
            }
        }
        for mapping in &ir.mitre_mappings {
            mitre_techniques.push(MitreMapping {
                technique_id: mapping
                    .technique_id
                    .clone(),
                technique_name: mapping.tag.clone(),
                tactic: mapping.tag.clone(),
                evidence: mapping.api.clone(),
            });
        }
    }

    let mut seen_techniques = HashSet::new();
    mitre_techniques.retain(|t| {
        seen_techniques.insert(t.technique_id.clone())
    });

    let summary = generate_summary(
        &categories,
        total_score,
        &risk_level,
    );

    ThreatResult {
        total_score,
        risk_level,
        categories,
        mitre_techniques,
        yara_matches: yara_matches.to_vec(),
        summary,
    }
}

pub fn classify_risk(score: u32) -> RiskLevel {
    match score {
        0..=BENIGN_MAX => RiskLevel::Benign,
        16..=LOW_MAX => RiskLevel::Low,
        36..=MEDIUM_MAX => RiskLevel::Medium,
        56..=HIGH_MAX => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

fn score_imports(
    import_result: Option<&ImportResult>,
    string_result: Option<&StringResult>,
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    if let Some(ir) = import_result {
        for combo in &ir.suspicious_combinations {
            let points = match combo.name.as_str() {
                "Process Injection Chain" => {
                    INJECTION_CHAIN
                }
                "Process Hollowing" => {
                    HOLLOWING_CHAIN
                }
                "Credential Theft" => {
                    CREDENTIAL_ACCESS
                }
                "APC Injection" => APC_INJECTION,
                "DLL Injection" => ANTI_DEBUG_API,
                "Download and Execute"
                | "Download and Execute (WinInet)" => {
                    NETWORK_DOWNLOAD
                }
                "Registry Persistence" => {
                    REGISTRY_RUN_KEYS
                }
                "Service Persistence" => {
                    REGISTRY_RUN_KEYS
                }
                "Linux ptrace Injection" => {
                    LINUX_PTRACE
                }
                "Linux RWX Memory" => {
                    LINUX_RWX_MEMORY
                }
                "Linux C2 Connection" => {
                    LINUX_C2_CONNECTION
                }
                "Linux Network Listener" => {
                    LINUX_NETWORK_LISTENER
                }
                "Linux Dynamic Loading" => {
                    LINUX_DYNAMIC_LOADING
                }
                "Linux Process Injection" => {
                    LINUX_PROCESS_INJECTION
                }
                _ => 3,
            };
            details.push(ScoringDetail {
                rule: format!(
                    "{} detected",
                    combo.name
                ),
                points,
                evidence: combo
                    .apis
                    .join(" + "),
            });
            raw += points;
        }

        for imp in &ir.imports {
            if imp.is_suspicious
                && imp
                    .threat_tags
                    .iter()
                    .any(|t| t == "anti-debug")
            {
                let pts = if imp.function
                    == "NtQueryInformationProcess"
                {
                    ANTI_DEBUG_API
                } else {
                    3
                };
                details.push(ScoringDetail {
                    rule: format!(
                        "Anti-debug API: {}",
                        imp.function
                    ),
                    points: pts,
                    evidence: imp.function.clone(),
                });
                raw += pts;
            }
        }

        if ir.statistics.total_imports
            < FEW_IMPORTS_THRESHOLD
            && ir.statistics.total_imports > 0
        {
            details.push(ScoringDetail {
                rule: "Very few imports".into(),
                points: VERY_FEW_IMPORTS,
                evidence: format!(
                    "{} imports",
                    ir.statistics.total_imports
                ),
            });
            raw += VERY_FEW_IMPORTS;
        }
    }

    if let Some(sr) = string_result {
        let import_names: HashSet<&str> = import_result
            .map(|ir| {
                ir.imports
                    .iter()
                    .map(|i| i.function.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let string_only_apis = sr
            .strings
            .iter()
            .filter(|s| {
                s.category
                    == StringCategory::SuspiciousApi
                    && !import_names
                        .contains(s.value.as_str())
            })
            .count();
        if string_only_apis > 0 {
            details.push(ScoringDetail {
                rule: "Suspicious API strings (not imported)".into(),
                points: 3,
                evidence: format!(
                    "{string_only_apis} API names found in strings only"
                ),
            });
            raw += 3;
        }
    }

    ScoringCategory {
        name: "Import/API Analysis".into(),
        score: raw.min(IMPORT_MAX),
        max_score: IMPORT_MAX,
        details,
    }
}

fn score_entropy(
    entropy_result: Option<&EntropyResult>,
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    if let Some(er) = entropy_result {
        let mut high_count = 0u32;
        for section in &er.sections {
            if section.entropy > HIGH_ENTROPY_THRESHOLD
                && high_count < HIGH_SECTION_ENTROPY_CAP
            {
                details.push(ScoringDetail {
                    rule: format!(
                        "High entropy section: {}",
                        section.name
                    ),
                    points: HIGH_SECTION_ENTROPY,
                    evidence: format!(
                        "entropy={:.2}",
                        section.entropy
                    ),
                });
                raw += HIGH_SECTION_ENTROPY;
                high_count += 1;
            }
        }

        if er.overall_entropy
            > VERY_HIGH_ENTROPY_THRESHOLD
        {
            details.push(ScoringDetail {
                rule: "Very high overall entropy"
                    .into(),
                points: VERY_HIGH_OVERALL_ENTROPY,
                evidence: format!(
                    "overall={:.2}",
                    er.overall_entropy
                ),
            });
            raw += VERY_HIGH_OVERALL_ENTROPY;
        }
    }

    ScoringCategory {
        name: "Entropy Analysis".into(),
        score: raw.min(ENTROPY_MAX),
        max_score: ENTROPY_MAX,
        details,
    }
}

fn score_packing(
    entropy_result: Option<&EntropyResult>,
    format_result: Option<&FormatResult>,
    string_result: Option<&StringResult>,
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    if let Some(er) = entropy_result {
        let mut has_packer_section = false;
        for section in &er.sections {
            if section
                .flags
                .contains(&EntropyFlag::PackerSectionName)
            {
                has_packer_section = true;
                details.push(ScoringDetail {
                    rule: "Known packer section name"
                        .into(),
                    points: PACKER_SECTION_NAME,
                    evidence: section.name.clone(),
                });
                raw += PACKER_SECTION_NAME;
            }
            if section
                .flags
                .contains(&EntropyFlag::EmptyRawData)
            {
                details.push(ScoringDetail {
                    rule:
                        "Empty raw with virtual size"
                            .into(),
                    points: EMPTY_RAW_WITH_VIRTUAL,
                    evidence: format!(
                        "section={} virtual={}",
                        section.name,
                        section.virtual_to_raw_ratio
                    ),
                });
                raw += EMPTY_RAW_WITH_VIRTUAL;
            }
            if section.flags.contains(
                &EntropyFlag::HighVirtualToRawRatio,
            ) {
                details.push(ScoringDetail {
                    rule: "High virtual/raw ratio"
                        .into(),
                    points: HIGH_VR_RATIO,
                    evidence: format!(
                        "section={} ratio={:.1}",
                        section.name,
                        section.virtual_to_raw_ratio
                    ),
                });
                raw += HIGH_VR_RATIO;
            }
        }

        if let Some(packer) = &er.packer_name {
            details.push(ScoringDetail {
                rule: "Packer signature match".into(),
                points: PACKER_SIGNATURE_MATCH,
                evidence: packer.clone(),
            });
            raw += PACKER_SIGNATURE_MATCH;
        }

        let has_pushad = er
            .packing_indicators
            .iter()
            .any(|pi| {
                pi.indicator_type == "entry_point"
            });
        if has_pushad {
            details.push(ScoringDetail {
                rule: "PUSHAD at entry point".into(),
                points: PUSHAD_EP,
                evidence: "0x60 at EP".into(),
            });
            raw += PUSHAD_EP;
        }

        let has_upx_sections = er
            .packing_indicators
            .iter()
            .any(|pi| {
                pi.packer_name.as_deref()
                    == Some("UPX")
            });
        let has_upx_magic = string_result
            .map_or(false, |sr| {
                sr.strings.iter().any(|s| {
                    s.value.contains("UPX!")
                })
            });
        if has_packer_section
            && has_upx_sections
            && !has_upx_magic
        {
            details.push(ScoringDetail {
                rule: "Modified UPX".into(),
                points: MODIFIED_UPX,
                evidence: "UPX sections without UPX! magic".into(),
            });
            raw += MODIFIED_UPX;
        }
    }

    if let Some(fr) = format_result {
        let suspicious_section_count =
            fr.sections.iter().filter(|s| {
                crate::formats::SUSPICIOUS_SECTION_NAMES
                    .iter()
                    .any(|&(sus, _)| s.name == sus)
            }).count();
        if suspicious_section_count > 0 {
            details.push(ScoringDetail {
                rule: "Suspicious section names".into(),
                points: 3,
                evidence: format!(
                    "{suspicious_section_count} suspicious section names"
                ),
            });
            raw += 3;
        }
    }

    ScoringCategory {
        name: "Packing Indicators".into(),
        score: raw.min(PACKING_MAX),
        max_score: PACKING_MAX,
        details,
    }
}

fn score_strings(
    string_result: Option<&StringResult>,
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    if let Some(sr) = string_result {
        let has_suspicious_urls =
            sr.strings.iter().any(|s| {
                s.category == StringCategory::Url
                    && SUSPICIOUS_TLDS.iter().any(
                        |tld| {
                            s.value
                                .to_ascii_lowercase()
                                .contains(tld)
                        },
                    )
            });
        if has_suspicious_urls {
            details.push(ScoringDetail {
                rule: "C2/malicious URL patterns"
                    .into(),
                points: C2_PATTERN,
                evidence: "URL with suspicious TLD"
                    .into(),
            });
            raw += C2_PATTERN;
        }

        let has_shell_commands = sr
            .strings
            .iter()
            .any(|s| {
                s.category == StringCategory::ShellCommand
            });
        if has_shell_commands {
            details.push(ScoringDetail {
                rule: "Suspicious shell commands"
                    .into(),
                points: SUSPICIOUS_COMMANDS,
                evidence: "Shell command strings found"
                    .into(),
            });
            raw += SUSPICIOUS_COMMANDS;
        }

        let has_base64_pe = sr.strings.iter().any(
            |s| {
                s.category == StringCategory::EncodedData
                    && BASE64_MZ_PREFIXES.iter().any(
                        |prefix| {
                            s.value.starts_with(prefix)
                        },
                    )
            },
        );
        if has_base64_pe {
            details.push(ScoringDetail {
                rule: "Base64-encoded PE header"
                    .into(),
                points: BASE64_PE_HEADER,
                evidence: "TVqQ/TVpQ prefix in Base64"
                    .into(),
            });
            raw += BASE64_PE_HEADER;
        }

        let has_reg_persistence = sr
            .strings
            .iter()
            .any(|s| {
                s.category
                    == StringCategory::PersistencePath
            });
        if has_reg_persistence {
            details.push(ScoringDetail {
                rule: "Registry persistence paths"
                    .into(),
                points: REGISTRY_PERSISTENCE,
                evidence:
                    "Run/RunOnce registry paths found"
                        .into(),
            });
            raw += REGISTRY_PERSISTENCE;
        }

        let has_crypto_wallets = sr
            .strings
            .iter()
            .any(|s| {
                s.category
                    == StringCategory::CryptoWallet
            });
        if has_crypto_wallets {
            details.push(ScoringDetail {
                rule: "Crypto wallet addresses".into(),
                points: CRYPTO_WALLET,
                evidence: "BTC/ETH address patterns"
                    .into(),
            });
            raw += CRYPTO_WALLET;
        }
    }

    ScoringCategory {
        name: "String Analysis".into(),
        score: raw.min(STRING_MAX),
        max_score: STRING_MAX,
        details,
    }
}

fn score_sections(
    format_result: Option<&FormatResult>,
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    if let Some(fr) = format_result {
        let has_rwx = fr.anomalies.iter().any(|a| {
            matches!(
                a,
                FormatAnomaly::RwxSection { .. }
            )
        });
        if has_rwx {
            details.push(ScoringDetail {
                rule: "RWX section detected".into(),
                points: RWX_SECTION,
                evidence: "Read+Write+Execute section"
                    .into(),
            });
            raw += RWX_SECTION;
        }

        let has_empty_name =
            fr.anomalies.iter().any(|a| {
                matches!(
                    a,
                    FormatAnomaly::EmptySectionName {
                        ..
                    }
                )
            });
        if has_empty_name {
            details.push(ScoringDetail {
                rule: "Empty/null section name".into(),
                points: EMPTY_SECTION_NAME,
                evidence:
                    "Section with empty or null name"
                        .into(),
            });
            raw += EMPTY_SECTION_NAME;
        }

        let section_count = fr.sections.len();
        if section_count > MAX_NORMAL_SECTIONS
            || section_count == 0
        {
            details.push(ScoringDetail {
                rule: "Unusual section count".into(),
                points: UNUSUAL_SECTION_COUNT,
                evidence: format!(
                    "{section_count} sections"
                ),
            });
            raw += UNUSUAL_SECTION_COUNT;
        }

        let has_zero_code = fr.sections.iter().any(
            |s| {
                (s.name == ".text" || s.name == ".code")
                    && s.raw_size == 0
            },
        );
        if has_zero_code {
            details.push(ScoringDetail {
                rule: "Zero-size code section".into(),
                points: ZERO_SIZE_CODE,
                evidence:
                    ".text/.code with raw_size == 0"
                        .into(),
            });
            raw += ZERO_SIZE_CODE;
        }
    }

    ScoringCategory {
        name: "Section Anomalies".into(),
        score: raw.min(SECTION_MAX),
        max_score: SECTION_MAX,
        details,
    }
}

fn score_entry_point(
    format_result: Option<&FormatResult>,
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    if let Some(fr) = format_result {
        let ep = fr.entry_point;

        let ep_section = fr.sections.iter().find(|s| {
            ep >= s.virtual_address
                && ep < s.virtual_address
                    + s.virtual_size
        });

        let in_text = fr.sections.iter().any(|s| {
            s.name == ".text"
                && ep >= s.virtual_address
                && ep < s.virtual_address
                    + s.virtual_size
        });

        if !in_text && ep_section.is_some() {
            details.push(ScoringDetail {
                rule: "EP outside .text section"
                    .into(),
                points: EP_OUTSIDE_TEXT,
                evidence: format!(
                    "EP=0x{ep:x} not in .text"
                ),
            });
            raw += EP_OUTSIDE_TEXT;
        }

        if ep_section.is_none() && !fr.sections.is_empty()
        {
            details.push(ScoringDetail {
                rule: "EP outside all sections".into(),
                points: EP_OUTSIDE_ALL,
                evidence: format!(
                    "EP=0x{ep:x} not in any section"
                ),
            });
            raw += EP_OUTSIDE_ALL;
        }

        if let Some(last) = fr.sections.last() {
            if ep >= last.virtual_address
                && ep < last.virtual_address
                    + last.virtual_size
                && fr.sections.len() > 1
            {
                details.push(ScoringDetail {
                    rule: "EP in last section".into(),
                    points: EP_LAST_SECTION,
                    evidence: format!(
                        "EP=0x{ep:x} in last section '{}'",
                        last.name
                    ),
                });
                raw += EP_LAST_SECTION;
            }
        }

        let has_tls = fr.anomalies.iter().any(|a| {
            matches!(
                a,
                FormatAnomaly::TlsCallbacksPresent {
                    ..
                }
            )
        });
        if has_tls {
            details.push(ScoringDetail {
                rule: "TLS callbacks present".into(),
                points: TLS_CALLBACKS,
                evidence: "PE TLS callback entries"
                    .into(),
            });
            raw += TLS_CALLBACKS;
        }
    }

    ScoringCategory {
        name: "Entry Point Anomalies".into(),
        score: raw.min(ENTRY_POINT_MAX),
        max_score: ENTRY_POINT_MAX,
        details,
    }
}

fn score_anti_analysis(
    import_result: Option<&ImportResult>,
    string_result: Option<&StringResult>,
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    let all_names = collect_api_and_string_names(
        import_result,
        string_result,
    );

    if all_names.iter().any(|n| n == "IsDebuggerPresent")
    {
        details.push(ScoringDetail {
            rule: "IsDebuggerPresent detected".into(),
            points: IS_DEBUGGER_PRESENT,
            evidence: "IsDebuggerPresent".into(),
        });
        raw += IS_DEBUGGER_PRESENT;
    }

    if all_names
        .iter()
        .any(|n| n == "NtQueryInformationProcess")
    {
        details.push(ScoringDetail {
            rule: "NtQueryInformationProcess detected"
                .into(),
            points: NT_QUERY_INFO_PROCESS,
            evidence: "NtQueryInformationProcess"
                .into(),
        });
        raw += NT_QUERY_INFO_PROCESS;
    }

    if let Some(sr) = string_result {
        let has_vm = sr.strings.iter().any(|s| {
            let lower = s.value.to_ascii_lowercase();
            VM_STRINGS
                .iter()
                .any(|vm| lower.contains(vm))
        });
        if has_vm {
            details.push(ScoringDetail {
                rule: "VM detection strings".into(),
                points: VM_DETECTION_STRINGS,
                evidence:
                    "VMware/VBox/QEMU/Hyper-V strings"
                        .into(),
            });
            raw += VM_DETECTION_STRINGS;
        }

        let has_sandbox = sr.strings.iter().any(|s| {
            let lower = s.value.to_ascii_lowercase();
            SANDBOX_STRINGS
                .iter()
                .any(|sb| lower.contains(sb))
        });
        if has_sandbox {
            details.push(ScoringDetail {
                rule: "Sandbox evasion strings".into(),
                points: SANDBOX_EVASION,
                evidence:
                    "sandbox/cuckoo/wireshark strings"
                        .into(),
            });
            raw += SANDBOX_EVASION;
        }

        let has_linux_anti_debug =
            sr.strings.iter().any(|s| {
                s.category
                    == StringCategory::AntiAnalysis
                    && s.value.contains("TracerPid")
            });
        if has_linux_anti_debug {
            details.push(ScoringDetail {
                rule: "Linux ptrace anti-debug"
                    .into(),
                points: LINUX_PTRACE_CHECK,
                evidence:
                    "TracerPid check detected"
                        .into(),
            });
            raw += LINUX_PTRACE_CHECK;
        }

        let has_proc_analysis =
            sr.strings.iter().any(|s| {
                s.category
                    == StringCategory::AntiAnalysis
                    && (s.value
                        .contains("/proc/self/maps")
                        || s.value.contains(
                            "/proc/self/status",
                        ))
            });
        if has_proc_analysis {
            details.push(ScoringDetail {
                rule: "/proc/self analysis".into(),
                points: PROC_SELF_ANALYSIS,
                evidence:
                    "Process self-inspection detected"
                        .into(),
            });
            raw += PROC_SELF_ANALYSIS;
        }
    }

    let has_timing = all_names.iter().any(|n| {
        TIMING_CHECK_FUNCTIONS
            .iter()
            .any(|t| n.contains(t))
    });
    if has_timing {
        details.push(ScoringDetail {
            rule: "Timing check APIs".into(),
            points: TIMING_CHECK_APIS,
            evidence: "GetTickCount/QueryPerformanceCounter".into(),
        });
        raw += TIMING_CHECK_APIS;
    }

    ScoringCategory {
        name: "Anti-Analysis Indicators".into(),
        score: raw.min(ANTI_ANALYSIS_MAX),
        max_score: ANTI_ANALYSIS_MAX,
        details,
    }
}

fn score_yara(
    yara_matches: &[YaraMatch],
) -> ScoringCategory {
    let mut details = Vec::new();
    let mut raw = 0u32;

    for ym in yara_matches {
        let category = ym
            .metadata
            .category
            .as_deref()
            .unwrap_or("");
        let severity = ym
            .metadata
            .severity
            .as_deref()
            .unwrap_or("");

        let points = if category == "malware"
            || severity == "critical"
        {
            YARA_MALWARE_FAMILY
        } else if category == "packer" {
            YARA_PACKER_RULE
        } else if category == "c2"
            || category == "credential-access"
        {
            YARA_SUSPICIOUS + 2
        } else {
            YARA_SUSPICIOUS
        };

        details.push(ScoringDetail {
            rule: format!(
                "YARA: {}",
                ym.rule_name
            ),
            points,
            evidence: ym
                .metadata
                .description
                .clone()
                .unwrap_or_default(),
        });
        raw += points;
    }

    ScoringCategory {
        name: "YARA Signature Matches".into(),
        score: raw.min(YARA_MAX),
        max_score: YARA_MAX,
        details,
    }
}

fn collect_api_and_string_names(
    import_result: Option<&ImportResult>,
    string_result: Option<&StringResult>,
) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(ir) = import_result {
        for imp in &ir.imports {
            names.push(imp.function.clone());
        }
    }
    if let Some(sr) = string_result {
        for s in &sr.strings {
            if s.category
                == StringCategory::SuspiciousApi
            {
                names.push(s.value.clone());
            }
        }
    }
    names
}

fn generate_summary(
    categories: &[ScoringCategory],
    total_score: u32,
    risk_level: &RiskLevel,
) -> String {
    let mut all_details: Vec<(&str, &ScoringDetail)> =
        Vec::new();
    for cat in categories {
        for detail in &cat.details {
            all_details
                .push((&cat.name, detail));
        }
    }
    all_details
        .sort_by(|a, b| b.1.points.cmp(&a.1.points));

    let top: Vec<String> = all_details
        .iter()
        .take(SUMMARY_TOP_N)
        .map(|(_, d)| d.rule.clone())
        .collect();

    if top.is_empty() {
        return format!(
            "{risk_level} risk (score {total_score}/100): \
             No significant threat indicators detected"
        );
    }

    format!(
        "{risk_level} risk (score {total_score}/100): {}",
        top.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_classification() {
        assert_eq!(classify_risk(0), RiskLevel::Benign);
        assert_eq!(
            classify_risk(15),
            RiskLevel::Benign
        );
        assert_eq!(classify_risk(16), RiskLevel::Low);
        assert_eq!(classify_risk(35), RiskLevel::Low);
        assert_eq!(
            classify_risk(36),
            RiskLevel::Medium
        );
        assert_eq!(
            classify_risk(55),
            RiskLevel::Medium
        );
        assert_eq!(classify_risk(56), RiskLevel::High);
        assert_eq!(classify_risk(75), RiskLevel::High);
        assert_eq!(
            classify_risk(76),
            RiskLevel::Critical
        );
        assert_eq!(
            classify_risk(100),
            RiskLevel::Critical
        );
    }

    #[test]
    fn category_capping() {
        let cat = ScoringCategory {
            name: "Test".into(),
            score: 30,
            max_score: 20,
            details: Vec::new(),
        };
        assert_eq!(cat.score.min(cat.max_score), 20);
    }

    #[test]
    fn total_is_sum_of_capped() {
        let result = compute_threat_score(
            None, None, None, None, &[],
        );
        assert_eq!(result.total_score, 0);
        assert_eq!(
            result.risk_level,
            RiskLevel::Benign
        );
    }

    #[test]
    fn summary_empty_when_no_threats() {
        let result = compute_threat_score(
            None, None, None, None, &[],
        );
        assert!(result.summary.contains("BENIGN"));
        assert!(result.summary.contains("0/100"));
    }

    #[test]
    fn yara_scoring_malware() {
        let matches = vec![YaraMatch {
            rule_name: "test_malware".into(),
            tags: Vec::new(),
            metadata: crate::yara::YaraMetadata {
                description: Some(
                    "Test malware rule".into(),
                ),
                category: Some("malware".into()),
                severity: Some("critical".into()),
            },
            matched_strings: Vec::new(),
        }];
        let cat = score_yara(&matches);
        assert_eq!(cat.score, YARA_MALWARE_FAMILY);
    }

    #[test]
    fn yara_scoring_packer() {
        let matches = vec![YaraMatch {
            rule_name: "test_packer".into(),
            tags: Vec::new(),
            metadata: crate::yara::YaraMetadata {
                description: Some(
                    "Test packer rule".into(),
                ),
                category: Some("packer".into()),
                severity: Some("medium".into()),
            },
            matched_strings: Vec::new(),
        }];
        let cat = score_yara(&matches);
        assert_eq!(cat.score, YARA_PACKER_RULE);
    }

    #[test]
    fn entropy_scoring() {
        use crate::passes::entropy::{
            EntropyResult, SectionEntropy,
        };
        use crate::types::EntropyClassification;

        let er = EntropyResult {
            overall_entropy: 7.2,
            sections: vec![SectionEntropy {
                name: ".text".into(),
                entropy: 7.5,
                size: 4096,
                classification:
                    EntropyClassification::Encrypted,
                virtual_to_raw_ratio: 1.0,
                is_anomalous: true,
                flags: vec![EntropyFlag::HighEntropy],
            }],
            packing_detected: false,
            packer_name: None,
            packing_indicators: Vec::new(),
        };
        let cat = score_entropy(Some(&er));
        assert!(
            cat.score > 0,
            "should score for high entropy"
        );
        assert!(cat.details.len() >= 2);
    }

    #[test]
    fn section_rwx_scoring() {
        use crate::formats::{
            FormatResult, SectionInfo,
        };
        use crate::types::{
            Architecture, BinaryFormat, Endianness,
            SectionPermissions,
        };

        let fr = FormatResult {
            format: BinaryFormat::Elf,
            architecture: Architecture::X86_64,
            bits: 64,
            endianness: Endianness::Little,
            entry_point: 0x1000,
            is_stripped: false,
            is_pie: false,
            has_debug_info: false,
            sections: vec![SectionInfo {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0,
                raw_size: 0x1000,
                permissions: SectionPermissions {
                    read: true,
                    write: true,
                    execute: true,
                },
                sha256: String::new(),
            }],
            segments: Vec::new(),
            anomalies: vec![
                FormatAnomaly::RwxSection {
                    name: ".text".into(),
                },
            ],
            pe_info: None,
            elf_info: None,
            macho_info: None,
            function_hints: Vec::new(),
        };
        let cat = score_sections(Some(&fr));
        assert_eq!(cat.score, RWX_SECTION);
    }

    #[test]
    fn threat_pass_populates_context() {
        use std::sync::Arc;
        use crate::context::BinarySource;

        fn load_fixture(name: &str) -> Vec<u8> {
            let path = format!(
                "{}/tests/fixtures/{name}",
                env!("CARGO_MANIFEST_DIR"),
            );
            std::fs::read(&path).unwrap_or_else(
                |e| panic!("fixture {path}: {e}"),
            )
        }

        let data = load_fixture("hello_elf");
        let size = data.len() as u64;
        let mut ctx = AnalysisContext::new(
            BinarySource::Buffered(Arc::from(data)),
            "deadbeef".into(),
            "test.bin".into(),
            size,
        );

        crate::passes::format::FormatPass
            .run(&mut ctx)
            .unwrap();
        crate::passes::imports::ImportPass
            .run(&mut ctx)
            .unwrap();
        crate::passes::strings::StringPass
            .run(&mut ctx)
            .unwrap();
        crate::passes::entropy::EntropyPass
            .run(&mut ctx)
            .unwrap();
        crate::passes::disasm::DisasmPass
            .run(&mut ctx)
            .unwrap();

        assert!(ctx.threat_result.is_none());
        ThreatPass.run(&mut ctx).unwrap();
        assert!(ctx.threat_result.is_some());

        let result = ctx.threat_result.unwrap();
        assert_eq!(result.categories.len(), 8);
        assert!(result.total_score <= 100);
    }
}
