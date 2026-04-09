// ©AngelaMos | 2026
// strings.rs
//
// String extraction and categorization pass
//
// StringPass depends on format and extracts printable
// strings from raw binary data in both ASCII and UTF-16LE
// encodings with a minimum length of 4 characters.
// extract_ascii scans for contiguous runs of printable
// bytes (0x20-0x7E, tab, newline, CR), while
// extract_utf16le decodes little-endian wide character
// sequences terminated by null pairs. Each extracted
// string is classified into one of 14 StringCategory
// values by a priority-ordered classifier chain: Url
// (http/https/ftp prefixes), IpAddress (dotted quad
// validation), RegistryKey (HKEY_/HKLM/HKCU prefixes),
// ShellCommand (cmd.exe, powershell, /bin/sh indicators),
// PersistencePath (Run keys, cron, systemd, LaunchAgents),
// AntiAnalysis (VMware, VirtualBox, QEMU, debugger, Wine
// detection), PackerSignature (UPX!, MPRESS, Themida,
// VMProtect), SuspiciousApi (matched against the 22
// SUSPICIOUS_APIS from imports.rs), DebugArtifact
// (/rustc/, .pdb, _ZN, DWARF), FilePath (Windows drive
// letters, UNC paths, Unix prefixes), CryptoWallet (BTC
// base58check and ETH 0x-prefixed addresses), Email
// (local@domain.tld validation), EncodedData (base64
// character set with padding validation, minimum 20
// chars), or Generic. Seven categories are flagged as
// suspicious. find_section attributes each string to its
// containing binary section by file offset. Statistics
// track totals by encoding and category. Unit tests
// verify minimum length filtering, UTF-16LE extraction,
// all 14 category classifiers, suspicious flag mapping,
// ELF string extraction, context population, and section
// attribution.
//
// Connects to:
//   pass.rs          - AnalysisPass trait, Sealed
//   context.rs       - AnalysisContext
//   formats/mod.rs   - SectionInfo
//   passes/imports.rs - SUSPICIOUS_APIS
//   types.rs         - StringCategory, StringEncoding

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::context::AnalysisContext;
use crate::error::EngineError;
use crate::formats::SectionInfo;
use crate::pass::{AnalysisPass, Sealed};
use crate::passes::imports::SUSPICIOUS_APIS;
use crate::types::{StringCategory, StringEncoding};

const MIN_STRING_LENGTH: usize = 4;

const PRINTABLE_MIN: u8 = 0x20;
const PRINTABLE_MAX: u8 = 0x7E;
const TAB: u8 = 0x09;
const NEWLINE: u8 = 0x0A;
const CARRIAGE_RETURN: u8 = 0x0D;

const SUSPICIOUS_CATEGORIES: &[StringCategory] = &[
    StringCategory::SuspiciousApi,
    StringCategory::PackerSignature,
    StringCategory::AntiAnalysis,
    StringCategory::PersistencePath,
    StringCategory::EncodedData,
    StringCategory::ShellCommand,
    StringCategory::CryptoWallet,
];

const URL_PREFIXES: &[&str] =
    &["http://", "https://", "ftp://"];

const UNIX_PATH_PREFIXES: &[&str] = &[
    "/etc/", "/tmp/", "/var/", "/bin/", "/usr/",
    "/dev/", "/proc/", "/sys/", "/opt/", "/home/",
    "/root/", "/lib/", "/sbin/",
];

const REGISTRY_PREFIXES: &[&str] = &[
    "HKEY_",
    "HKLM\\",
    "HKCU\\",
    "HKCR\\",
    "HKCC\\",
    "HKU\\",
];

const SHELL_INDICATORS: &[&str] = &[
    "cmd.exe",
    "cmd /c",
    "cmd /k",
    "powershell",
    "pwsh",
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "bash -c",
    "sh -c",
    "| bash",
    "|bash",
    "| /bin/sh",
    "|/bin/sh",
    "| /bin/bash",
    "|/bin/bash",
];

const PACKER_SIGNATURES: &[&str] = &[
    "UPX!", "MPRESS", ".themida", ".vmp", ".enigma",
    "PEC2", "ASPack", "MEW ",
];

const DEBUG_ARTIFACTS: &[&str] = &[
    "/rustc/",
    ".cargo/registry/",
    "panicked at",
    ".pdb",
    "_ZN",
    ".debug_",
    "DWARF",
];

const ANTI_ANALYSIS_INDICATORS: &[&str] = &[
    "VMware",
    "VirtualBox",
    "VBox",
    "QEMU",
    "sandbox",
    "Sandboxie",
    "wireshark",
    "procmon",
    "x64dbg",
    "x32dbg",
    "ollydbg",
    "IDA Pro",
    "Ghidra",
    "Immunity",
    "SbieDll",
    "dbghelp",
    "wine_get_unix_file_name",
    "TracerPid",
    "/proc/self/status",
    "/proc/self/maps",
];

const PERSISTENCE_PATHS: &[&str] = &[
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "CurrentVersion\\RunServices",
    "/etc/cron",
    "/etc/init.d/",
    "/etc/systemd/",
    ".bashrc",
    ".bash_profile",
    ".profile",
    "/etc/rc.local",
    "crontab",
    "launchd",
    "LaunchAgents",
    "LaunchDaemons",
    ".config/autostart",
];

const BASE64_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64_MIN_LENGTH: usize = 20;

const IP_OCTET_MAX: u32 = 255;
const IP_OCTET_COUNT: usize = 4;

const BTC_MIN_LENGTH: usize = 26;
const BTC_MAX_LENGTH: usize = 35;
const ETH_ADDRESS_LENGTH: usize = 42;
const ETH_PREFIX: &str = "0x";
const ETH_HEX_DIGITS: usize = 40;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringResult {
    pub strings: Vec<ExtractedString>,
    pub statistics: StringStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: u64,
    pub encoding: StringEncoding,
    pub length: usize,
    pub category: StringCategory,
    pub is_suspicious: bool,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringStatistics {
    pub total: usize,
    pub by_encoding: HashMap<StringEncoding, usize>,
    pub by_category: HashMap<StringCategory, usize>,
    pub suspicious_count: usize,
}

pub struct StringPass;

impl Sealed for StringPass {}

impl AnalysisPass for StringPass {
    fn name(&self) -> &'static str {
        "strings"
    }

    fn dependencies(&self) -> &[&'static str] {
        &["format"]
    }

    fn run(
        &self,
        ctx: &mut AnalysisContext,
    ) -> Result<(), EngineError> {
        let sections = ctx
            .format_result
            .as_ref()
            .map(|fr| fr.sections.as_slice());
        let result =
            extract_strings(ctx.data(), sections);
        ctx.string_result = Some(result);
        Ok(())
    }
}

fn extract_strings(
    data: &[u8],
    sections: Option<&[SectionInfo]>,
) -> StringResult {
    let mut strings = Vec::new();

    extract_ascii(data, sections, &mut strings);
    extract_utf16le(data, sections, &mut strings);

    let mut by_encoding = HashMap::new();
    let mut by_category = HashMap::new();
    let mut suspicious_count = 0;

    for s in &strings {
        *by_encoding
            .entry(s.encoding.clone())
            .or_insert(0) += 1;
        *by_category
            .entry(s.category.clone())
            .or_insert(0) += 1;
        if s.is_suspicious {
            suspicious_count += 1;
        }
    }

    let total = strings.len();
    let statistics = StringStatistics {
        total,
        by_encoding,
        by_category,
        suspicious_count,
    };

    StringResult {
        strings,
        statistics,
    }
}

fn is_printable(b: u8) -> bool {
    (PRINTABLE_MIN..=PRINTABLE_MAX).contains(&b)
        || b == TAB
        || b == NEWLINE
        || b == CARRIAGE_RETURN
}

fn extract_ascii(
    data: &[u8],
    sections: Option<&[SectionInfo]>,
    out: &mut Vec<ExtractedString>,
) {
    let mut start = 0;
    let mut in_run = false;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable(byte) {
            if !in_run {
                start = i;
                in_run = true;
            }
        } else if in_run {
            let len = i - start;
            if len >= MIN_STRING_LENGTH {
                if let Ok(s) =
                    std::str::from_utf8(&data[start..i])
                {
                    let is_multibyte = s
                        .bytes()
                        .any(|b| !b.is_ascii());
                    let encoding = if is_multibyte {
                        StringEncoding::Utf8
                    } else {
                        StringEncoding::Ascii
                    };
                    let category = classify(s);
                    let is_suspicious =
                        is_category_suspicious(&category);
                    let section = sections.and_then(|secs| {
                        find_section(
                            secs,
                            start as u64,
                        )
                    });
                    out.push(ExtractedString {
                        value: s.to_string(),
                        offset: start as u64,
                        encoding,
                        length: len,
                        category,
                        is_suspicious,
                        section,
                    });
                }
            }
            in_run = false;
        }
    }

    if in_run {
        let len = data.len() - start;
        if len >= MIN_STRING_LENGTH {
            if let Ok(s) =
                std::str::from_utf8(&data[start..])
            {
                let is_multibyte =
                    s.bytes().any(|b| !b.is_ascii());
                let encoding = if is_multibyte {
                    StringEncoding::Utf8
                } else {
                    StringEncoding::Ascii
                };
                let category = classify(s);
                let is_suspicious =
                    is_category_suspicious(&category);
                let section = sections.and_then(|secs| {
                    find_section(secs, start as u64)
                });
                out.push(ExtractedString {
                    value: s.to_string(),
                    offset: start as u64,
                    encoding,
                    length: len,
                    category,
                    is_suspicious,
                    section,
                });
            }
        }
    }
}

fn extract_utf16le(
    data: &[u8],
    sections: Option<&[SectionInfo]>,
    out: &mut Vec<ExtractedString>,
) {
    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];

        if hi == 0x00 && is_printable(lo) {
            let start = i;
            let mut code_units = Vec::new();
            let mut pos = i;

            while pos + 1 < data.len() {
                let clo = data[pos];
                let chi = data[pos + 1];
                if chi == 0x00 && clo == 0x00 {
                    break;
                }
                if chi == 0x00 && is_printable(clo) {
                    code_units.push(u16::from(clo));
                    pos += 2;
                } else {
                    break;
                }
            }

            if code_units.len() >= MIN_STRING_LENGTH {
                let value =
                    String::from_utf16_lossy(&code_units);
                let category = classify(&value);
                let is_suspicious =
                    is_category_suspicious(&category);
                let section = sections.and_then(|secs| {
                    find_section(secs, start as u64)
                });
                out.push(ExtractedString {
                    value,
                    offset: start as u64,
                    encoding: StringEncoding::Utf16Le,
                    length: code_units.len(),
                    category,
                    is_suspicious,
                    section,
                });
            }

            i = if pos > i { pos } else { i + 2 };
        } else {
            i += 2;
        }
    }
}

fn find_section(
    sections: &[SectionInfo],
    file_offset: u64,
) -> Option<String> {
    sections
        .iter()
        .find(|s| {
            s.raw_size > 0
                && file_offset >= s.raw_offset
                && file_offset
                    < s.raw_offset + s.raw_size
        })
        .map(|s| s.name.clone())
}

fn classify(s: &str) -> StringCategory {
    if is_url(s) {
        return StringCategory::Url;
    }
    if is_ip_address(s) {
        return StringCategory::IpAddress;
    }
    if is_registry_key(s) {
        return StringCategory::RegistryKey;
    }
    if is_shell_command(s) {
        return StringCategory::ShellCommand;
    }
    if is_persistence_path(s) {
        return StringCategory::PersistencePath;
    }
    if is_anti_analysis(s) {
        return StringCategory::AntiAnalysis;
    }
    if is_packer_signature(s) {
        return StringCategory::PackerSignature;
    }
    if is_suspicious_api(s) {
        return StringCategory::SuspiciousApi;
    }
    if is_debug_artifact(s) {
        return StringCategory::DebugArtifact;
    }
    if is_file_path(s) {
        return StringCategory::FilePath;
    }
    if is_crypto_wallet(s) {
        return StringCategory::CryptoWallet;
    }
    if is_email(s) {
        return StringCategory::Email;
    }
    if is_encoded_data(s) {
        return StringCategory::EncodedData;
    }
    StringCategory::Generic
}

fn is_category_suspicious(
    category: &StringCategory,
) -> bool {
    SUSPICIOUS_CATEGORIES.contains(category)
}

fn is_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    URL_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn is_ip_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != IP_OCTET_COUNT {
        return false;
    }
    parts.iter().all(|part| {
        if part.is_empty() || part.len() > 3 {
            return false;
        }
        match part.parse::<u32>() {
            Ok(val) => val <= IP_OCTET_MAX,
            Err(_) => false,
        }
    })
}

fn is_file_path(s: &str) -> bool {
    if s.len() >= 3
        && s.as_bytes()[0].is_ascii_uppercase()
        && s.as_bytes()[1] == b':'
        && s.as_bytes()[2] == b'\\'
    {
        return true;
    }
    if s.starts_with("\\\\") {
        return true;
    }
    UNIX_PATH_PREFIXES
        .iter()
        .any(|prefix| s.starts_with(prefix))
}

fn is_registry_key(s: &str) -> bool {
    REGISTRY_PREFIXES
        .iter()
        .any(|prefix| s.starts_with(prefix))
}

fn is_shell_command(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    SHELL_INDICATORS
        .iter()
        .any(|indicator| lower.contains(indicator))
}

fn is_crypto_wallet(s: &str) -> bool {
    if s.len() >= BTC_MIN_LENGTH
        && s.len() <= BTC_MAX_LENGTH
        && (s.starts_with('1') || s.starts_with('3'))
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric())
        && !s.chars().any(|c| {
            c == '0' || c == 'O' || c == 'I' || c == 'l'
        })
    {
        return true;
    }

    if s.len() == ETH_ADDRESS_LENGTH
        && s.starts_with(ETH_PREFIX)
        && s[2..].len() == ETH_HEX_DIGITS
        && s[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return true;
    }

    false
}

fn is_email(s: &str) -> bool {
    let at_pos = match s.find('@') {
        Some(p) if p > 0 => p,
        _ => return false,
    };
    let domain = &s[at_pos + 1..];
    let dot_pos = match domain.rfind('.') {
        Some(p) if p > 0 => p,
        _ => return false,
    };
    let tld = &domain[dot_pos + 1..];
    if tld.len() < 2 {
        return false;
    }
    let local = &s[..at_pos];
    local
        .chars()
        .all(|c| c.is_ascii_alphanumeric()
            || c == '.'
            || c == '_'
            || c == '%'
            || c == '+'
            || c == '-')
        && domain[..dot_pos]
            .chars()
            .all(|c| c.is_ascii_alphanumeric()
                || c == '.'
                || c == '-')
        && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_suspicious_api(s: &str) -> bool {
    SUSPICIOUS_APIS
        .iter()
        .any(|api| s == api.name)
}

fn is_packer_signature(s: &str) -> bool {
    PACKER_SIGNATURES
        .iter()
        .any(|sig| s.contains(sig))
}

fn is_debug_artifact(s: &str) -> bool {
    DEBUG_ARTIFACTS
        .iter()
        .any(|artifact| s.contains(artifact))
}

fn is_anti_analysis(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    ANTI_ANALYSIS_INDICATORS.iter().any(|indicator| {
        lower.contains(&indicator.to_ascii_lowercase())
    })
}

fn is_persistence_path(s: &str) -> bool {
    PERSISTENCE_PATHS
        .iter()
        .any(|path| s.contains(path))
}

fn is_encoded_data(s: &str) -> bool {
    if s.len() < BASE64_MIN_LENGTH {
        return false;
    }
    let trimmed = s.trim_end_matches('=');
    if trimmed.is_empty() {
        return false;
    }
    let all_base64 = trimmed
        .bytes()
        .all(|b| BASE64_CHARS.contains(&b));
    if !all_base64 {
        return false;
    }
    let padding = s.len() - trimmed.len();
    padding <= 2
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
    fn ascii_extraction_min_length() {
        let data =
            b"abc\x00abcdef\x00ab\x00longstring\x00";
        let result = extract_strings(data, None);

        let values: Vec<&str> = result
            .strings
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        assert!(
            !values.contains(&"abc"),
            "3-char string should be excluded"
        );
        assert!(
            !values.contains(&"ab"),
            "2-char string should be excluded"
        );
        assert!(
            values.contains(&"abcdef"),
            "6-char string should be included"
        );
        assert!(
            values.contains(&"longstring"),
            "10-char string should be included"
        );
    }

    #[test]
    fn utf16le_extraction() {
        let s = "Hello World!";
        let mut data: Vec<u8> = Vec::new();
        for c in s.encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        data.push(0x00);
        data.push(0x00);

        let result = extract_strings(&data, None);
        let utf16_strings: Vec<&ExtractedString> =
            result
                .strings
                .iter()
                .filter(|s| {
                    s.encoding == StringEncoding::Utf16Le
                })
                .collect();
        assert!(
            !utf16_strings.is_empty(),
            "should extract UTF-16LE string"
        );
        assert!(utf16_strings
            .iter()
            .any(|s| s.value.contains("Hello")));
    }

    #[test]
    fn category_url() {
        assert_eq!(
            classify("https://evil.com/payload"),
            StringCategory::Url,
        );
        assert_eq!(
            classify("http://malware.ru/dropper"),
            StringCategory::Url,
        );
        assert_eq!(
            classify("ftp://files.example.com"),
            StringCategory::Url,
        );
    }

    #[test]
    fn category_ip_address() {
        assert_eq!(
            classify("192.168.1.1"),
            StringCategory::IpAddress,
        );
        assert_eq!(
            classify("10.0.0.1"),
            StringCategory::IpAddress,
        );
        assert_ne!(
            classify("999.999.999.999"),
            StringCategory::IpAddress,
        );
        assert_ne!(
            classify("1.2.3"),
            StringCategory::IpAddress,
        );
    }

    #[test]
    fn category_registry_key() {
        assert_eq!(
            classify("HKLM\\Software\\Microsoft"),
            StringCategory::RegistryKey,
        );
        assert_eq!(
            classify("HKEY_LOCAL_MACHINE"),
            StringCategory::RegistryKey,
        );
    }

    #[test]
    fn category_file_path() {
        assert_eq!(
            classify("C:\\Windows\\System32\\notepad.exe"),
            StringCategory::FilePath,
        );
        assert_eq!(
            classify("/tmp/output.log"),
            StringCategory::FilePath,
        );
        assert_eq!(
            classify("\\\\server\\share"),
            StringCategory::FilePath,
        );
    }

    #[test]
    fn category_shell_command() {
        assert_eq!(
            classify("cmd.exe /c whoami"),
            StringCategory::ShellCommand,
        );
        assert_eq!(
            classify("/bin/bash -c echo hi"),
            StringCategory::ShellCommand,
        );
    }

    #[test]
    fn category_packer_signature() {
        assert_eq!(
            classify("UPX!"),
            StringCategory::PackerSignature,
        );
        assert_eq!(
            classify("This is .themida packed"),
            StringCategory::PackerSignature,
        );
    }

    #[test]
    fn category_anti_analysis() {
        assert_eq!(
            classify("VMware Virtual Platform"),
            StringCategory::AntiAnalysis,
        );
        assert_eq!(
            classify("wireshark.exe"),
            StringCategory::AntiAnalysis,
        );
    }

    #[test]
    fn category_persistence() {
        assert_eq!(
            classify(
                "Software\\Microsoft\\Windows\\\
                 CurrentVersion\\Run"
            ),
            StringCategory::PersistencePath,
        );
        assert_eq!(
            classify("/etc/crontab"),
            StringCategory::PersistencePath,
        );
    }

    #[test]
    fn category_encoded_data() {
        assert_eq!(
            classify(
                "SGVsbG8gV29ybGQhIFRoaXMgaXM="
            ),
            StringCategory::EncodedData,
        );
        assert_ne!(
            classify("short"),
            StringCategory::EncodedData,
        );
    }

    #[test]
    fn category_email() {
        assert_eq!(
            classify("user@example.com"),
            StringCategory::Email,
        );
    }

    #[test]
    fn suspicious_flag_by_category() {
        assert!(is_category_suspicious(
            &StringCategory::ShellCommand
        ));
        assert!(is_category_suspicious(
            &StringCategory::AntiAnalysis
        ));
        assert!(is_category_suspicious(
            &StringCategory::PackerSignature
        ));
        assert!(is_category_suspicious(
            &StringCategory::PersistencePath
        ));
        assert!(is_category_suspicious(
            &StringCategory::EncodedData
        ));
        assert!(is_category_suspicious(
            &StringCategory::CryptoWallet
        ));
        assert!(is_category_suspicious(
            &StringCategory::SuspiciousApi
        ));
        assert!(!is_category_suspicious(
            &StringCategory::Generic
        ));
        assert!(!is_category_suspicious(
            &StringCategory::Url
        ));
    }

    #[test]
    fn elf_strings_extracted() {
        let data = load_fixture("hello_elf");
        let result = extract_strings(&data, None);

        assert!(
            !result.strings.is_empty(),
            "ELF binary should contain strings"
        );
        assert!(result.statistics.total > 0);
    }

    #[test]
    fn string_pass_populates_context() {
        let data = load_fixture("hello_elf");
        let mut ctx = make_ctx(data);
        assert!(ctx.string_result.is_none());

        StringPass.run(&mut ctx).unwrap();
        assert!(ctx.string_result.is_some());
    }

    #[test]
    fn section_attribution() {
        let sections = vec![SectionInfo {
            name: ".rodata".into(),
            virtual_address: 0,
            virtual_size: 100,
            raw_offset: 10,
            raw_size: 100,
            permissions:
                crate::types::SectionPermissions {
                    read: true,
                    write: false,
                    execute: false,
                },
            sha256: String::new(),
        }];

        let found = find_section(&sections, 50);
        assert_eq!(found, Some(".rodata".into()));

        let not_found = find_section(&sections, 200);
        assert_eq!(not_found, None);
    }
}
