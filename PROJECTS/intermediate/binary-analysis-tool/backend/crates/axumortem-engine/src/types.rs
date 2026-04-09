// ©AngelaMos | 2026
// types.rs
//
// Core enum and struct definitions shared across all passes
//
// Defines the type vocabulary used throughout the engine:
// BinaryFormat (Elf/Pe/MachO), Architecture (x86 through
// AArch64 with an Other fallback), Endianness, RiskLevel
// (five tiers from Benign to Critical), Severity (four tiers
// for import threat tagging), StringEncoding (Ascii/Utf8/
// Utf16Le), StringCategory (14 classifications from Url to
// Generic), EntropyClassification (five bands from Plaintext
// to Encrypted), EntropyFlag (five section anomaly markers),
// FlowControlType and CfgEdgeType for disassembly CFG
// representation, and SectionPermissions with an is_rwx()
// helper. All enums derive Serialize/Deserialize for JSON
// output and implement Display where needed for human-
// readable formatting.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Benign,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringCategory {
    Url,
    IpAddress,
    FilePath,
    RegistryKey,
    ShellCommand,
    CryptoWallet,
    Email,
    SuspiciousApi,
    PackerSignature,
    DebugArtifact,
    AntiAnalysis,
    PersistencePath,
    EncodedData,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropyClassification {
    Plaintext,
    NativeCode,
    Compressed,
    Packed,
    Encrypted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropyFlag {
    HighEntropy,
    HighVirtualToRawRatio,
    EmptyRawData,
    Rwx,
    PackerSectionName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowControlType {
    Next,
    Branch,
    ConditionalBranch,
    Call,
    Return,
    Interrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgEdgeType {
    Fallthrough,
    ConditionalTrue,
    ConditionalFalse,
    Unconditional,
    Call,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf => write!(f, "ELF"),
            Self::Pe => write!(f, "PE"),
            Self::MachO => write!(f, "Mach-O"),
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm => write!(f, "ARM"),
            Self::Aarch64 => write!(f, "AArch64"),
            Self::Other(name) => write!(f, "{name}"),
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Benign => write!(f, "BENIGN"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Little => write!(f, "Little-endian"),
            Self::Big => write!(f, "Big-endian"),
        }
    }
}

impl SectionPermissions {
    pub fn is_rwx(&self) -> bool {
        self.read && self.write && self.execute
    }
}
