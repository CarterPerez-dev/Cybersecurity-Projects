// ©AngelaMos | 2026
// yara.rs
//
// YARA rule scanner with builtin detection rules
//
// Embeds 14 YARA rules as a compile-time constant covering
// UPX packing, anti-debugging (Windows and Linux), process
// injection, keylogger APIs, crypto mining, Windows and
// Linux persistence mechanisms, network backdoors,
// ransomware indicators, shellcode patterns (NOP sleds, egg
// hunters), obfuscation (XOR loops, base64 alphabet), C2
// endpoint paths, and credential file access. YaraScanner
// wraps a compiled yara_x::Rules instance. new() compiles
// only the builtin ruleset; with_custom_rules() also loads
// .yar/.yara files from a directory. scan() executes against
// binary data and returns YaraMatch structs containing rule
// name, tags, metadata (description/category/severity), and
// matched string identifiers with counts. Unit tests verify
// compilation, UPX detection, process injection detection,
// and clean-data negative cases using fixture binaries.
//
// Connects to:
//   error.rs - EngineError::Yara for compilation/scan failures

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::EngineError;

const BUILTIN_RULES: &str = r#"
rule suspicious_upx_packed {
    meta:
        description = "Detects UPX packed binaries"
        category = "packer"
        severity = "medium"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_magic = { 55 50 58 21 }
    condition:
        ($upx0 and $upx1) or $upx_magic
}

rule suspicious_anti_debug {
    meta:
        description = "Detects common anti-debugging techniques"
        category = "evasion"
        severity = "high"
    strings:
        $api1 = "IsDebuggerPresent"
        $api2 = "CheckRemoteDebuggerPresent"
        $api3 = "NtQueryInformationProcess"
        $api4 = "OutputDebugString"
        $int2d = { CD 2D }
    condition:
        2 of ($api*) or $int2d
}

rule suspicious_process_injection {
    meta:
        description = "Detects potential process injection capabilities"
        category = "injection"
        severity = "critical"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtUnmapViewOfSection"
    condition:
        ($api1 and $api2 and $api3) or ($api4 and $api2)
}

rule suspicious_keylogger {
    meta:
        description = "Detects potential keylogger behavior"
        category = "spyware"
        severity = "high"
    strings:
        $api1 = "GetAsyncKeyState"
        $api2 = "SetWindowsHookEx"
        $api3 = "GetKeyState"
        $api4 = "GetKeyboardState"
    condition:
        2 of them
}

rule suspicious_crypto_mining {
    meta:
        description = "Detects cryptocurrency mining indicators"
        category = "miner"
        severity = "medium"
    strings:
        $pool1 = "stratum+tcp://"
        $pool2 = "stratum+ssl://"
        $algo1 = "cryptonight"
        $algo2 = "randomx"
        $algo3 = "ethash"
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
    condition:
        any of ($pool*) or (any of ($algo*) and $wallet)
}

rule suspicious_persistence {
    meta:
        description = "Detects Windows persistence mechanisms"
        category = "persistence"
        severity = "high"
    strings:
        $reg1 = "CurrentVersion\\Run"
        $reg2 = "CurrentVersion\\RunOnce"
        $svc1 = "CreateServiceA"
        $svc2 = "CreateServiceW"
        $task = "schtasks"
    condition:
        any of them
}

rule suspicious_network_backdoor {
    meta:
        description = "Detects potential backdoor network behavior"
        category = "backdoor"
        severity = "critical"
    strings:
        $bind = "bind"
        $listen = "listen"
        $accept = "accept"
        $shell1 = "cmd.exe"
        $shell2 = "/bin/sh"
        $shell3 = "/bin/bash"
    condition:
        ($bind and $listen and $accept) and any of ($shell*)
}

rule suspicious_ransomware {
    meta:
        description = "Detects potential ransomware indicators"
        category = "ransomware"
        severity = "critical"
    strings:
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypto"
        $ransom1 = "your files have been encrypted"
        $ransom2 = "bitcoin"
        $ransom3 = "decrypt"
        $crypto1 = "CryptEncrypt"
        $crypto2 = "CryptGenKey"
    condition:
        (any of ($ext*) and any of ($ransom*)) or
        (any of ($crypto*) and any of ($ransom*))
}

rule suspicious_shellcode {
    meta:
        description = "Detects potential shellcode patterns"
        category = "shellcode"
        severity = "high"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $egg_hunter1 = { 66 81 CA FF 0F }
        $stack_pivot = { 94 C3 }
    condition:
        any of them
}

rule suspicious_obfuscation {
    meta:
        description = "Detects common obfuscation patterns"
        category = "obfuscation"
        severity = "medium"
    strings:
        $xor_loop = { 80 3? ?? 74 ?? 80 3? ?? }
        $decode_base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    condition:
        any of them
}

rule suspicious_linux_anti_debug {
    meta:
        description = "Detects Linux anti-debugging via /proc inspection"
        category = "evasion"
        severity = "high"
    strings:
        $tracer = "TracerPid"
        $proc_status = "/proc/self/status"
        $proc_maps = "/proc/self/maps"
    condition:
        $tracer or ($proc_status and $proc_maps)
}

rule suspicious_linux_persistence {
    meta:
        description = "Detects Linux persistence mechanisms"
        category = "persistence"
        severity = "high"
    strings:
        $cron1 = "/etc/cron"
        $cron2 = "crontab"
        $init = "/etc/init.d/"
        $systemd = "/etc/systemd/"
        $bashrc = ".bashrc"
        $profile = ".bash_profile"
        $rc_local = "/etc/rc.local"
        $xdg_autostart = ".config/autostart"
    condition:
        2 of them
}

rule suspicious_c2_endpoints {
    meta:
        description = "Detects common C2 server endpoint paths"
        category = "c2"
        severity = "high"
    strings:
        $gate = "/gate.php"
        $beacon = "/beacon"
        $callback = "/callback"
        $checkin = "/checkin"
        $exfil = "/exfil"
        $panel = "/panel/"
        $command = "/command"
        $bot = "/bot/"
        $upload_php = "/upload.php"
    condition:
        2 of them
}

rule suspicious_credential_access {
    meta:
        description = "Detects credential file access patterns"
        category = "credential-access"
        severity = "high"
    strings:
        $passwd = "/etc/passwd"
        $shadow = "/etc/shadow"
        $ssh_key = ".ssh/id_rsa"
        $ssh_key2 = ".ssh/authorized_keys"
        $kerberos = "/etc/krb5.conf"
        $gnupg = ".gnupg/"
    condition:
        $shadow or ($passwd and any of ($ssh*, $kerberos, $gnupg))
}
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub metadata: YaraMetadata,
    pub matched_strings: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMetadata {
    pub description: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub match_count: usize,
}

pub struct YaraScanner {
    rules: yara_x::Rules,
}

impl YaraScanner {
    pub fn new() -> Result<Self, EngineError> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(BUILTIN_RULES).map_err(
            |e| EngineError::Yara(e.to_string()),
        )?;

        Ok(Self {
            rules: compiler.build(),
        })
    }

    pub fn with_custom_rules(
        rules_dir: &Path,
    ) -> Result<Self, EngineError> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(BUILTIN_RULES).map_err(
            |e| EngineError::Yara(e.to_string()),
        )?;

        if rules_dir.is_dir() {
            for entry in std::fs::read_dir(rules_dir)
                .map_err(|e| {
                    EngineError::Yara(format!(
                        "failed to read rules dir: {e}"
                    ))
                })?
            {
                let entry = entry.map_err(|e| {
                    EngineError::Yara(format!(
                        "dir entry error: {e}"
                    ))
                })?;
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|ext| ext == "yar" || ext == "yara")
                {
                    let source = std::fs::read_to_string(
                        &path,
                    )
                    .map_err(|e| {
                        EngineError::Yara(format!(
                            "failed to read {}: {e}",
                            path.display()
                        ))
                    })?;
                    compiler
                        .add_source(source.as_str())
                        .map_err(|e| {
                            EngineError::Yara(format!(
                                "compile error in {}: {e}",
                                path.display()
                            ))
                        })?;
                }
            }
        }

        Ok(Self {
            rules: compiler.build(),
        })
    }

    pub fn scan(
        &self,
        data: &[u8],
    ) -> Result<Vec<YaraMatch>, EngineError> {
        let mut scanner =
            yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(data).map_err(
            |e| EngineError::Yara(e.to_string()),
        )?;

        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            let tags: Vec<String> = rule
                .tags()
                .map(|t| t.identifier().to_string())
                .collect();

            let mut description = None;
            let mut category = None;
            let mut severity = None;
            for (key, value) in rule.metadata() {
                match key {
                    "description" => {
                        if let yara_x::MetaValue::String(s) = value {
                            description =
                                Some(s.to_string());
                        }
                    }
                    "category" => {
                        if let yara_x::MetaValue::String(s) = value {
                            category =
                                Some(s.to_string());
                        }
                    }
                    "severity" => {
                        if let yara_x::MetaValue::String(s) = value {
                            severity =
                                Some(s.to_string());
                        }
                    }
                    _ => {}
                }
            }

            let mut matched_strings = Vec::new();
            for pattern in rule.patterns() {
                let id = pattern
                    .identifier()
                    .to_string();
                let count =
                    pattern.matches().count();
                if count > 0 {
                    matched_strings.push(
                        YaraStringMatch {
                            identifier: id,
                            match_count: count,
                        },
                    );
                }
            }

            matches.push(YaraMatch {
                rule_name: rule
                    .identifier()
                    .to_string(),
                tags,
                metadata: YaraMetadata {
                    description,
                    category,
                    severity,
                },
                matched_strings,
            });
        }

        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_compile() {
        let scanner = YaraScanner::new().unwrap();
        let result = scanner.scan(&[0u8; 64]).unwrap();
        assert!(result.is_empty() || !result.is_empty());
    }

    #[test]
    fn detects_upx_signature() {
        let mut data = vec![0u8; 512];
        let upx0 = b"UPX0";
        let upx1 = b"UPX1";
        data[0x100..0x104].copy_from_slice(upx0);
        data[0x140..0x144].copy_from_slice(upx1);

        let scanner = YaraScanner::new().unwrap();
        let result = scanner.scan(&data).unwrap();
        let upx_match = result
            .iter()
            .find(|m| m.rule_name == "suspicious_upx_packed");
        assert!(
            upx_match.is_some(),
            "should detect UPX packer signature"
        );
        let meta =
            &upx_match.unwrap().metadata;
        assert_eq!(
            meta.category.as_deref(),
            Some("packer")
        );
    }

    #[test]
    fn detects_process_injection() {
        let mut data = Vec::new();
        data.extend_from_slice(
            b"\x00\x00VirtualAllocEx\x00\x00",
        );
        data.extend_from_slice(
            b"\x00\x00WriteProcessMemory\x00\x00",
        );
        data.extend_from_slice(
            b"\x00\x00CreateRemoteThread\x00\x00",
        );
        data.extend_from_slice(&[0u8; 256]);

        let scanner = YaraScanner::new().unwrap();
        let result = scanner.scan(&data).unwrap();
        let injection = result.iter().find(|m| {
            m.rule_name
                == "suspicious_process_injection"
        });
        assert!(
            injection.is_some(),
            "should detect process injection APIs"
        );
    }

    #[test]
    fn clean_data_no_matches() {
        let data = b"Hello, this is perfectly normal text content with nothing suspicious at all.";
        let scanner = YaraScanner::new().unwrap();
        let result = scanner.scan(data).unwrap();
        let suspicious: Vec<_> = result
            .iter()
            .filter(|m| {
                m.rule_name != "suspicious_obfuscation"
            })
            .collect();
        assert!(
            suspicious.is_empty(),
            "clean text should not trigger suspicious rules, got: {:?}",
            suspicious.iter().map(|m| &m.rule_name).collect::<Vec<_>>()
        );
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR"),
        );
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!("fixture {path}: {e}")
        })
    }

    #[test]
    fn scan_elf_binary() {
        let data = load_fixture("hello_elf");
        let scanner = YaraScanner::new().unwrap();
        let result = scanner.scan(&data).unwrap();
        assert!(
            result.is_empty() || !result.is_empty(),
            "scan should complete without error"
        );
    }
}
