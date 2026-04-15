/*
©AngelaMos | 2026
ssh.go

Scans SSH configuration and authorized keys for persistence indicators

Checks authorized_keys files for forced command options, sshd_config
for dangerous directives like PermitRootLogin and non-standard
AuthorizedKeysFile paths, and detects ~/.ssh/rc login scripts.

MITRE ATT&CK:
  T1098.004 - Account Manipulation: SSH Authorized Keys
*/

package scanner

import (
	"path/filepath"
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	sshScannerName = "ssh"
	mitreSSH       = "T1098.004"
)

func init() {
	Register(&SSHScanner{})
}

type SSHScanner struct{}

func (s *SSHScanner) Name() string {
	return sshScannerName
}

func (s *SSHScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	for _, home := range FindUserDirs(root) {
		findings = append(
			findings,
			s.scanAuthorizedKeys(
				filepath.Join(
					home, ".ssh", "authorized_keys",
				),
			)...,
		)
		findings = append(
			findings,
			s.scanAuthorizedKeys(
				filepath.Join(
					home, ".ssh", "authorized_keys2",
				),
			)...,
		)

		rc := filepath.Join(home, ".ssh", "rc")
		if FileExists(rc) {
			findings = append(findings, types.Finding{
				Scanner:  sshScannerName,
				Severity: types.SeverityMedium,
				Title:    "SSH rc script detected",
				Path:     rc,
				Evidence: "~/.ssh/rc executes on every SSH login",
				MITRE:    mitreSSH,
			})
			findings = append(
				findings,
				ScanFileForPatterns(
					rc, sshScannerName, mitreSSH,
				)...,
			)
		}
	}

	sshdConfig := ResolveRoot(root, "/etc/ssh/sshd_config")
	findings = append(
		findings,
		s.scanSSHDConfig(sshdConfig)...,
	)

	sshdConfigD := ResolveRoot(
		root, "/etc/ssh/sshd_config.d",
	)
	for _, path := range ListFiles(sshdConfigD) {
		findings = append(
			findings,
			s.scanSSHDConfig(path)...,
		)
	}

	return findings
}

func (s *SSHScanner) scanAuthorizedKeys(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.Contains(trimmed, "command=") {
			findings = append(findings, types.Finding{
				Scanner:  sshScannerName,
				Severity: types.SeverityHigh,
				Title:    "Forced command in authorized_keys",
				Path:     path,
				Evidence: truncate(trimmed),
				MITRE:    mitreSSH,
			})
		}

		if strings.Contains(trimmed, "environment=") {
			findings = append(findings, types.Finding{
				Scanner:  sshScannerName,
				Severity: types.SeverityHigh,
				Title:    "Environment override in authorized_keys",
				Path:     path,
				Evidence: truncate(trimmed),
				MITRE:    mitreSSH,
			})
		}
	}
	return findings
}

func (s *SSHScanner) scanSSHDConfig(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.HasPrefix(lower, "permitrootlogin") &&
			strings.Contains(lower, "yes") {
			findings = append(findings, types.Finding{
				Scanner:  sshScannerName,
				Severity: types.SeverityMedium,
				Title:    "PermitRootLogin enabled",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreSSH,
			})
		}

		if strings.HasPrefix(lower, "authorizedkeysfile") {
			val := strings.Fields(trimmed)
			if len(val) >= 2 {
				keyPath := val[1]
				if !strings.Contains(
					keyPath, ".ssh/authorized_keys",
				) {
					findings = append(
						findings, types.Finding{
							Scanner:  sshScannerName,
							Severity: types.SeverityHigh,
							Title:    "Non-standard AuthorizedKeysFile path",
							Path:     path,
							Evidence: trimmed,
							MITRE:    mitreSSH,
						},
					)
				}
			}
		}
	}
	return findings
}

const maxKeyLineLen = 120

func truncate(s string) string {
	if len(s) <= maxKeyLineLen {
		return s
	}
	return s[:maxKeyLineLen] + "..."
}
