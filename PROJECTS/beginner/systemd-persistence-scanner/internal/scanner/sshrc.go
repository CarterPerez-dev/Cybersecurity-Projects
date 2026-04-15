/*
©AngelaMos | 2026
sshrc.go

Scans /etc/ssh/sshrc for system-wide SSH login persistence

The sshrc file executes as the connecting user on every SSH login,
distinct from per-user ~/.ssh/rc files. Attackers plant callbacks
here because it runs before the user's shell and is rarely audited.

MITRE ATT&CK:
  T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification
*/

package scanner

import (
	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	sshrcScannerName = "sshrc"
	mitreSSHRC       = "T1546.004"
)

func init() {
	Register(&SSHRCScanner{})
}

type SSHRCScanner struct{}

func (s *SSHRCScanner) Name() string {
	return sshrcScannerName
}

func (s *SSHRCScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	sshrc := ResolveRoot(root, "/etc/ssh/sshrc")
	if !FileExists(sshrc) {
		return nil
	}

	findings = append(findings, types.Finding{
		Scanner:  sshrcScannerName,
		Severity: types.SeverityMedium,
		Title:    "System-wide sshrc login script exists",
		Path:     sshrc,
		Evidence: "/etc/ssh/sshrc runs on every SSH login",
		MITRE:    mitreSSHRC,
	})

	findings = append(
		findings,
		ScanFileForPatterns(
			sshrc, sshrcScannerName, mitreSSHRC,
		)...,
	)

	if IsWorldWritable(sshrc) {
		findings = append(findings, types.Finding{
			Scanner:  sshrcScannerName,
			Severity: types.SeverityMedium,
			Title:    "World-writable sshrc script",
			Path:     sshrc,
			Evidence: "Any user can modify this login script",
			MITRE:    mitreSSHRC,
		})
	}

	return findings
}
