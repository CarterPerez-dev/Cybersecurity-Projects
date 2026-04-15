/*
©AngelaMos | 2026
pam.go

Scans PAM configuration for authentication backdoor indicators

Checks /etc/pam.d/ for pam_exec.so entries that run custom scripts
and for references to non-standard PAM modules that may accept any
credential.

MITRE ATT&CK:
  T1556.003 - Modify Authentication Process: Pluggable Authentication Modules
*/

package scanner

import (
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	pamScannerName = "pam"
	mitrePAM       = "T1556.003"
)

func init() {
	Register(&PAMScanner{})
}

type PAMScanner struct{}

func (p *PAMScanner) Name() string {
	return pamScannerName
}

func (p *PAMScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	pamD := ResolveRoot(root, "/etc/pam.d")
	for _, path := range ListFiles(pamD) {
		findings = append(
			findings,
			p.scanPamConfig(path)...,
		)
	}

	return findings
}

func (p *PAMScanner) scanPamConfig(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if IsCommentOrEmpty(trimmed) {
			continue
		}

		if strings.Contains(trimmed, "pam_exec.so") {
			sev := types.SeverityMedium
			if NetworkToolPattern.MatchString(trimmed) ||
				TempDirPattern.MatchString(trimmed) {
				sev = types.SeverityHigh
			}

			findings = append(findings, types.Finding{
				Scanner:  pamScannerName,
				Severity: sev,
				Title:    "pam_exec.so runs external command",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitrePAM,
			})
		}

		if strings.Contains(trimmed, "pam_permit.so") &&
			containsAuthContext(trimmed) {
			findings = append(findings, types.Finding{
				Scanner:  pamScannerName,
				Severity: types.SeverityHigh,
				Title:    "pam_permit.so in auth context (accepts any credential)",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitrePAM,
			})
		}
	}
	return findings
}

func containsAuthContext(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 1 {
		return false
	}
	return fields[0] == "auth"
}
