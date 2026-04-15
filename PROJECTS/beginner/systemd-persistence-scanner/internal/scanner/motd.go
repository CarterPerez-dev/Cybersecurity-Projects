/*
©AngelaMos | 2026
motd.go

Scans MOTD scripts for login-triggered persistence

Checks /etc/update-motd.d/ for scripts that execute as root on
every SSH or console login. Attackers plant callbacks here because
the directory is rarely monitored.

MITRE ATT&CK:
  T1546 - Event Triggered Execution
*/

package scanner

import (
	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	motdScannerName = "motd"
	mitreMOTD       = "T1546"
)

func init() {
	Register(&MOTDScanner{})
}

type MOTDScanner struct{}

func (m *MOTDScanner) Name() string {
	return motdScannerName
}

func (m *MOTDScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	motdDir := ResolveRoot(root, "/etc/update-motd.d")
	for _, path := range ListFiles(motdDir) {
		findings = append(
			findings,
			ScanFileForPatterns(
				path, motdScannerName, mitreMOTD,
			)...,
		)

		if IsWorldWritable(path) {
			findings = append(findings, types.Finding{
				Scanner:  motdScannerName,
				Severity: types.SeverityMedium,
				Title:    "World-writable MOTD script",
				Path:     path,
				Evidence: "Any user can modify this login script",
				MITRE:    mitreMOTD,
			})
		}
	}

	return findings
}
