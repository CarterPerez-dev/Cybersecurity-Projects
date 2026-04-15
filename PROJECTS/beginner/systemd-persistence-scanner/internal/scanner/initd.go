/*
©AngelaMos | 2026
initd.go

Scans SysV init scripts and rc.local for persistence indicators

Checks /etc/init.d/ for non-standard scripts and /etc/rc.local for
any executable content beyond comments. Legacy persistence mechanism
that still works on many modern Linux distributions.

MITRE ATT&CK:
  T1037.004 - Boot or Logon Initialization Scripts: RC Scripts
*/

package scanner

import (
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	initdScannerName = "initd"
	mitreInitd       = "T1037.004"
)

func init() {
	Register(&InitdScanner{})
}

type InitdScanner struct{}

func (i *InitdScanner) Name() string {
	return initdScannerName
}

func (i *InitdScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	initDir := ResolveRoot(root, "/etc/init.d")
	for _, path := range ListFiles(initDir) {
		findings = append(
			findings,
			ScanFileForPatterns(
				path, initdScannerName, mitreInitd,
			)...,
		)

		if IsWorldWritable(path) {
			findings = append(findings, types.Finding{
				Scanner:  initdScannerName,
				Severity: types.SeverityMedium,
				Title:    "World-writable init.d script",
				Path:     path,
				Evidence: "Any user can modify this init script",
				MITRE:    mitreInitd,
			})
		}
	}

	rcLocal := ResolveRoot(root, "/etc/rc.local")
	findings = append(
		findings,
		i.scanRcLocal(rcLocal)...,
	)

	return findings
}

func (i *InitdScanner) scanRcLocal(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	hasContent := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "#") ||
			trimmed == "exit 0" {
			continue
		}
		hasContent = true
		break
	}

	if !hasContent {
		return nil
	}

	findings := []types.Finding{{
		Scanner:  initdScannerName,
		Severity: types.SeverityMedium,
		Title:    "rc.local contains executable content",
		Path:     path,
		Evidence: "rc.local runs as root at boot",
		MITRE:    mitreInitd,
	}}

	findings = append(
		findings,
		ScanFileForPatterns(
			path, initdScannerName, mitreInitd,
		)...,
	)

	return findings
}
