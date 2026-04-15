/*
©AngelaMos | 2026
xdg.go

Scans XDG autostart entries for persistence through desktop login

Parses .desktop files in system and user autostart directories for
suspicious Exec= directives that run on graphical session login.

MITRE ATT&CK:
  T1547.013 - Boot or Logon Autostart Execution: XDG Autostart Entries
*/

package scanner

import (
	"path/filepath"
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	xdgScannerName = "xdg"
	mitreXDG       = "T1547.013"
)

func init() {
	Register(&XDGScanner{})
}

type XDGScanner struct{}

func (x *XDGScanner) Name() string {
	return xdgScannerName
}

func (x *XDGScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	sysDir := ResolveRoot(root, "/etc/xdg/autostart")
	findings = append(
		findings,
		x.scanAutostartDir(sysDir)...,
	)

	for _, home := range FindUserDirs(root) {
		userDir := filepath.Join(
			home, ".config", "autostart",
		)
		findings = append(
			findings,
			x.scanAutostartDir(userDir)...,
		)
	}

	return findings
}

func (x *XDGScanner) scanAutostartDir(
	dir string,
) []types.Finding {
	var findings []types.Finding

	for _, path := range ListFiles(dir) {
		if !strings.HasSuffix(path, ".desktop") {
			continue
		}
		findings = append(
			findings,
			x.analyzeDesktop(path)...,
		)
	}

	return findings
}

func (x *XDGScanner) analyzeDesktop(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, "Exec=") {
			continue
		}

		cmd := strings.TrimPrefix(trimmed, "Exec=")
		matched, sev, label := MatchLine(cmd)
		if matched {
			findings = append(findings, types.Finding{
				Scanner:  xdgScannerName,
				Severity: sev,
				Title:    "Suspicious XDG autostart: " + label,
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreXDG,
			})
		} else if TempDirPattern.MatchString(cmd) {
			findings = append(findings, types.Finding{
				Scanner:  xdgScannerName,
				Severity: types.SeverityMedium,
				Title:    "XDG autostart runs from temp directory",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreXDG,
			})
		}
	}

	return findings
}
