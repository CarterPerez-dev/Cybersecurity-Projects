/*
©AngelaMos | 2026
udev.go

Scans udev rules for persistence through device event triggers

Parses udev rule files for RUN+= directives that execute commands
on hardware events. Flags rules pointing to suspicious paths or
containing shell interpreters and network tools.

MITRE ATT&CK:
  T1546 - Event Triggered Execution
*/

package scanner

import (
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	udevScannerName = "udev"
	mitreUdev       = "T1546"
)

var udevDirs = []string{
	"/etc/udev/rules.d",
	"/lib/udev/rules.d",
	"/usr/lib/udev/rules.d",
	"/run/udev/rules.d",
}

func init() {
	Register(&UdevScanner{})
}

type UdevScanner struct{}

func (u *UdevScanner) Name() string {
	return udevScannerName
}

func (u *UdevScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	for _, dir := range udevDirs {
		resolved := ResolveRoot(root, dir)
		for _, path := range ListFiles(resolved) {
			if !strings.HasSuffix(path, ".rules") {
				continue
			}
			findings = append(
				findings,
				u.scanRuleFile(path)...,
			)
		}
	}

	return findings
}

func (u *UdevScanner) scanRuleFile(
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

		if !strings.Contains(trimmed, "RUN+=") &&
			!strings.Contains(trimmed, "RUN+=\"") {
			continue
		}

		runCmd := extractRunDirective(trimmed)
		if runCmd == "" {
			continue
		}

		matched, sev, label := MatchLine(runCmd)
		if matched {
			findings = append(findings, types.Finding{
				Scanner:  udevScannerName,
				Severity: sev,
				Title:    "Suspicious udev RUN directive: " + label,
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreUdev,
			})
			continue
		}

		if TempDirPattern.MatchString(runCmd) ||
			containsShellCommand(runCmd) {
			findings = append(findings, types.Finding{
				Scanner:  udevScannerName,
				Severity: types.SeverityMedium,
				Title:    "Udev rule executes command",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreUdev,
			})
		}
	}
	return findings
}

func extractRunDirective(line string) string {
	idx := strings.Index(line, "RUN+=")
	if idx == -1 {
		return ""
	}
	rest := line[idx+5:]
	rest = strings.TrimPrefix(rest, "\"")
	if end := strings.Index(rest, "\""); end != -1 {
		return rest[:end]
	}
	return strings.TrimSpace(rest)
}
