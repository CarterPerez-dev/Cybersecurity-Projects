/*
©AngelaMos | 2026
logrotate.go

Scans logrotate configuration for persistence via rotate hooks

Parses /etc/logrotate.d/ configs for postrotate, prerotate,
firstaction, and lastaction blocks that execute shell commands
as root during log rotation. Attackers embed callbacks here
because these files are rarely audited.

MITRE ATT&CK:
  T1053.003 - Scheduled Task/Job: Cron
*/

package scanner

import (
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	logrotateScannerName = "logrotate"
	mitreLogrotate       = "T1053.003"
)

var rotateHooks = []string{
	"postrotate",
	"prerotate",
	"firstaction",
	"lastaction",
}

func init() {
	Register(&LogrotateScanner{})
}

type LogrotateScanner struct{}

func (l *LogrotateScanner) Name() string {
	return logrotateScannerName
}

func (l *LogrotateScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	confD := ResolveRoot(root, "/etc/logrotate.d")
	for _, path := range ListFiles(confD) {
		findings = append(
			findings,
			l.scanConfig(path)...,
		)
	}

	mainConf := ResolveRoot(root, "/etc/logrotate.conf")
	findings = append(
		findings,
		l.scanConfig(mainConf)...,
	)

	return findings
}

func (l *LogrotateScanner) scanConfig(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	inBlock := false
	blockName := ""

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "endscript" {
			inBlock = false
			continue
		}

		for _, hook := range rotateHooks {
			if trimmed == hook {
				inBlock = true
				blockName = hook
				break
			}
		}

		if !inBlock {
			continue
		}

		if IsCommentOrEmpty(trimmed) {
			continue
		}

		matched, sev, label := MatchLine(trimmed)
		if matched {
			findings = append(findings, types.Finding{
				Scanner:  logrotateScannerName,
				Severity: sev,
				Title: "Suspicious logrotate " +
					blockName + ": " + label,
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreLogrotate,
			})
			continue
		}

		if containsShellCommand(trimmed) {
			findings = append(findings, types.Finding{
				Scanner:  logrotateScannerName,
				Severity: types.SeverityMedium,
				Title: "Logrotate " + blockName +
					" runs shell command",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreLogrotate,
			})
		}
	}

	return findings
}
