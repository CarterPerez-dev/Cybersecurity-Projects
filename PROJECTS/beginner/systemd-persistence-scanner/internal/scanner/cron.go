/*
©AngelaMos | 2026
cron.go

Scans all cron locations for persistence indicators

Checks per-user crontabs, system crontab, cron.d drop-ins, periodic
cron directories, and anacron. Parses crontab entries to extract
commands and runs them through the suspicious pattern engine.

MITRE ATT&CK:
  T1053.003 - Scheduled Task/Job: Cron
*/

package scanner

import (
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	cronScannerName = "cron"
	mitreCron       = "T1053.003"
)

var cronDirs = []string{
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
}

var cronSpoolDirs = []string{
	"/var/spool/cron/crontabs",
	"/var/spool/cron",
}

func init() {
	Register(&CronScanner{})
}

type CronScanner struct{}

func (c *CronScanner) Name() string {
	return cronScannerName
}

func (c *CronScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	etcCrontab := ResolveRoot(root, "/etc/crontab")
	findings = append(
		findings,
		c.scanCrontab(etcCrontab)...,
	)

	anacrontab := ResolveRoot(root, "/etc/anacrontab")
	findings = append(
		findings,
		c.scanCrontab(anacrontab)...,
	)

	for _, dir := range cronDirs {
		resolved := ResolveRoot(root, dir)
		for _, path := range ListFiles(resolved) {
			findings = append(
				findings,
				c.scanCrontab(path)...,
			)
			findings = append(
				findings,
				c.checkPermissions(path)...,
			)
		}
	}

	for _, dir := range cronSpoolDirs {
		resolved := ResolveRoot(root, dir)
		for _, path := range ListFiles(resolved) {
			findings = append(
				findings,
				c.scanCrontab(path)...,
			)
		}
	}

	return findings
}

func (c *CronScanner) scanCrontab(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	for _, line := range lines {
		if IsCommentOrEmpty(line) {
			continue
		}

		cmd := extractCronCommand(line)
		if cmd == "" {
			continue
		}

		matched, sev, label := MatchLine(cmd)
		if matched {
			findings = append(findings, types.Finding{
				Scanner:  cronScannerName,
				Severity: sev,
				Title:    "Suspicious cron entry: " + label,
				Path:     path,
				Evidence: strings.TrimSpace(line),
				MITRE:    mitreCron,
			})
		}
	}
	return findings
}

func extractCronCommand(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}

	firstField := strings.Fields(trimmed)[0]
	if strings.Contains(firstField, "=") {
		return ""
	}

	if strings.HasPrefix(trimmed, "@") {
		parts := strings.Fields(trimmed)
		if len(parts) >= 2 {
			return strings.Join(parts[1:], " ")
		}
		return ""
	}

	fields := strings.Fields(trimmed)
	if len(fields) >= 7 {
		return strings.Join(fields[6:], " ")
	}
	if len(fields) >= 6 {
		return strings.Join(fields[5:], " ")
	}
	return trimmed
}

func (c *CronScanner) checkPermissions(
	path string,
) []types.Finding {
	if !IsWorldWritable(path) {
		return nil
	}

	return []types.Finding{{
		Scanner:  cronScannerName,
		Severity: types.SeverityMedium,
		Title:    "World-writable cron file",
		Path:     path,
		Evidence: "Any user can modify this cron entry",
		MITRE:    mitreCron,
	}}
}
