/*
©AngelaMos | 2026
systemd.go

Scans systemd unit files for persistence indicators

Enumerates service and timer units across system and user directories,
parses Exec directives, and flags units that show signs of attacker
installation: suspicious commands, non-standard paths, world-writable
files, and recent modification timestamps.

MITRE ATT&CK:
  T1543.002 - Create or Modify System Process: Systemd Service
  T1053.006 - Scheduled Task/Job: Systemd Timers
*/

package scanner

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	systemdScannerName = "systemd"
	mitreSystemd       = "T1543.002"
	mitreTimer         = "T1053.006"
	mitrePath          = "T1543.002"
)

var systemdDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
}

var execDirectives = []string{
	"ExecStart=",
	"ExecStartPre=",
	"ExecStartPost=",
	"ExecStop=",
	"ExecStopPost=",
	"ExecReload=",
}

func init() {
	Register(&SystemdScanner{})
}

type SystemdScanner struct{}

func (s *SystemdScanner) Name() string {
	return systemdScannerName
}

func (s *SystemdScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	for _, dir := range systemdDirs {
		resolved := ResolveRoot(root, dir)
		findings = append(
			findings,
			s.scanDir(resolved)...,
		)
	}

	for _, home := range FindUserDirs(root) {
		userDir := filepath.Join(
			home, ".config", "systemd", "user",
		)
		findings = append(
			findings,
			s.scanDir(userDir)...,
		)
	}

	return findings
}

func (s *SystemdScanner) scanDir(
	dir string,
) []types.Finding {
	var findings []types.Finding

	files := ListFiles(dir)
	for _, path := range files {
		ext := filepath.Ext(path)
		if ext != ".service" && ext != ".timer" &&
			ext != ".socket" && ext != ".path" {
			continue
		}

		mitre := mitreSystemd
		switch ext {
		case ".timer":
			mitre = mitreTimer
		case ".path":
			mitre = mitrePath
		}

		findings = append(
			findings,
			s.analyzeUnit(path, mitre)...,
		)
	}

	entries := ListDir(dir)
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".d") {
			dropinDir := filepath.Join(dir, e.Name())
			for _, f := range ListFiles(dropinDir) {
				if strings.HasSuffix(f, ".conf") {
					findings = append(
						findings,
						s.analyzeUnit(f, mitreSystemd)...,
					)
				}
			}
		}
	}

	return findings
}

func (s *SystemdScanner) analyzeUnit(
	path, mitre string,
) []types.Finding {
	var findings []types.Finding
	lines := ReadLines(path)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		for _, directive := range execDirectives {
			if !strings.HasPrefix(trimmed, directive) {
				continue
			}
			cmd := strings.TrimPrefix(trimmed, directive)
			cmd = strings.TrimPrefix(cmd, "-")

			matched, sev, label := MatchLine(cmd)
			if matched {
				findings = append(findings, types.Finding{
					Scanner:  systemdScannerName,
					Severity: sev,
					Title: "Suspicious " +
						strings.TrimSuffix(
							directive, "=",
						) + ": " + label,
					Path:     path,
					Evidence: trimmed,
					MITRE:    mitre,
				})
			}
		}
	}

	if IsWorldWritable(path) {
		findings = append(findings, types.Finding{
			Scanner:  systemdScannerName,
			Severity: types.SeverityMedium,
			Title:    "World-writable unit file",
			Path:     path,
			Evidence: "File permissions allow any user to modify this unit",
			MITRE:    mitre,
		})
	}

	if ModifiedWithin(path, 24*time.Hour) {
		findings = append(findings, types.Finding{
			Scanner:  systemdScannerName,
			Severity: types.SeverityMedium,
			Title:    "Recently modified unit file",
			Path:     path,
			Evidence: "Modified within the last 24 hours",
			MITRE:    mitre,
		})
	}

	return findings
}
