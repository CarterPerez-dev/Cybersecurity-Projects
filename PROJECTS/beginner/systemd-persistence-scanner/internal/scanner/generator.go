/*
©AngelaMos | 2026
generator.go

Scans systemd generator directories for persistence executables

Systemd generators run very early in boot, before logging starts,
and produce unit files dynamically. Any executable placed in a
generator directory runs as root with minimal audit trail. Flags
all executables found, with elevated severity for world-writable
files or recent modifications.

MITRE ATT&CK:
  T1543.002 - Create or Modify System Process: Systemd Service
*/

package scanner

import (
	"time"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	generatorScannerName = "generator"
	mitreGenerator       = "T1543.002"
)

var generatorDirs = []string{
	"/etc/systemd/system-generators",
	"/usr/local/lib/systemd/system-generators",
	"/lib/systemd/system-generators",
	"/usr/lib/systemd/system-generators",
	"/run/systemd/system-generators",
	"/etc/systemd/user-generators",
	"/usr/local/lib/systemd/user-generators",
	"/usr/lib/systemd/user-generators",
	"/run/systemd/user-generators",
}

func init() {
	Register(&GeneratorScanner{})
}

type GeneratorScanner struct{}

func (g *GeneratorScanner) Name() string {
	return generatorScannerName
}

func (g *GeneratorScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	for _, dir := range generatorDirs {
		resolved := ResolveRoot(root, dir)
		for _, path := range ListFiles(resolved) {
			findings = append(findings, types.Finding{
				Scanner:  generatorScannerName,
				Severity: types.SeverityMedium,
				Title:    "Systemd generator executable found",
				Path:     path,
				Evidence: "Generators run as root early in boot before logging",
				MITRE:    mitreGenerator,
			})

			findings = append(
				findings,
				ScanFileForPatterns(
					path, generatorScannerName, mitreGenerator,
				)...,
			)

			if IsWorldWritable(path) {
				findings = append(findings, types.Finding{
					Scanner:  generatorScannerName,
					Severity: types.SeverityHigh,
					Title:    "World-writable systemd generator",
					Path:     path,
					Evidence: "Any user can modify this generator",
					MITRE:    mitreGenerator,
				})
			}

			if ModifiedWithin(path, 24*time.Hour) {
				findings = append(findings, types.Finding{
					Scanner:  generatorScannerName,
					Severity: types.SeverityHigh,
					Title:    "Recently modified systemd generator",
					Path:     path,
					Evidence: "Modified within the last 24 hours",
					MITRE:    mitreGenerator,
				})
			}
		}
	}

	return findings
}
