/*
©AngelaMos | 2026
preload.go

Scans for LD_PRELOAD and dynamic linker hijacking persistence

Checks /etc/ld.so.preload for entries (almost never legitimate),
scans /etc/ld.so.conf.d/ for libraries in suspicious paths, and
looks for LD_PRELOAD exports in /etc/environment.

MITRE ATT&CK:
  T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking
*/

package scanner

import (
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	preloadScannerName = "ld_preload"
	mitrePreload       = "T1574.006"
)

func init() {
	Register(&PreloadScanner{})
}

type PreloadScanner struct{}

func (p *PreloadScanner) Name() string {
	return preloadScannerName
}

func (p *PreloadScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	preload := ResolveRoot(root, "/etc/ld.so.preload")
	findings = append(
		findings,
		p.scanPreloadFile(preload)...,
	)

	confD := ResolveRoot(root, "/etc/ld.so.conf.d")
	for _, path := range ListFiles(confD) {
		findings = append(
			findings,
			p.scanConfFile(path)...,
		)
	}

	envFile := ResolveRoot(root, "/etc/environment")
	findings = append(
		findings,
		p.scanEnvironment(envFile)...,
	)

	return findings
}

func (p *PreloadScanner) scanPreloadFile(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		sev := types.SeverityHigh
		if TempDirPattern.MatchString(trimmed) {
			sev = types.SeverityCritical
		}

		findings = append(findings, types.Finding{
			Scanner:  preloadScannerName,
			Severity: sev,
			Title:    "Library in ld.so.preload",
			Path:     path,
			Evidence: trimmed,
			MITRE:    mitrePreload,
		})
	}
	return findings
}

func (p *PreloadScanner) scanConfFile(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	var findings []types.Finding

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if IsCommentOrEmpty(trimmed) {
			continue
		}

		if TempDirPattern.MatchString(trimmed) {
			findings = append(findings, types.Finding{
				Scanner:  preloadScannerName,
				Severity: types.SeverityHigh,
				Title:    "Library path in temp directory",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitrePreload,
			})
		}
	}
	return findings
}

func (p *PreloadScanner) scanEnvironment(
	path string,
) []types.Finding {
	lines := ReadLines(path)
	if lines == nil {
		return nil
	}

	var findings []types.Finding
	for _, line := range lines {
		if LDPreloadPattern.MatchString(line) {
			findings = append(findings, types.Finding{
				Scanner:  preloadScannerName,
				Severity: types.SeverityCritical,
				Title:    "LD_PRELOAD in /etc/environment",
				Path:     path,
				Evidence: strings.TrimSpace(line),
				MITRE:    mitrePreload,
			})
		}
	}
	return findings
}
