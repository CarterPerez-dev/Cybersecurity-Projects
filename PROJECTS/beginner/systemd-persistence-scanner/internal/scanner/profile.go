/*
©AngelaMos | 2026
profile.go

Scans shell initialization files for injected persistence commands

Checks system-wide and per-user shell RC files (bash, zsh, profile)
for suspicious patterns: network callbacks, encoded payloads, alias
hijacking, PATH manipulation, LD_PRELOAD exports, and background
process launchers.

MITRE ATT&CK:
  T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification
*/

package scanner

import (
	"path/filepath"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	profileScannerName = "profile"
	mitreProfile       = "T1546.004"
)

var systemProfiles = []string{
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/zsh/zshrc",
	"/etc/zsh/zprofile",
}

var userProfileFiles = []string{
	".bashrc",
	".bash_profile",
	".bash_login",
	".bash_logout",
	".profile",
	".zshrc",
	".zprofile",
}

func init() {
	Register(&ProfileScanner{})
}

type ProfileScanner struct{}

func (p *ProfileScanner) Name() string {
	return profileScannerName
}

func (p *ProfileScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	for _, path := range systemProfiles {
		resolved := ResolveRoot(root, path)
		findings = append(
			findings,
			ScanFileForPatterns(
				resolved, profileScannerName, mitreProfile,
			)...,
		)
	}

	profileD := ResolveRoot(root, "/etc/profile.d")
	for _, path := range ListFiles(profileD) {
		findings = append(
			findings,
			ScanFileForPatterns(
				path, profileScannerName, mitreProfile,
			)...,
		)
	}

	for _, home := range FindUserDirs(root) {
		for _, name := range userProfileFiles {
			path := filepath.Join(home, name)
			findings = append(
				findings,
				ScanFileForPatterns(
					path, profileScannerName, mitreProfile,
				)...,
			)
		}
	}

	return findings
}
