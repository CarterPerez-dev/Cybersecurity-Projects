/*
©AngelaMos | 2026
completion.go

Scans bash completion scripts for persistence via shell sourcing

Bash completion scripts in /etc/bash_completion.d/ and user
~/.bash_completion files are sourced on every interactive shell
startup. They execute in the user's context and are rarely
monitored, making them attractive for credential theft and
C2 callbacks.

MITRE ATT&CK:
  T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification
*/

package scanner

import (
	"path/filepath"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	completionScannerName = "completion"
	mitreCompletion       = "T1546.004"
)

func init() {
	Register(&CompletionScanner{})
}

type CompletionScanner struct{}

func (c *CompletionScanner) Name() string {
	return completionScannerName
}

func (c *CompletionScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	sysDir := ResolveRoot(root, "/etc/bash_completion.d")
	for _, path := range ListFiles(sysDir) {
		findings = append(
			findings,
			ScanFileForPatterns(
				path, completionScannerName, mitreCompletion,
			)...,
		)
	}

	for _, home := range FindUserDirs(root) {
		bc := filepath.Join(home, ".bash_completion")
		findings = append(
			findings,
			ScanFileForPatterns(
				bc, completionScannerName, mitreCompletion,
			)...,
		)
	}

	return findings
}
