/*
©AngelaMos | 2026
atjob.go

Scans the at job spool for scheduled one-time persistence

Checks /var/spool/at/ and /var/spool/atjobs/ for pending at jobs
that execute commands at a scheduled time. At jobs are frequently
overlooked during incident response.

MITRE ATT&CK:
  T1053.001 - Scheduled Task/Job: At
*/

package scanner

import (
	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	atjobScannerName = "atjob"
	mitreAt          = "T1053.001"
)

var atDirs = []string{
	"/var/spool/at",
	"/var/spool/atjobs",
}

func init() {
	Register(&AtJobScanner{})
}

type AtJobScanner struct{}

func (a *AtJobScanner) Name() string {
	return atjobScannerName
}

func (a *AtJobScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	for _, dir := range atDirs {
		resolved := ResolveRoot(root, dir)
		files := ListFiles(resolved)
		for _, path := range files {
			findings = append(findings, types.Finding{
				Scanner:  atjobScannerName,
				Severity: types.SeverityLow,
				Title:    "Pending at job found",
				Path:     path,
				Evidence: "Scheduled one-time execution",
				MITRE:    mitreAt,
			})

			findings = append(
				findings,
				ScanFileForPatterns(
					path, atjobScannerName, mitreAt,
				)...,
			)
		}
	}

	return findings
}
