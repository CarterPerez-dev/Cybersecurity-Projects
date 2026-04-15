/*
©AngelaMos | 2026
netifhook.go

Scans network interface hook directories for persistence scripts

Checks NetworkManager dispatcher scripts and if-up.d hooks that
trigger on network state changes. Attackers use these to establish
C2 callbacks whenever a network interface activates.

MITRE ATT&CK:
  T1546 - Event Triggered Execution
*/

package scanner

import (
	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	netifhookScannerName = "netifhook"
	mitreNetifhook       = "T1546"
)

var netHookDirs = []string{
	"/etc/NetworkManager/dispatcher.d",
	"/etc/NetworkManager/dispatcher.d/pre-up.d",
	"/etc/NetworkManager/dispatcher.d/pre-down.d",
	"/etc/network/if-up.d",
	"/etc/network/if-down.d",
	"/etc/network/if-pre-up.d",
	"/etc/network/if-post-down.d",
}

func init() {
	Register(&NetIfHookScanner{})
}

type NetIfHookScanner struct{}

func (n *NetIfHookScanner) Name() string {
	return netifhookScannerName
}

func (n *NetIfHookScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	for _, dir := range netHookDirs {
		resolved := ResolveRoot(root, dir)
		for _, path := range ListFiles(resolved) {
			findings = append(
				findings,
				ScanFileForPatterns(
					path,
					netifhookScannerName,
					mitreNetifhook,
				)...,
			)

			if IsWorldWritable(path) {
				findings = append(findings, types.Finding{
					Scanner:  netifhookScannerName,
					Severity: types.SeverityMedium,
					Title:    "World-writable network hook script",
					Path:     path,
					Evidence: "Any user can modify this network hook",
					MITRE:    mitreNetifhook,
				})
			}
		}
	}

	return findings
}
