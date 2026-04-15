/*
©AngelaMos | 2026
kernel.go

Scans kernel module configuration for persistence indicators

Checks /etc/modules-load.d/ and /etc/modprobe.d/ for suspicious
module load directives and install hooks that execute shell commands
when modules are loaded.

MITRE ATT&CK:
  T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions
*/

package scanner

import (
	"strings"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

const (
	kernelScannerName = "kernel"
	mitreKernel       = "T1547.006"
)

func init() {
	Register(&KernelScanner{})
}

type KernelScanner struct{}

func (k *KernelScanner) Name() string {
	return kernelScannerName
}

func (k *KernelScanner) Scan(
	root string,
) []types.Finding {
	var findings []types.Finding

	modulesD := ResolveRoot(root, "/etc/modules-load.d")
	for _, path := range ListFiles(modulesD) {
		findings = append(
			findings,
			k.scanModulesFile(path)...,
		)
	}

	modulesFile := ResolveRoot(root, "/etc/modules")
	findings = append(
		findings,
		k.scanModulesFile(modulesFile)...,
	)

	modprobeD := ResolveRoot(root, "/etc/modprobe.d")
	for _, path := range ListFiles(modprobeD) {
		findings = append(
			findings,
			k.scanModprobeConf(path)...,
		)
	}

	return findings
}

func (k *KernelScanner) scanModulesFile(
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

		findings = append(findings, types.Finding{
			Scanner:  kernelScannerName,
			Severity: types.SeverityInfo,
			Title:    "Kernel module loaded at boot",
			Path:     path,
			Evidence: trimmed,
			MITRE:    mitreKernel,
		})
	}
	return findings
}

func (k *KernelScanner) scanModprobeConf(
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

		if strings.HasPrefix(trimmed, "install ") &&
			containsShellCommand(trimmed) {
			findings = append(findings, types.Finding{
				Scanner:  kernelScannerName,
				Severity: types.SeverityHigh,
				Title:    "Module install hook runs shell command",
				Path:     path,
				Evidence: trimmed,
				MITRE:    mitreKernel,
			})
		}
	}
	return findings
}
