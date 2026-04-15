/*
©AngelaMos | 2026
kernel_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestKernelScanner_SuspiciousModprobe(t *testing.T) {
	k := &KernelScanner{}
	path := filepath.Join(
		testdataDir(), "kernel", "suspicious.conf",
	)

	findings := k.scanModprobeConf(path)
	if len(findings) == 0 {
		t.Fatal(
			"suspicious modprobe config produced no findings",
		)
	}

	if findings[0].Severity != types.SeverityHigh {
		t.Errorf(
			"severity = %v, want high",
			findings[0].Severity,
		)
	}

	if findings[0].Title != "Module install hook runs shell command" {
		t.Errorf(
			"title = %q, want %q",
			findings[0].Title,
			"Module install hook runs shell command",
		)
	}
}

func TestKernelScanner_CleanModules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.conf")
	writeTestFile(
		t, path,
		"# Clean module config\n"+
			"options snd_hda_intel power_save=1\n"+
			"blacklist nouveau\n",
	)

	k := &KernelScanner{}
	findings := k.scanModprobeConf(path)

	if len(findings) > 0 {
		t.Errorf(
			"clean modprobe produced %d findings, want 0",
			len(findings),
		)
	}
}

func TestKernelScanner_ModulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "modules")
	writeTestFile(
		t, path,
		"# /etc/modules\nlp\nloop\n",
	)

	k := &KernelScanner{}
	findings := k.scanModulesFile(path)

	if len(findings) != 2 {
		t.Fatalf(
			"modules file: got %d findings, want 2",
			len(findings),
		)
	}

	for _, f := range findings {
		if f.Severity != types.SeverityInfo {
			t.Errorf(
				"severity = %v, want info",
				f.Severity,
			)
		}
	}
}

func TestContainsShellCommand(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "bash path",
			line: "install usb-storage /bin/bash -c 'echo test'",
			want: true,
		},
		{
			name: "network tool",
			line: "install fake curl http://evil.com",
			want: true,
		},
		{
			name: "clean modprobe",
			line: "install pcspkr /bin/true",
			want: false,
		},
		{
			name: "python script",
			line: "install mod python3 -c 'import os'",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsShellCommand(tt.line)
			if got != tt.want {
				t.Errorf(
					"containsShellCommand(%q) = %v, want %v",
					tt.line, got, tt.want,
				)
			}
		})
	}
}
