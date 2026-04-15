/*
©AngelaMos | 2026
udev_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestUdevScanner_BackdoorRule(t *testing.T) {
	u := &UdevScanner{}
	path := filepath.Join(
		testdataDir(), "udev", "backdoor.rules",
	)

	findings := u.scanRuleFile(path)
	if len(findings) == 0 {
		t.Fatal("backdoor udev rule produced no findings")
	}

	hasHighOrAbove := false
	for _, f := range findings {
		if f.Severity >= types.SeverityHigh {
			hasHighOrAbove = true
		}
	}

	if !hasHighOrAbove {
		t.Error("expected high+ severity for curl|sh in RUN+=")
	}
}

func TestExtractRunDirective(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "quoted directive",
			line: `ACTION=="add", RUN+="/bin/bash -c 'echo test'"`,
			want: "/bin/bash -c 'echo test'",
		},
		{
			name: "no run directive",
			line: `ACTION=="add", SUBSYSTEM=="usb"`,
			want: "",
		},
		{
			name: "unquoted directive",
			line: `RUN+=/usr/bin/payload`,
			want: "/usr/bin/payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRunDirective(tt.line)
			if got != tt.want {
				t.Errorf(
					"extractRunDirective(%q) = %q, want %q",
					tt.line, got, tt.want,
				)
			}
		})
	}
}
