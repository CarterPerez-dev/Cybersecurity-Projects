/*
©AngelaMos | 2026
pam_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestPAMScanner_BackdoorConfig(t *testing.T) {
	p := &PAMScanner{}
	path := filepath.Join(
		testdataDir(), "pam", "backdoor-pam",
	)

	findings := p.scanPamConfig(path)
	if len(findings) == 0 {
		t.Fatal("backdoor pam config produced no findings")
	}

	hasPermit := false
	for _, f := range findings {
		if f.Severity == types.SeverityHigh &&
			f.Title == "pam_permit.so in auth context "+
				"(accepts any credential)" {
			hasPermit = true
		}
	}

	if !hasPermit {
		t.Error(
			"expected high severity for pam_permit.so in auth",
		)
	}
}

func TestPAMScanner_CleanConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean-pam")
	writeTestFile(
		t, path,
		"auth required pam_unix.so\n"+
			"account required pam_unix.so\n",
	)

	p := &PAMScanner{}
	findings := p.scanPamConfig(path)

	if len(findings) > 0 {
		t.Errorf(
			"clean pam config produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestPAMScanner_PamExec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pam-exec")
	writeTestFile(
		t, path,
		"auth optional pam_exec.so /tmp/.hidden/hook\n",
	)

	p := &PAMScanner{}
	findings := p.scanPamConfig(path)

	if len(findings) == 0 {
		t.Fatal("pam_exec.so with tmp path produced no findings")
	}

	if findings[0].Severity != types.SeverityHigh {
		t.Errorf(
			"severity = %v, want high",
			findings[0].Severity,
		)
	}
}

func TestContainsAuthContext(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "auth line",
			line: "auth required pam_unix.so",
			want: true,
		},
		{
			name: "account line",
			line: "account required pam_unix.so",
			want: false,
		},
		{
			name: "session line",
			line: "session optional pam_motd.so",
			want: false,
		},
		{
			name: "empty",
			line: "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsAuthContext(tt.line)
			if got != tt.want {
				t.Errorf(
					"containsAuthContext(%q) = %v, want %v",
					tt.line, got, tt.want,
				)
			}
		})
	}
}
