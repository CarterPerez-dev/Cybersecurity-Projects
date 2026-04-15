/*
©AngelaMos | 2026
cron_test.go
*/

package scanner

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestCronScanner_CleanCrontab(t *testing.T) {
	c := &CronScanner{}
	path := filepath.Join(
		testdataDir(), "cron", "clean-crontab",
	)

	findings := c.scanCrontab(path)
	if len(findings) > 0 {
		t.Errorf(
			"clean crontab produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestCronScanner_MaliciousCrontab(t *testing.T) {
	c := &CronScanner{}
	path := filepath.Join(
		testdataDir(), "cron", "malicious-crontab",
	)

	findings := c.scanCrontab(path)
	for _, f := range findings {
		t.Logf(
			"finding: sev=%s title=%s evidence=%s",
			f.Severity, f.Title, f.Evidence,
		)
	}
	if len(findings) < 3 {
		t.Fatalf(
			"malicious crontab: got %d findings, want >= 3",
			len(findings),
		)
	}

	hasCritical := false
	hasHigh := false
	for _, f := range findings {
		if f.Severity == types.SeverityCritical {
			hasCritical = true
		}
		if f.Severity == types.SeverityHigh {
			hasHigh = true
		}
	}

	if !hasCritical {
		t.Error("expected critical finding for reverse shell")
	}
	if !hasHigh {
		t.Error("expected high finding for curl|bash")
	}
}

func TestExtractCronCommand(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "system cron with user field",
			line: "0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf",
			want: "/usr/sbin/logrotate /etc/logrotate.conf",
		},
		{
			name: "at-style entry",
			line: "@reboot root /usr/bin/startup.sh",
			want: "root /usr/bin/startup.sh",
		},
		{
			name: "environment variable",
			line: "SHELL=/bin/bash",
			want: "",
		},
		{
			name: "comment",
			line: "# some comment",
			want: "",
		},
		{
			name: "empty",
			line: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCronCommand(tt.line)
			if got != tt.want {
				t.Errorf(
					"extractCronCommand(%q) = %q, want %q",
					tt.line, got, tt.want,
				)
			}
		})
	}
}
