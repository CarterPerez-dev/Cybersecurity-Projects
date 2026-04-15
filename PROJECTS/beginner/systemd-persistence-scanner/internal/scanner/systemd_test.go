/*
©AngelaMos | 2026
systemd_test.go
*/

package scanner

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(
		filepath.Dir(file),
		"..", "..", "testdata",
	)
}

func TestSystemdScanner_CleanService(t *testing.T) {
	s := &SystemdScanner{}
	findings := s.analyzeUnit(
		filepath.Join(
			testdataDir(), "systemd", "clean-service.service",
		),
		mitreSystemd,
	)

	suspicious := filterSuspicious(findings)
	if len(suspicious) > 0 {
		t.Errorf(
			"clean service produced %d suspicious findings, want 0",
			len(suspicious),
		)
		for _, f := range suspicious {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}

func TestSystemdScanner_SuspiciousService(t *testing.T) {
	s := &SystemdScanner{}
	findings := s.analyzeUnit(
		filepath.Join(
			testdataDir(),
			"systemd",
			"suspicious-service.service",
		),
		mitreSystemd,
	)

	suspicious := filterSuspicious(findings)
	if len(suspicious) == 0 {
		t.Fatal("suspicious service produced no findings")
	}

	foundCurl := false
	foundTmp := false
	for _, f := range suspicious {
		if f.Severity >= types.SeverityHigh {
			foundCurl = true
		}
		if f.Severity >= types.SeverityMedium {
			foundTmp = true
		}
	}

	if !foundCurl {
		t.Error("expected high-severity finding for curl|sh")
	}
	if !foundTmp {
		t.Error("expected finding for /tmp path")
	}
}

func TestSystemdScanner_TimerMITRE(t *testing.T) {
	s := &SystemdScanner{}
	path := filepath.Join(
		testdataDir(),
		"systemd",
		"timer-backdoor.timer",
	)
	findings := s.analyzeUnit(path, mitreTimer)

	for _, f := range findings {
		if f.MITRE != mitreTimer {
			t.Errorf(
				"timer finding MITRE = %q, want %q",
				f.MITRE, mitreTimer,
			)
		}
	}
}

func TestSystemdScanner_PathUnit(t *testing.T) {
	s := &SystemdScanner{}
	path := filepath.Join(
		testdataDir(),
		"systemd",
		"watch-beacon.path",
	)
	findings := s.analyzeUnit(path, mitrePath)

	for _, f := range findings {
		if f.MITRE != mitrePath {
			t.Errorf(
				"path unit MITRE = %q, want %q",
				f.MITRE, mitrePath,
			)
		}
	}
}

func filterSuspicious(
	findings []types.Finding,
) []types.Finding {
	var result []types.Finding
	for _, f := range findings {
		if f.Severity >= types.SeverityMedium &&
			f.Title != "Recently modified unit file" {
			result = append(result, f)
		}
	}
	return result
}
