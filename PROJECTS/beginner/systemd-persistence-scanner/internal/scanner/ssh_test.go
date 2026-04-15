/*
©AngelaMos | 2026
ssh_test.go
*/

package scanner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestSSHScanner_CleanKeys(t *testing.T) {
	s := &SSHScanner{}
	path := filepath.Join(
		testdataDir(), "ssh", "clean-authorized-keys",
	)

	findings := s.scanAuthorizedKeys(path)
	if len(findings) > 0 {
		t.Errorf(
			"clean keys produced %d findings, want 0",
			len(findings),
		)
	}
}

func TestSSHScanner_CommandKeys(t *testing.T) {
	s := &SSHScanner{}
	path := filepath.Join(
		testdataDir(), "ssh", "command-authorized-keys",
	)

	findings := s.scanAuthorizedKeys(path)
	if len(findings) < 2 {
		t.Fatalf(
			"command keys: got %d findings, want >= 2",
			len(findings),
		)
	}

	hasCommand := false
	hasEnv := false
	for _, f := range findings {
		if f.Severity == types.SeverityHigh {
			switch {
			case strings.Contains(f.Title, "Forced command"):
				hasCommand = true
			case strings.Contains(
				f.Title, "Environment override",
			):
				hasEnv = true
			}
		}
	}

	if !hasCommand {
		t.Error("expected finding for command= option")
	}
	if !hasEnv {
		t.Error("expected finding for environment= option")
	}
}

func TestSSHScanner_SSHDConfigDangerous(t *testing.T) {
	s := &SSHScanner{}
	path := filepath.Join(
		testdataDir(), "ssh", "sshd_config-dangerous",
	)

	findings := s.scanSSHDConfig(path)
	if len(findings) < 2 {
		t.Fatalf(
			"dangerous sshd_config: got %d findings, want >= 2",
			len(findings),
		)
	}

	hasRootLogin := false
	hasKeysFile := false
	for _, f := range findings {
		switch {
		case strings.Contains(
			f.Title, "PermitRootLogin",
		):
			hasRootLogin = true
		case strings.Contains(
			f.Title, "AuthorizedKeysFile",
		):
			hasKeysFile = true
		}
	}

	if !hasRootLogin {
		t.Error("expected finding for PermitRootLogin yes")
	}
	if !hasKeysFile {
		t.Error(
			"expected finding for non-standard AuthorizedKeysFile",
		)
	}
}

func TestSSHScanner_SSHDConfigClean(t *testing.T) {
	s := &SSHScanner{}
	path := filepath.Join(
		testdataDir(), "ssh", "sshd_config-clean",
	)

	findings := s.scanSSHDConfig(path)
	if len(findings) > 0 {
		t.Errorf(
			"clean sshd_config produced %d findings, want 0",
			len(findings),
		)
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Evidence)
		}
	}
}
