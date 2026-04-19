/*
©AngelaMos | 2026
fingerprint_test.go
*/

package intel

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifySSHClient(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"libssh", "SSH-2.0-libssh-0.9.6", "libssh"},
		{"paramiko", "SSH-2.0-paramiko_3.4.0", "paramiko"},
		{"putty", "SSH-2.0-PuTTY_Release_0.78", "putty"},
		{"dropbear", "SSH-2.0-dropbear_2022.83", "dropbear"},
		{"nmap", "SSH-2.0-Nmap-SSH2-Hostkey", "nmap"},
		{"go-ssh", "SSH-2.0-Go", "go-ssh"},
		{"asyncssh", "SSH-2.0-AsyncSSH_2.13.2", "asyncssh"},
		{"trilead", "SSH-2.0-TRILEAD", "trilead"},
		{"jsch", "SSH-2.0-JSCH-0.2.9", "jsch"},
		{"wolfssh", "SSH-2.0-wolfSSHv1.4.12", "wolfssh"},
		{"russh", "SSH-2.0-russh_0.40.2", "russh"},
		{"twisted", "SSH-2.0-Twisted_Conch", "twisted"},
		{"erlang", "SSH-2.0-Erlang/4.15", "erlang"},
		{"openssh", "SSH-2.0-OpenSSH_9.6", "openssh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifySSHClient(tt.version))
		})
	}
}

func TestSSHExploitToolPriority(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"hydra", "SSH-2.0-libssh_hydra", "hydra"},
		{"medusa", "SSH-2.0-medusa_2.2", "medusa"},
		{"ncrack", "SSH-2.0-ncrack", "ncrack"},
		{"metasploit", "SSH-2.0-metasploit_framework", "metasploit"},
		{"cobalt strike", "SSH-2.0-cobalt", "cobalt-strike"},
		{"brutessh", "SSH-2.0-brutessh", "brutessh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifySSHClient(tt.version))
		})
	}
}

func TestClassifyHTTPClient(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{"nuclei", "Nuclei/v3.1.0", "nuclei"},
		{"sqlmap", "sqlmap/1.7.11", "sqlmap"},
		{"nikto", "Nikto/2.5.0", "nikto"},
		{"gobuster", "gobuster/3.6", "gobuster"},
		{"wpscan", "WPScan v3.8.25", "wpscan"},
		{"burpsuite", "Mozilla/5.0 (BurpSuite)", "burpsuite"},
		{"nmap", "Mozilla/5.0 Nmap Scripting Engine", "nmap"},
		{"ffuf", "Fuzz Faster U Fool v2.1.0 - ffuf", "ffuf"},
		{"shodan", "Shodan.io", "shodan"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClassifyHTTPClient(tt.userAgent))
		})
	}
}

func TestIsKnownAttackTool(t *testing.T) {
	assert.True(t, IsKnownAttackTool("hydra"))
	assert.True(t, IsKnownAttackTool("metasploit"))
	assert.True(t, IsKnownAttackTool("sqlmap"))
	assert.True(t, IsKnownAttackTool("nuclei"))
	assert.False(t, IsKnownAttackTool("openssh"))
	assert.False(t, IsKnownAttackTool(""))
}

func TestClassifyCaseInsensitive(t *testing.T) {
	assert.Equal(t,
		"paramiko",
		ClassifySSHClient("SSH-2.0-PARAMIKO_3.0"),
	)
	assert.Equal(t,
		"nuclei",
		ClassifyHTTPClient("NUCLEI/v3.0"),
	)
}

func TestUnknownClientReturnsEmpty(t *testing.T) {
	assert.Empty(t, ClassifySSHClient("SSH-2.0-UnknownClient"))
	assert.Empty(t, ClassifyHTTPClient("Mozilla/5.0 Chrome/120.0"))
}
