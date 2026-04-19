/*
©AngelaMos | 2026
fingerprint.go

Attacker tool family classification from protocol metadata

Maps SSH client version strings and HTTP user-agents to known
offensive tool families. Identification enables correlation of
attack campaigns and provides actionable intelligence for incident
response teams analyzing honeypot data.
*/

package intel

import "strings"

var sshToolPatterns = []struct {
	pattern string
	family  string
}{
	{"libssh", "libssh"},
	{"paramiko", "paramiko"},
	{"putty", "putty"},
	{"dropbear", "dropbear"},
	{"nmap", "nmap"},
	{"go", "go-ssh"},
	{"asyncssh", "asyncssh"},
	{"trilead", "trilead"},
	{"jsch", "jsch"},
	{"wolfssh", "wolfssh"},
	{"russh", "russh"},
	{"twisted", "twisted"},
	{"erlang", "erlang"},
}

var sshExploitPatterns = []struct {
	pattern string
	family  string
}{
	{"hydra", "hydra"},
	{"medusa", "medusa"},
	{"ncrack", "ncrack"},
	{"metasploit", "metasploit"},
	{"cobalt", "cobalt-strike"},
	{"brutessh", "brutessh"},
}

func ClassifySSHClient(
	clientVersion string,
) string {
	lower := strings.ToLower(clientVersion)

	for _, p := range sshExploitPatterns {
		if strings.Contains(lower, p.pattern) {
			return p.family
		}
	}

	for _, p := range sshToolPatterns {
		if strings.Contains(lower, p.pattern) {
			return p.family
		}
	}

	if strings.Contains(lower, "openssh") {
		return "openssh"
	}

	return ""
}

var httpToolPatterns = []struct {
	pattern string
	family  string
}{
	{"nuclei", "nuclei"},
	{"sqlmap", "sqlmap"},
	{"nmap", "nmap"},
	{"nikto", "nikto"},
	{"gobuster", "gobuster"},
	{"dirbuster", "dirbuster"},
	{"wfuzz", "wfuzz"},
	{"ffuf", "ffuf"},
	{"burp", "burpsuite"},
	{"acunetix", "acunetix"},
	{"nessus", "nessus"},
	{"openvas", "openvas"},
	{"wpscan", "wpscan"},
	{"metasploit", "metasploit"},
	{"hydra", "hydra"},
	{"zgrab", "zgrab"},
	{"masscan", "masscan"},
	{"censys", "censys"},
	{"shodan", "shodan"},
	{"httpx", "httpx"},
	{"feroxbuster", "feroxbuster"},
	{"whatweb", "whatweb"},
}

func ClassifyHTTPClient(
	userAgent string,
) string {
	lower := strings.ToLower(userAgent)
	for _, p := range httpToolPatterns {
		if strings.Contains(lower, p.pattern) {
			return p.family
		}
	}
	return ""
}

func IsKnownAttackTool(family string) bool {
	exploitTools := map[string]bool{
		"hydra":         true,
		"medusa":        true,
		"ncrack":        true,
		"metasploit":    true,
		"cobalt-strike": true,
		"brutessh":      true,
		"sqlmap":        true,
		"burpsuite":     true,
		"nikto":         true,
		"nuclei":        true,
		"wpscan":        true,
		"acunetix":      true,
		"nessus":        true,
		"openvas":       true,
	}
	return exploitTools[family]
}
