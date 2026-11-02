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

const (
	familyNmap         = "nmap"
	familyHydra        = "hydra"
	familyMedusa       = "medusa"
	familyNcrack       = "ncrack"
	familyMetasploit   = "metasploit"
	familyCobaltStrike = "cobalt-strike"
	familyBruteSSH     = "brutessh"
	familyNuclei       = "nuclei"
	familySQLMap       = "sqlmap"
	familyNikto        = "nikto"
	familyBurpSuite    = "burpsuite"
	familyAcunetix     = "acunetix"
	familyNessus       = "nessus"
	familyOpenVAS      = "openvas"
	familyWPScan       = "wpscan"
)

var sshToolPatterns = []struct {
	pattern string
	family  string
}{
	{"libssh", "libssh"},
	{"paramiko", "paramiko"},
	{"putty", "putty"},
	{"dropbear", "dropbear"},
	{familyNmap, familyNmap},
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
	{familyHydra, familyHydra},
	{familyMedusa, familyMedusa},
	{familyNcrack, familyNcrack},
	{familyMetasploit, familyMetasploit},
	{"cobalt", familyCobaltStrike},
	{familyBruteSSH, familyBruteSSH},
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
	{familyNuclei, familyNuclei},
	{familySQLMap, familySQLMap},
	{familyNmap, familyNmap},
	{familyNikto, familyNikto},
	{"gobuster", "gobuster"},
	{"dirbuster", "dirbuster"},
	{"wfuzz", "wfuzz"},
	{"ffuf", "ffuf"},
	{"burp", familyBurpSuite},
	{familyAcunetix, familyAcunetix},
	{familyNessus, familyNessus},
	{familyOpenVAS, familyOpenVAS},
	{familyWPScan, familyWPScan},
	{familyMetasploit, familyMetasploit},
	{familyHydra, familyHydra},
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
		familyHydra:        true,
		familyMedusa:       true,
		familyNcrack:       true,
		familyMetasploit:   true,
		familyCobaltStrike: true,
		familyBruteSSH:     true,
		familySQLMap:       true,
		familyBurpSuite:    true,
		familyNikto:        true,
		familyNuclei:       true,
		familyWPScan:       true,
		familyAcunetix:     true,
		familyNessus:       true,
		familyOpenVAS:      true,
	}
	return exploitTools[family]
}
