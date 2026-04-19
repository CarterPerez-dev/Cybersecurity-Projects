/*
©AngelaMos | 2026
scanner.go

HTTP scanner detection by user-agent fingerprinting

Matches incoming User-Agent headers against known automated scanning
tools. Returns the tool family name for tagging events when a scanner
is identified, enabling correlation of probe activity.
*/

package httpd

import "strings"

var scannerPatterns = map[string]string{
	"nuclei":          "nuclei",
	"sqlmap":          "sqlmap",
	"nmap":            "nmap",
	"zgrab":           "zgrab",
	"masscan":         "masscan",
	"nikto":           "nikto",
	"gobuster":        "gobuster",
	"dirbuster":       "dirbuster",
	"wfuzz":           "wfuzz",
	"ffuf":            "ffuf",
	"burp":            "burpsuite",
	"acunetix":        "acunetix",
	"openvas":         "openvas",
	"nessus":          "nessus",
	"w3af":            "w3af",
	"arachni":         "arachni",
	"whatweb":         "whatweb",
	"wpscan":          "wpscan",
	"joomscan":        "joomscan",
	"metasploit":      "metasploit",
	"hydra":           "hydra",
	"scrapy":          "scrapy",
	"python-requests": "python-requests",
	"go-http-client":  "go-http-client",
	"libwww-perl":     "libwww-perl",
	"censys":          "censys",
	"shodan":          "shodan",
	"netcraft":        "netcraft",
	"curl/":           "curl",
	"wget/":           "wget",
	"httpx":           "httpx",
	"feroxbuster":     "feroxbuster",
	"dnsrecon":        "dnsrecon",
	"testssl":         "testssl",
	"sslscan":         "sslscan",
}

func DetectScanner(userAgent string) string {
	lower := strings.ToLower(userAgent)
	for pattern, name := range scannerPatterns {
		if strings.Contains(lower, pattern) {
			return name
		}
	}
	return ""
}
