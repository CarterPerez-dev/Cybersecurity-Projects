/*
©AngelaMos | 2026
blocklist.go

Blocklist export in multiple firewall and proxy formats

Generates IP blocklists from honeypot IOC data in plain text,
iptables rules, nginx deny directives, and CSV formats. Each
format is directly consumable by the target system without
additional processing.
*/

package intel

import (
	"fmt"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	FormatPlain    = "plain"
	FormatIPTables = "iptables"
	FormatNginx    = "nginx"
	FormatCSV      = "csv"
)

func GenerateBlocklist(
	iocs []*types.IOC, format string,
) string {
	ips := FilterIPs(iocs)
	if len(ips) == 0 {
		return ""
	}

	switch format {
	case FormatIPTables:
		return generateIPTables(ips)
	case FormatNginx:
		return generateNginx(ips)
	case FormatCSV:
		return generateCSV(ips)
	default:
		return generatePlain(ips)
	}
}

func generatePlain(iocs []*types.IOC) string {
	var b strings.Builder
	b.WriteString(
		"# Hive Honeypot Blocklist\n",
	)
	b.WriteString(fmt.Sprintf(
		"# Generated: %s\n",
		time.Now().UTC().Format(time.RFC3339),
	))
	b.WriteString(fmt.Sprintf(
		"# Entries: %d\n#\n",
		len(iocs),
	))

	for _, ioc := range iocs {
		b.WriteString(ioc.Value)
		b.WriteByte('\n')
	}

	return b.String()
}

func generateIPTables(
	iocs []*types.IOC,
) string {
	var b strings.Builder
	b.WriteString(
		"# Hive Honeypot — iptables blocklist\n",
	)
	b.WriteString(fmt.Sprintf(
		"# Generated: %s\n",
		time.Now().UTC().Format(time.RFC3339),
	))
	b.WriteString(fmt.Sprintf(
		"# Entries: %d\n\n",
		len(iocs),
	))

	for _, ioc := range iocs {
		b.WriteString(fmt.Sprintf(
			"iptables -A INPUT -s %s -j DROP\n",
			ioc.Value,
		))
	}

	return b.String()
}

func generateNginx(iocs []*types.IOC) string {
	var b strings.Builder
	b.WriteString(
		"# Hive Honeypot — nginx blocklist\n",
	)
	b.WriteString(fmt.Sprintf(
		"# Generated: %s\n",
		time.Now().UTC().Format(time.RFC3339),
	))
	b.WriteString(fmt.Sprintf(
		"# Entries: %d\n",
		len(iocs),
	))
	b.WriteString(
		"# Include in server block: " +
			"include /etc/nginx/blocklist.conf;\n\n",
	)

	for _, ioc := range iocs {
		b.WriteString(fmt.Sprintf(
			"deny %s;\n", ioc.Value,
		))
	}

	return b.String()
}

func generateCSV(iocs []*types.IOC) string {
	var b strings.Builder
	b.WriteString(
		"ip,type,first_seen,last_seen," +
			"sight_count,confidence,source,tags\n",
	)

	for _, ioc := range iocs {
		b.WriteString(fmt.Sprintf(
			"%s,%s,%s,%s,%d,%d,%s,\"%s\"\n",
			ioc.Value,
			ioc.Type.String(),
			ioc.FirstSeen.UTC().Format(time.RFC3339),
			ioc.LastSeen.UTC().Format(time.RFC3339),
			ioc.SightCount,
			ioc.Confidence,
			ioc.Source,
			strings.Join(ioc.Tags, ";"),
		))
	}

	return b.String()
}

func SupportedFormats() []string {
	return []string{
		FormatPlain,
		FormatIPTables,
		FormatNginx,
		FormatCSV,
	}
}
