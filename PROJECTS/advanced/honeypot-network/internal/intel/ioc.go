/*
©AngelaMos | 2026
ioc.go

Indicator of Compromise extraction from honeypot events

Parses event service data to extract actionable IOCs: IP addresses,
URLs from download commands, domains from HTTP requests, and
credential pairs. Each IOC is tagged with its source context and
assigned a confidence score based on the extraction method.
*/

package intel

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

var urlPattern = regexp.MustCompile(
	`https?://[^\s'"` + "`" + `<>]+`,
)

var domainPattern = regexp.MustCompile(
	`https?://([^/:]+)`,
)

type Extractor struct{}

func NewExtractor() *Extractor {
	return &Extractor{}
}

func (e *Extractor) Extract(
	ev *types.Event,
) []*types.IOC {
	var iocs []*types.IOC

	iocs = append(iocs, e.extractSourceIP(ev)...)
	iocs = append(iocs, e.extractFromData(ev)...)

	return iocs
}

func (e *Extractor) extractSourceIP(
	ev *types.Event,
) []*types.IOC {
	if ev.SourceIP == "" {
		return nil
	}

	ip := net.ParseIP(ev.SourceIP)
	if ip == nil {
		return nil
	}

	if ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}

	iocType := types.IOCIPv4
	if ip.To4() == nil {
		iocType = types.IOCIPv6
	}

	return []*types.IOC{{
		Type:       iocType,
		Value:      ev.SourceIP,
		FirstSeen:  ev.Timestamp,
		LastSeen:   ev.Timestamp,
		SightCount: 1,
		Confidence: confidenceForEvent(ev),
		Source:     "honeypot:" + ev.ServiceType.String(),
		Tags:       eventTags(ev),
	}}
}

func (e *Extractor) extractFromData(
	ev *types.Event,
) []*types.IOC {
	if len(ev.ServiceData) == 0 {
		return nil
	}

	var parsed map[string]interface{}
	if json.Unmarshal(ev.ServiceData, &parsed) != nil {
		return nil
	}

	var iocs []*types.IOC

	iocs = append(iocs, extractURLs(parsed, ev)...)
	iocs = append(
		iocs, extractUserAgents(parsed, ev)...,
	)

	return iocs
}

func extractURLs(
	data map[string]interface{},
	ev *types.Event,
) []*types.IOC {
	var iocs []*types.IOC

	for _, key := range []string{
		"command", "raw", "query", "body", "path",
	} {
		val, ok := data[key].(string)
		if !ok {
			continue
		}

		urls := urlPattern.FindAllString(val, -1)
		for _, u := range urls {
			iocs = append(iocs, &types.IOC{
				Type:       types.IOCURL,
				Value:      u,
				FirstSeen:  ev.Timestamp,
				LastSeen:   ev.Timestamp,
				SightCount: 1,
				Confidence: 80,
				Source:     "honeypot:" + ev.ServiceType.String(),
				Tags:       []string{"extracted-url"},
			})

			matches := domainPattern.FindStringSubmatch(u)
			if len(matches) > 1 {
				domain := matches[1]
				if net.ParseIP(domain) == nil {
					iocs = append(iocs, &types.IOC{
						Type:       types.IOCDomain,
						Value:      domain,
						FirstSeen:  ev.Timestamp,
						LastSeen:   ev.Timestamp,
						SightCount: 1,
						Confidence: 70,
						Source:     "honeypot:" + ev.ServiceType.String(),
						Tags:       []string{"extracted-domain"},
					})
				}
			}
		}
	}

	return iocs
}

func extractUserAgents(
	data map[string]interface{},
	ev *types.Event,
) []*types.IOC {
	ua, ok := data["user_agent"].(string)
	if !ok || ua == "" {
		return nil
	}

	family := ClassifyHTTPClient(ua)
	if family == "" || !IsKnownAttackTool(family) {
		return nil
	}

	return []*types.IOC{{
		Type:       types.IOCUserAgent,
		Value:      ua,
		FirstSeen:  ev.Timestamp,
		LastSeen:   ev.Timestamp,
		SightCount: 1,
		Confidence: 90,
		Source:     "honeypot:" + ev.ServiceType.String(),
		Tags:       []string{"attack-tool", "tool:" + family},
	}}
}

func confidenceForEvent(ev *types.Event) int {
	switch ev.EventType {
	case types.EventExploit:
		return 95
	case types.EventCommand:
		return 85
	case types.EventLoginSuccess, types.EventLoginFailed:
		return 80
	case types.EventScan:
		return 70
	case types.EventConnect:
		return 50
	default:
		return 60
	}
}

func eventTags(ev *types.Event) []string {
	tags := []string{
		"service:" + ev.ServiceType.String(),
	}
	if ev.EventType == types.EventExploit {
		tags = append(tags, "exploit-attempt")
	}
	return tags
}

func ExtractBulk(
	events []*types.Event,
) []*types.IOC {
	ext := NewExtractor()
	seen := make(map[string]*types.IOC)

	for _, ev := range events {
		iocs := ext.Extract(ev)
		for _, ioc := range iocs {
			key := ioc.Type.String() + ":" + ioc.Value
			if existing, ok := seen[key]; ok {
				existing.SightCount++
				if ioc.LastSeen.After(existing.LastSeen) {
					existing.LastSeen = ioc.LastSeen
				}
				if ioc.FirstSeen.Before(existing.FirstSeen) {
					existing.FirstSeen = ioc.FirstSeen
				}
				if ioc.Confidence > existing.Confidence {
					existing.Confidence = ioc.Confidence
				}
				existing.Tags = mergeUnique(
					existing.Tags, ioc.Tags,
				)
			} else {
				seen[key] = ioc
			}
		}
	}

	result := make([]*types.IOC, 0, len(seen))
	for _, ioc := range seen {
		result = append(result, ioc)
	}
	return result
}

func mergeUnique(a, b []string) []string {
	set := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	result := make([]string, 0, len(set))
	for s := range set {
		result = append(result, s)
	}
	return result
}

func FilterIPs(
	iocs []*types.IOC,
) []*types.IOC {
	var ips []*types.IOC
	for _, ioc := range iocs {
		if ioc.Type == types.IOCIPv4 ||
			ioc.Type == types.IOCIPv6 {
			ips = append(ips, ioc)
		}
	}
	return ips
}

func FilterByMinConfidence(
	iocs []*types.IOC, minConf int,
) []*types.IOC {
	var filtered []*types.IOC
	for _, ioc := range iocs {
		if ioc.Confidence >= minConf {
			filtered = append(filtered, ioc)
		}
	}
	return filtered
}

func FilterByAge(
	iocs []*types.IOC, maxAge time.Duration,
) []*types.IOC {
	cutoff := time.Now().UTC().Add(-maxAge)
	var filtered []*types.IOC
	for _, ioc := range iocs {
		if ioc.LastSeen.After(cutoff) {
			filtered = append(filtered, ioc)
		}
	}
	return filtered
}

func HasTag(ioc *types.IOC, tag string) bool {
	for _, t := range ioc.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}
