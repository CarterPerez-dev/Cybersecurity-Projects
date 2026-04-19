/*
©AngelaMos | 2026
stix.go

STIX 2.1 threat intelligence export for honeypot IOCs

Generates standards-compliant STIX bundles containing indicator
objects for each IOC extracted from honeypot traffic. Compatible
with MISP, OpenCTI, and other threat intelligence platforms that
consume STIX 2.1 JSON feeds.
*/

package intel

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	stixVersion   = "2.1"
	stixSpecVer   = "2.1"
	identityName  = "Hive Honeypot Network"
	identityClass = "system"
)

type stixBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

type stixIdentity struct {
	Type          string `json:"type"`
	SpecVersion   string `json:"spec_version"`
	ID            string `json:"id"`
	Created       string `json:"created"`
	Modified      string `json:"modified"`
	Name          string `json:"name"`
	IdentityClass string `json:"identity_class"`
}

type stixIndicator struct {
	Type         string   `json:"type"`
	SpecVersion  string   `json:"spec_version"`
	ID           string   `json:"id"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
	Name         string   `json:"name"`
	Pattern      string   `json:"pattern"`
	PatternType  string   `json:"pattern_type"`
	ValidFrom    string   `json:"valid_from"`
	Labels       []string `json:"labels"`
	Confidence   int      `json:"confidence"`
	CreatedByRef string   `json:"created_by_ref"`
}

func GenerateSTIXBundle(
	iocs []*types.IOC,
) ([]byte, error) {
	identityID := fmt.Sprintf(
		"identity--%s",
		uuid.New().String(),
	)
	now := time.Now().UTC().Format(time.RFC3339)

	identity := stixIdentity{
		Type:          "identity",
		SpecVersion:   stixSpecVer,
		ID:            identityID,
		Created:       now,
		Modified:      now,
		Name:          identityName,
		IdentityClass: identityClass,
	}

	objects := []interface{}{identity}

	for _, ioc := range iocs {
		pattern := iocToSTIXPattern(ioc)
		if pattern == "" {
			continue
		}

		indicator := stixIndicator{
			Type:        "indicator",
			SpecVersion: stixSpecVer,
			ID: fmt.Sprintf(
				"indicator--%s",
				uuid.New().String(),
			),
			Created:  ioc.FirstSeen.UTC().Format(time.RFC3339),
			Modified: ioc.LastSeen.UTC().Format(time.RFC3339),
			Name: fmt.Sprintf(
				"%s: %s",
				ioc.Type.String(), ioc.Value,
			),
			Pattern:      pattern,
			PatternType:  "stix",
			ValidFrom:    ioc.FirstSeen.UTC().Format(time.RFC3339),
			Labels:       stixLabels(ioc),
			Confidence:   ioc.Confidence,
			CreatedByRef: identityID,
		}

		objects = append(objects, indicator)
	}

	bundle := stixBundle{
		Type: "bundle",
		ID: fmt.Sprintf(
			"bundle--%s",
			uuid.New().String(),
		),
		Objects: objects,
	}

	return json.MarshalIndent(bundle, "", "  ")
}

func iocToSTIXPattern(ioc *types.IOC) string {
	switch ioc.Type {
	case types.IOCIPv4:
		return fmt.Sprintf(
			"[ipv4-addr:value = '%s']", ioc.Value,
		)
	case types.IOCIPv6:
		return fmt.Sprintf(
			"[ipv6-addr:value = '%s']", ioc.Value,
		)
	case types.IOCDomain:
		return fmt.Sprintf(
			"[domain-name:value = '%s']", ioc.Value,
		)
	case types.IOCURL:
		return fmt.Sprintf(
			"[url:value = '%s']", ioc.Value,
		)
	case types.IOCHashSHA256:
		return fmt.Sprintf(
			"[file:hashes.'SHA-256' = '%s']",
			ioc.Value,
		)
	case types.IOCHashMD5:
		return fmt.Sprintf(
			"[file:hashes.MD5 = '%s']", ioc.Value,
		)
	case types.IOCUserAgent:
		return fmt.Sprintf(
			"[network-traffic:extensions."+
				"'http-request-ext'."+
				"request_header.'User-Agent' = '%s']",
			ioc.Value,
		)
	case types.IOCEmail:
		return fmt.Sprintf(
			"[email-addr:value = '%s']", ioc.Value,
		)
	default:
		return ""
	}
}

func stixLabels(ioc *types.IOC) []string {
	labels := []string{"malicious-activity"}

	switch ioc.Type {
	case types.IOCIPv4, types.IOCIPv6:
		labels = append(
			labels, "anomalous-activity",
		)
	case types.IOCURL, types.IOCDomain:
		labels = append(labels, "malware")
	case types.IOCHashSHA256, types.IOCHashMD5:
		labels = append(labels, "malware")
	case types.IOCUserAgent:
		labels = append(labels, "tool")
	default:
	}

	for _, tag := range ioc.Tags {
		if tag == "exploit-attempt" {
			labels = append(
				labels, "exploit-activity",
			)
		}
	}

	return labels
}
