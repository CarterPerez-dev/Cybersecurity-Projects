/*
©AngelaMos | 2026
types.go

Shared domain types used across all packages in sentinel

Defines the core data structures that flow through the scan pipeline:
scanner results, individual findings with severity and MITRE mappings,
and the aggregated scan report. All packages import from here; nothing
in this package imports from internal packages.
*/

package types

import "time"

const Version = "1.0.0"

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	return severityNames[s]
}

func (s Severity) Label() string {
	return severityLabels[s]
}

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

var severityLabels = map[Severity]string{
	SeverityInfo:     "INFO",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

func ParseSeverity(s string) Severity {
	for sev, name := range severityNames {
		if name == s {
			return sev
		}
	}
	return SeverityInfo
}

type Finding struct {
	Scanner  string   `json:"scanner"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Path     string   `json:"path"`
	Evidence string   `json:"evidence"`
	MITRE    string   `json:"mitre"`
}

type ScanResult struct {
	Version    string        `json:"version"`
	ScanTime   time.Time     `json:"scan_time"`
	Hostname   string        `json:"hostname"`
	Findings   []Finding     `json:"findings"`
	Summary    SeverityCount `json:"summary"`
	DurationMs int64         `json:"duration_ms"`
}

type SeverityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func Tally(findings []Finding) SeverityCount {
	var c SeverityCount
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			c.Critical++
		case SeverityHigh:
			c.High++
		case SeverityMedium:
			c.Medium++
		case SeverityLow:
			c.Low++
		case SeverityInfo:
			c.Info++
		}
	}
	return c
}

type Scanner interface {
	Name() string
	Scan(root string) []Finding
}
