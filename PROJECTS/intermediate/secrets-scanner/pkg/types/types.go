// ©AngelaMos | 2026
// types.go

package types

import (
	"regexp"
	"time"
)

type SecretType int

const (
	SecretTypePassword SecretType = iota
	SecretTypeAPIKey
	SecretTypeToken
	SecretTypePrivateKey
	SecretTypeConnectionString
	SecretTypeGenericHighEntropy
)

func (s SecretType) String() string {
	switch s {
	case SecretTypePassword:
		return "password"
	case SecretTypeAPIKey:
		return "api-key"
	case SecretTypeToken:
		return "token"
	case SecretTypePrivateKey:
		return "private-key"
	case SecretTypeConnectionString:
		return "connection-string"
	case SecretTypeGenericHighEntropy:
		return "generic-high-entropy"
	default:
		return "unknown"
	}
}

type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func ParseSeverity(s string) Severity {
	switch s {
	case "CRITICAL", "critical":
		return SeverityCritical
	case "HIGH", "high":
		return SeverityHigh
	case "MEDIUM", "medium":
		return SeverityMedium
	case "LOW", "low":
		return SeverityLow
	default:
		return SeverityLow
	}
}

func (s Severity) Rank() int {
	return int(s)
}

type HIBPStatus int

const (
	HIBPUnchecked HIBPStatus = iota
	HIBPBreached
	HIBPClean
	HIBPSkipped
	HIBPError
)

func (h HIBPStatus) String() string {
	switch h {
	case HIBPUnchecked:
		return "unchecked"
	case HIBPBreached:
		return "breached"
	case HIBPClean:
		return "clean"
	case HIBPSkipped:
		return "skipped"
	case HIBPError:
		return "error"
	default:
		return "unchecked"
	}
}

type Allowlist struct {
	Paths     []*regexp.Regexp
	Values    []*regexp.Regexp
	Stopwords []string
}

type Rule struct {
	ID          string
	Description string
	Severity    Severity
	Keywords    []string
	Pattern     *regexp.Regexp
	SecretGroup int
	Entropy     *float64
	Allowlist   Allowlist
	SecretType  SecretType
}

type Chunk struct {
	Content    string
	FilePath   string
	LineStart  int
	CommitSHA  string
	Author     string
	CommitDate time.Time
}

type Finding struct {
	RuleID      string
	Description string
	Severity    Severity
	Match       string
	Secret      string //nolint:gosec
	Entropy     float64
	FilePath    string
	LineNumber  int
	LineContent string
	CommitSHA   string
	Author      string
	CommitDate  time.Time
	HIBPStatus  HIBPStatus
	BreachCount int
}

type ScanResult struct {
	Findings      []Finding
	TotalFiles    int
	TotalRules    int
	TotalFindings int
	HIBPChecked   int
	HIBPBreached  int
	Duration      time.Duration
}
