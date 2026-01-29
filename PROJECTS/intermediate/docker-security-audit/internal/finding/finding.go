/*
AngelaMos | 2026
finding.go
*/

package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	containerIDShortLength = 12
	imageIDShortLength     = 12
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityToString = map[Severity]string{
	SeverityInfo:     "INFO",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

var stringToSeverity = func() map[string]Severity {
	m := make(map[string]Severity, len(severityToString))
	for sev, str := range severityToString {
		m[str] = sev
	}
	return m
}()

var severityColors = map[Severity]string{
	SeverityInfo:     "\033[36m",
	SeverityLow:      "\033[34m",
	SeverityMedium:   "\033[33m",
	SeverityHigh:     "\033[31m",
	SeverityCritical: "\033[35m",
}

func (s Severity) String() string {
	if str, ok := severityToString[s]; ok {
		return str
	}
	return "UNKNOWN"
}

func (s Severity) Color() string {
	if color, ok := severityColors[s]; ok {
		return color
	}
	return "\033[0m"
}

func ParseSeverity(s string) (Severity, bool) {
	sev, ok := stringToSeverity[strings.ToUpper(strings.TrimSpace(s))]
	return sev, ok
}

type TargetType string

const (
	TargetContainer  TargetType = "container"
	TargetImage      TargetType = "image"
	TargetDockerfile TargetType = "dockerfile"
	TargetCompose    TargetType = "compose"
	TargetDaemon     TargetType = "daemon"
)

type Target struct {
	Type TargetType
	Name string
	ID   string
}

func (t Target) String() string {
	if t.ID != "" && len(t.ID) >= containerIDShortLength {
		return fmt.Sprintf(
			"%s:%s (%s)",
			t.Type,
			t.Name,
			t.ID[:containerIDShortLength],
		)
	}
	if t.ID != "" {
		return fmt.Sprintf("%s:%s (%s)", t.Type, t.Name, t.ID)
	}
	return fmt.Sprintf("%s:%s", t.Type, t.Name)
}

type Location struct {
	Path   string
	Line   int
	Column int
}

func (l Location) String() string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.Path, l.Line)
	}
	return l.Path
}

type CISControl struct {
	ID          string
	Section     string
	Title       string
	Description string
	Scored      bool
	Level       int
}

func (c CISControl) String() string {
	return fmt.Sprintf("CIS %s", c.ID)
}

type Finding struct {
	ID          string
	RuleID      string
	Title       string
	Description string
	Severity    Severity
	Category    string
	Target      Target
	Location    *Location
	Remediation string
	References  []string
	CISControl  *CISControl
	Timestamp   time.Time
}

func New(
	ruleID string,
	title string,
	severity Severity,
	target Target,
) *Finding {
	f := &Finding{
		RuleID:    ruleID,
		Title:     title,
		Severity:  severity,
		Target:    target,
		Timestamp: time.Now(),
	}
	f.ID = f.generateID()
	return f
}

func (f *Finding) generateID() string {
	data := fmt.Sprintf(
		"%s|%s|%s|%s",
		f.RuleID,
		f.Target.Type,
		f.Target.Name,
		f.Target.ID,
	)
	if f.Location != nil {
		data += fmt.Sprintf("|%s:%d", f.Location.Path, f.Location.Line)
	}
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func (f *Finding) WithDescription(desc string) *Finding {
	f.Description = desc
	return f
}

func (f *Finding) WithCategory(cat string) *Finding {
	f.Category = cat
	return f
}

func (f *Finding) WithLocation(loc *Location) *Finding {
	f.Location = loc
	f.ID = f.generateID()
	return f
}

func (f *Finding) WithRemediation(rem string) *Finding {
	f.Remediation = rem
	return f
}

func (f *Finding) WithReferences(refs ...string) *Finding {
	f.References = refs
	return f
}

func (f *Finding) WithCISControl(control *CISControl) *Finding {
	f.CISControl = control
	return f
}

// Collection is a slice of findings with filtering and aggregation methods
type Collection []*Finding

func (c Collection) BySeverity(sev Severity) Collection {
	result := make(Collection, 0, len(c))
	for _, f := range c {
		if f.Severity == sev {
			result = append(result, f)
		}
	}
	return result
}

func (c Collection) AtOrAbove(sev Severity) Collection {
	result := make(Collection, 0, len(c))
	for _, f := range c {
		if f.Severity >= sev {
			result = append(result, f)
		}
	}
	return result
}

func (c Collection) ByCategory(cat string) Collection {
	result := make(Collection, 0, len(c))
	for _, f := range c {
		if f.Category == cat {
			result = append(result, f)
		}
	}
	return result
}

func (c Collection) ByTargetType(tt TargetType) Collection {
	result := make(Collection, 0, len(c))
	for _, f := range c {
		if f.Target.Type == tt {
			result = append(result, f)
		}
	}
	return result
}

func (c Collection) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int, len(severityToString))
	for _, f := range c {
		counts[f.Severity]++
	}
	return counts
}

func (c Collection) HasSeverityAtOrAbove(sev Severity) bool {
	for _, f := range c {
		if f.Severity >= sev {
			return true
		}
	}
	return false
}

func (c Collection) Total() int {
	return len(c)
}
