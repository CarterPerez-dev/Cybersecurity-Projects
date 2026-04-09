// ©AngelaMos | 2026
// types.go

package types

import (
	"strings"
	"time"
)

type Ecosystem int

const (
	EcosystemGo Ecosystem = iota
	EcosystemNode
	EcosystemPython
)

func (e Ecosystem) String() string {
	switch e {
	case EcosystemGo:
		return "go"
	case EcosystemNode:
		return "node"
	case EcosystemPython:
		return "python"
	default:
		return "unknown"
	}
}

type Severity int

const (
	SeverityNone Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
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
	case SeverityNone:
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

func ParseSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	case "NONE":
		return SeverityNone
	default:
		return SeverityNone
	}
}

func (s Severity) Rank() int {
	return int(s)
}

type Checksum struct {
	Algorithm string
	Value     string
}

type Package struct {
	Name       string
	Version    string
	Ecosystem  Ecosystem
	PURL       string
	Checksums  []Checksum
	Direct     bool
	DepthLevel int
}

type DependencyGraph struct {
	Root  Package
	Nodes map[string]Package
	Edges map[string][]string
}

func NewDependencyGraph(root Package) *DependencyGraph {
	g := &DependencyGraph{
		Root:  root,
		Nodes: make(map[string]Package),
		Edges: make(map[string][]string),
	}
	g.Nodes[root.PURL] = root
	return g
}

func (g *DependencyGraph) AddPackage(pkg Package) {
	g.Nodes[pkg.PURL] = pkg
}

func (g *DependencyGraph) AddEdge(parentPURL, childPURL string) {
	g.Edges[parentPURL] = append(g.Edges[parentPURL], childPURL)
}

type Vulnerability struct {
	ID            string
	Aliases       []string
	Severity      Severity
	Score         float64
	AffectedRange string
	FixVersion    string
	Summary       string
	Source        string
	Published     time.Time
}

type VulnMatch struct {
	Package       Package
	Vulnerability Vulnerability
}

type PolicyViolation struct {
	Rule    string
	Message string
	Package Package
	Vuln    *Vulnerability
}

type ScanResult struct {
	Graphs     []*DependencyGraph
	TotalPkgs  int
	DirectPkgs int
	Ecosystems []Ecosystem
}

type VulnReport struct {
	Matches    []VulnMatch
	TotalPkgs  int
	DirectPkgs int
	BySeverity map[Severity]int
}

type CheckResult struct {
	Passed     bool
	Violations []PolicyViolation
}
