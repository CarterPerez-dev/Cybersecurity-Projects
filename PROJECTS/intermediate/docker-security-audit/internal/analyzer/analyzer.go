/*
AngelaMos | 2026
analyzer.go
*/

package analyzer

import (
	"context"

	"github.com/CarterPerez-dev/docksec/internal/finding"
)

// Analyzer defines the interface for security analyzers that inspect
// Docker environments and produce security findings.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context) (finding.Collection, error)
}

// Result holds the output of a single analyzer run, including any
// findings discovered and any error encountered during analysis.
type Result struct {
	Analyzer string
	Findings finding.Collection
	Error    error
}

// Category represents a grouping for security findings, typically
// aligned with CIS Docker Benchmark sections.
type Category string

// Categories for organizing security findings by CIS Docker Benchmark section.
const (
	CategoryContainerRuntime Category = "Container Runtime"
	CategoryDaemon           Category = "Docker Daemon Configuration"
	CategoryImage            Category = "Container Images and Build Files"
	CategoryDockerfile       Category = "Dockerfile"
	CategoryCompose          Category = "Docker Compose"
)
