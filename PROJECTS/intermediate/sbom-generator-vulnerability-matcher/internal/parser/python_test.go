// ©AngelaMos | 2026
// python_test.go

package parser

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPythonDetect(t *testing.T) {
	p := NewPythonParser()
	assert.True(t, p.Detect(filepath.Join(testdataDir(t), "python-project")))
	assert.False(t, p.Detect(filepath.Join(testdataDir(t), "go-project")))
	assert.False(t, p.Detect(filepath.Join(testdataDir(t), "empty-project")))
}

func TestPythonParse(t *testing.T) {
	p := NewPythonParser()
	dir := filepath.Join(testdataDir(t), "python-project")
	graph, err := p.Parse(dir)
	require.NoError(t, err)

	assert.Equal(t, "test-project", graph.Root.Name)
	assert.Equal(t, types.EcosystemPython, graph.Root.Ecosystem)

	directCount := 0
	for _, pkg := range graph.Nodes {
		if pkg.Direct && pkg.PURL != graph.Root.PURL {
			directCount++
		}
	}
	assert.GreaterOrEqual(t, directCount, 2)

	hasRequests := false
	hasPydantic := false
	for _, pkg := range graph.Nodes {
		switch pkg.Name {
		case "requests":
			hasRequests = true
			assert.Equal(t, "2.31.0", pkg.Version)
			assert.True(t, pkg.Direct)
		case "pydantic":
			hasPydantic = true
			assert.Equal(t, "2.6.1", pkg.Version)
			assert.True(t, pkg.Direct)
		}
	}
	assert.True(t, hasRequests)
	assert.True(t, hasPydantic)
}

func TestPythonParseTransitive(t *testing.T) {
	p := NewPythonParser()
	dir := filepath.Join(testdataDir(t), "python-project")
	graph, err := p.Parse(dir)
	require.NoError(t, err)

	hasUrllib3 := false
	hasCertifi := false
	for _, pkg := range graph.Nodes {
		switch pkg.Name {
		case "urllib3":
			hasUrllib3 = true
			assert.False(t, pkg.Direct)
		case "certifi":
			hasCertifi = true
			assert.False(t, pkg.Direct)
		}
	}
	assert.True(t, hasUrllib3)
	assert.True(t, hasCertifi)
}

func TestPythonParseEdges(t *testing.T) {
	p := NewPythonParser()
	dir := filepath.Join(testdataDir(t), "python-project")
	graph, err := p.Parse(dir)
	require.NoError(t, err)

	requestsPURL := "pkg:pypi/requests@2.31.0"
	children := graph.Edges[requestsPURL]
	assert.NotEmpty(t, children)
}

func TestPythonEcosystem(t *testing.T) {
	p := NewPythonParser()
	assert.Equal(t, types.EcosystemPython, p.Ecosystem())
}

func TestExtractPyPkgName(t *testing.T) {
	assert.Equal(t, "requests", extractPyPkgName("requests>=2.31.0"))
	assert.Equal(t, "pydantic", extractPyPkgName("pydantic>=2.5.0"))
	assert.Equal(t, "pytest", extractPyPkgName("pytest>=8.0.0"))
	assert.Equal(t, "simple", extractPyPkgName("simple"))
}
