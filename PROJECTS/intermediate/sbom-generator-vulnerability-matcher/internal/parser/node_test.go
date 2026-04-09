// ©AngelaMos | 2026
// node_test.go

package parser

import (
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeDetect(t *testing.T) {
	p := NewNodeParser()
	assert.True(t, p.Detect(filepath.Join(testdataDir(t), "node-project")))
	assert.False(t, p.Detect(filepath.Join(testdataDir(t), "go-project")))
	assert.False(t, p.Detect(filepath.Join(testdataDir(t), "empty-project")))
}

func TestNodeParse(t *testing.T) {
	p := NewNodeParser()
	dir := filepath.Join(testdataDir(t), "node-project")
	graph, err := p.Parse(dir)
	require.NoError(t, err)

	assert.Equal(t, "test-project", graph.Root.Name)
	assert.Equal(t, types.EcosystemNode, graph.Root.Ecosystem)

	directCount := 0
	for _, pkg := range graph.Nodes {
		if pkg.Direct && pkg.PURL != graph.Root.PURL {
			directCount++
		}
	}
	assert.Equal(t, 3, directCount)

	hasExpress := false
	hasLodash := false
	hasTS := false
	for _, pkg := range graph.Nodes {
		switch pkg.Name {
		case "express":
			hasExpress = true
			assert.Equal(t, "4.18.2", pkg.Version)
		case "lodash":
			hasLodash = true
			assert.Equal(t, "4.17.20", pkg.Version)
		case "typescript":
			hasTS = true
			assert.Equal(t, "5.3.3", pkg.Version)
		}
	}
	assert.True(t, hasExpress)
	assert.True(t, hasLodash)
	assert.True(t, hasTS)
}

func TestNodeParseTransitive(t *testing.T) {
	p := NewNodeParser()
	dir := filepath.Join(testdataDir(t), "node-project")
	graph, err := p.Parse(dir)
	require.NoError(t, err)

	hasSemver := false
	for _, pkg := range graph.Nodes {
		if pkg.Name == "semver" {
			hasSemver = true
			assert.False(t, pkg.Direct)
		}
	}
	assert.True(t, hasSemver)
}

func TestNodeEcosystem(t *testing.T) {
	p := NewNodeParser()
	assert.Equal(t, types.EcosystemNode, p.Ecosystem())
}

func TestCleanNodeVersion(t *testing.T) {
	assert.Equal(t, "4.18.2", cleanNodeVersion("^4.18.2"))
	assert.Equal(t, "4.18.2", cleanNodeVersion("~4.18.2"))
	assert.Equal(t, "1.2.3", cleanNodeVersion(">=1.2.3"))
	assert.Equal(t, "2.0.0", cleanNodeVersion("<2.0.0"))
	assert.Equal(t, "1.0.0", cleanNodeVersion(">=1.0.0 <2.0.0"))
	assert.Equal(t, "4.18.2", cleanNodeVersion("4.18.2"))
	assert.Equal(t, "1.0.0", cleanNodeVersion("=1.0.0"))
}
