// ©AngelaMos | 2026
// gomod_test.go

package parser

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

func TestGoModDetect(t *testing.T) {
	p := NewGoModParser()
	assert.True(t, p.Detect(filepath.Join(testdataDir(t), "go-project")))
	assert.False(t, p.Detect(filepath.Join(testdataDir(t), "node-project")))
	assert.False(t, p.Detect(filepath.Join(testdataDir(t), "empty-project")))
}

func TestGoModParse(t *testing.T) {
	p := NewGoModParser()
	dir := filepath.Join(testdataDir(t), "go-project")
	graph, err := p.Parse(dir)
	require.NoError(t, err)

	assert.Equal(t, "example.com/testproject", graph.Root.Name)
	assert.Equal(t, types.EcosystemGo, graph.Root.Ecosystem)

	directCount := 0
	for _, pkg := range graph.Nodes {
		if pkg.Direct && pkg.PURL != graph.Root.PURL {
			directCount++
		}
	}
	assert.Equal(t, 2, directCount)

	_, hasCobra := graph.Nodes["pkg:golang/github.com/spf13/cobra@v1.10.2"]
	assert.True(t, hasCobra)

	_, hasNet := graph.Nodes["pkg:golang/golang.org/x/net@v0.1.0"]
	assert.True(t, hasNet)

	_, hasMousetrap := graph.Nodes["pkg:golang/github.com/inconshreveable/mousetrap@v1.1.0"]
	assert.True(t, hasMousetrap)
}

func TestGoModParseChecksums(t *testing.T) {
	p := NewGoModParser()
	dir := filepath.Join(testdataDir(t), "go-project")
	graph, err := p.Parse(dir)
	require.NoError(t, err)

	cobra := graph.Nodes["pkg:golang/github.com/spf13/cobra@v1.10.2"]
	assert.NotEmpty(t, cobra.Checksums)
}

func TestGoModEcosystem(t *testing.T) {
	p := NewGoModParser()
	assert.Equal(t, types.EcosystemGo, p.Ecosystem())
}
