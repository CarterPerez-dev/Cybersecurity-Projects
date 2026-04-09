// ©AngelaMos | 2026
// spdx_test.go

package sbom

import (
	"encoding/json"
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestGraph() *types.DependencyGraph {
	root := types.Package{
		Name: "test-project", Version: "1.0.0",
		Ecosystem: types.EcosystemGo,
		PURL:      "pkg:golang/test-project@1.0.0",
		Direct:    true,
	}
	g := types.NewDependencyGraph(root)

	dep := types.Package{
		Name: "github.com/example/lib", Version: "v2.0.0",
		Ecosystem: types.EcosystemGo,
		PURL:      "pkg:golang/github.com/example/lib@v2.0.0",
		Direct:    true, DepthLevel: 1,
		Checksums: []types.Checksum{{Algorithm: "SHA-256", Value: "abc123"}},
	}
	g.AddPackage(dep)
	g.AddEdge(root.PURL, dep.PURL)

	return g
}

func TestSPDXGenerate(t *testing.T) {
	g := makeTestGraph()
	gen := NewSPDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))

	assert.Equal(t, "SPDX-2.3", doc["spdxVersion"])
	assert.Equal(t, "CC0-1.0", doc["dataLicense"])

	packages, ok := doc["packages"].([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(packages), 2)

	relationships, ok := doc["relationships"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, relationships)
}

func TestSPDXValidJSON(t *testing.T) {
	g := makeTestGraph()
	gen := NewSPDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)
	assert.True(t, json.Valid(data))
}

func TestSPDXHasDescribes(t *testing.T) {
	g := makeTestGraph()
	gen := NewSPDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(data, &doc))

	hasDescribes := false
	for _, rel := range doc.Relationships {
		if rel.Type == "DESCRIBES" {
			hasDescribes = true
			break
		}
	}
	assert.True(t, hasDescribes)
}

func TestSPDXHasDependsOn(t *testing.T) {
	g := makeTestGraph()
	gen := NewSPDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)

	var doc spdxDocument
	require.NoError(t, json.Unmarshal(data, &doc))

	hasDependsOn := false
	for _, rel := range doc.Relationships {
		if rel.Type == "DEPENDS_ON" {
			hasDependsOn = true
			break
		}
	}
	assert.True(t, hasDependsOn)
}
