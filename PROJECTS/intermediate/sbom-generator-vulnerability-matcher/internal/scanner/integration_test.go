// ©AngelaMos | 2026
// integration_test.go

package scanner

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/bomber/internal/graph"
	"github.com/CarterPerez-dev/bomber/internal/parser"
	"github.com/CarterPerez-dev/bomber/internal/sbom"
	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullPipelineGoProject(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "go-project"))
	require.NoError(t, err)
	require.Len(t, result.Graphs, 1)

	g := result.Graphs[0]
	assert.Greater(t, len(graph.AllPackages(g)), 1)
	assert.Empty(t, graph.DetectCycles(g))

	spdxGen := sbom.NewSPDXGenerator()
	spdxData, err := spdxGen.Generate(result.Graphs)
	require.NoError(t, err)
	assert.True(t, json.Valid(spdxData))

	cdxGen := sbom.NewCycloneDXGenerator()
	cdxData, err := cdxGen.Generate(result.Graphs)
	require.NoError(t, err)
	assert.True(t, json.Valid(cdxData))
}

func TestFullPipelineMonorepo(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "monorepo"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Graphs), 2)
	assert.GreaterOrEqual(t, len(result.Ecosystems), 2)
}

func TestFullPipelinePythonProject(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "python-project"))
	require.NoError(t, err)
	require.Len(t, result.Graphs, 1)

	g := result.Graphs[0]
	all := graph.AllPackages(g)
	assert.Greater(t, len(all), 1)

	spdxGen := sbom.NewSPDXGenerator()
	spdxData, err := spdxGen.Generate(result.Graphs)
	require.NoError(t, err)
	assert.True(t, json.Valid(spdxData))
}

func TestFullPipelineAllEcosystems(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	ecosystems := []string{"go-project", "node-project", "python-project"}

	for _, eco := range ecosystems {
		t.Run(eco, func(t *testing.T) {
			s := New(reg)
			result, err := s.Scan(filepath.Join(testdataDir(t), eco))
			require.NoError(t, err)
			require.NotEmpty(t, result.Graphs)
			assert.Greater(t, result.TotalPkgs, 0)
			assert.Greater(t, result.DirectPkgs, 0)

			for _, g := range result.Graphs {
				spdxGen := sbom.NewSPDXGenerator()
				spdxData, err := spdxGen.Generate([]*types.DependencyGraph{g})
				require.NoError(t, err)
				assert.True(t, json.Valid(spdxData))

				cdxGen := sbom.NewCycloneDXGenerator()
				cdxData, err := cdxGen.Generate([]*types.DependencyGraph{g})
				require.NoError(t, err)
				assert.True(t, json.Valid(cdxData))
			}
		})
	}
}
