// ©AngelaMos | 2026
// cyclonedx_test.go

package sbom

import (
	"encoding/json"
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCycloneDXGenerate(t *testing.T) {
	g := makeTestGraph()
	gen := NewCycloneDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))

	assert.Equal(t, "CycloneDX", doc["bomFormat"])
	assert.Equal(t, "1.5", doc["specVersion"])

	components, ok := doc["components"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, components)

	deps, ok := doc["dependencies"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, deps)
}

func TestCycloneDXValidJSON(t *testing.T) {
	g := makeTestGraph()
	gen := NewCycloneDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)
	assert.True(t, json.Valid(data))
}

func TestCycloneDXHasSerialNumber(t *testing.T) {
	g := makeTestGraph()
	gen := NewCycloneDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)

	var doc cdxDocument
	require.NoError(t, json.Unmarshal(data, &doc))

	assert.Contains(t, doc.SerialNum, "urn:uuid:")
}

func TestCycloneDXHasPURL(t *testing.T) {
	g := makeTestGraph()
	gen := NewCycloneDXGenerator()
	data, err := gen.Generate([]*types.DependencyGraph{g})
	require.NoError(t, err)

	var doc cdxDocument
	require.NoError(t, json.Unmarshal(data, &doc))

	hasPURL := false
	for _, comp := range doc.Components {
		if comp.PURL != "" {
			hasPURL = true
			break
		}
	}
	assert.True(t, hasPURL)
}
