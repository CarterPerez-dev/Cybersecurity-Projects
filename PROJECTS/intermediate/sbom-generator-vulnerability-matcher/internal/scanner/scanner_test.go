// ©AngelaMos | 2026
// scanner_test.go

package scanner

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CarterPerez-dev/bomber/internal/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

func TestScanGoProject(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "go-project"))
	require.NoError(t, err)

	assert.Len(t, result.Graphs, 1)
	assert.Greater(t, result.TotalPkgs, 0)
}

func TestScanNodeProject(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "node-project"))
	require.NoError(t, err)

	assert.Len(t, result.Graphs, 1)
	assert.Greater(t, result.TotalPkgs, 0)
}

func TestScanPythonProject(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "python-project"))
	require.NoError(t, err)

	assert.Len(t, result.Graphs, 1)
	assert.Greater(t, result.TotalPkgs, 0)
}

func TestScanMonorepo(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "monorepo"))
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(result.Graphs), 2)
	assert.GreaterOrEqual(t, len(result.Ecosystems), 2)
}

func TestScanEmptyProject(t *testing.T) {
	reg := parser.NewRegistry()
	parser.RegisterAll(reg)

	s := New(reg)
	result, err := s.Scan(filepath.Join(testdataDir(t), "empty-project"))
	require.NoError(t, err)

	assert.Empty(t, result.Graphs)
	assert.Equal(t, 0, result.TotalPkgs)
}
