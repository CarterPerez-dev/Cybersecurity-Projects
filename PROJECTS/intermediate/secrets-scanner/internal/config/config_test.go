// ©AngelaMos | 2026
// config_test.go

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadExplicitPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "portia.toml")

	content := `
[rules]
disable = ["generic-password"]

[scan]
max_file_size = 2097152
excludes = ["vendor/", "*.test.js"]

[output]
format = "json"
verbose = true

[hibp]
enabled = true
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, []string{"generic-password"}, cfg.Rules.Disable)
	assert.Equal(t, int64(2097152), cfg.Scan.MaxFileSize)
	assert.Equal(t, []string{"vendor/", "*.test.js"}, cfg.Scan.Excludes)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.True(t, cfg.Output.Verbose)
	assert.True(t, cfg.HIBP.Enabled)
}

func TestLoadNonexistentExplicitPath(t *testing.T) {
	t.Parallel()

	cfg, err := Load("/nonexistent/path/portia.toml")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "terminal", cfg.Output.Format)
	assert.Equal(t, int64(1<<20), cfg.Scan.MaxFileSize)
}

func TestLoadEmptyPathReturnsDefaults(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "terminal", cfg.Output.Format)
	assert.Equal(t, int64(1<<20), cfg.Scan.MaxFileSize)
}

func TestLoadDiscoveryFromCurrentDir(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	content := `
[output]
format = "sarif"
`
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, DefaultConfigFile),
		[]byte(content), 0o644,
	))

	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "sarif", cfg.Output.Format)
}

func TestLoadPyprojectFallback(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	content := `
[project]
name = "myproject"

[tool.portia.output]
format = "json"
verbose = true
`
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pyproject.toml"),
		[]byte(content), 0o644,
	))

	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.True(t, cfg.Output.Verbose)
}

func TestLoadPyprojectIgnoredWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck

	content := `
[project]
name = "myproject"
`
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "pyproject.toml"),
		[]byte(content), 0o644,
	))

	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "terminal", cfg.Output.Format)
}

func TestDefaultTemplateValidTOML(t *testing.T) {
	t.Parallel()

	tmpl := DefaultTemplate()
	assert.Contains(t, tmpl, "[rules]")
	assert.Contains(t, tmpl, "[scan]")
	assert.Contains(t, tmpl, "[output]")
	assert.Contains(t, tmpl, "[hibp]")
	assert.Contains(t, tmpl, "[allowlist]")
}

func TestPyprojectTemplateIncludesName(t *testing.T) {
	t.Parallel()

	tmpl := PyprojectTemplate("myapp")
	assert.Contains(t, tmpl, `name = "myapp"`)
	assert.Contains(t, tmpl, "[tool.portia]")
}

func TestLoadInvalidTOML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	require.NoError(t, os.WriteFile(path, []byte(`[invalid`), 0o644))

	_, err := Load(path)
	assert.Error(t, err)
}
