// ©AngelaMos | 2026
// pipeline_test.go

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/portia/internal/rules"
	"github.com/CarterPerez-dev/portia/internal/source"
)

func TestPipelineDirectoryScan(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "config.py"),
		[]byte(`api_key = "AKIAIOSFODNN7EXAMPLE"`+"\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "clean.go"),
		[]byte("package main\n\nfunc main() {}\n"),
		0o644,
	))

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, len(result.Findings), 1)

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "test-aws-key" {
			found = true
			assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", f.Secret)
		}
	}
	assert.True(t, found, "expected to find AWS key")
}

func TestPipelineNoFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"),
		0o644,
	))

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
}

func TestPipelineMultipleSecrets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "secrets.env"),
		[]byte(
			`AWS_KEY=AKIAIOSFODNN7EXAMPLE`+"\n"+
				`STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc`+"\n"+
				`password = "xK9mP2vL5nQ8jR3t"`+"\n",
		),
		0o644,
	))

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(result.Findings), 2)
}

func TestPipelineContextCancel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for i := range 20 {
		name := "file" + string(rune('A'+i)) + ".txt"
		require.NoError(t, os.WriteFile( //nolint:gosec
			filepath.Join(dir, name),
			[]byte(`AKIAIOSFODNN7EXAMPLE`+"\n"),
			0o644,
		))
	}

	reg := testRegistry()
	p := NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Run(ctx, src)
	assert.Error(t, err)
}

func TestPipelineDedup(t *testing.T) {
	t.Parallel()

	reg := rules.NewRegistry()
	rules.RegisterBuiltins(reg)
	p := NewPipeline(reg)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "dup.txt"),
		[]byte(
			`AKIAIOSFODNN7EXAMPLE`+"\n"+
				`AKIAIOSFODNN7EXAMPLE`+"\n",
		),
		0o644,
	))

	src := source.NewDirectory(dir, 0, nil)
	result, err := p.Run(context.Background(), src)
	require.NoError(t, err)

	awsCount := 0
	for _, f := range result.Findings {
		if f.Secret == "AKIAIOSFODNN7EXAMPLE" { //nolint:gosec
			awsCount++
		}
	}
	assert.LessOrEqual(t, awsCount, 2)
}
