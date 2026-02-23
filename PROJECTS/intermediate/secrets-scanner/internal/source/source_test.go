// ©AngelaMos | 2026
// source_test.go

package source

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

func collectChunks(
	t *testing.T, src Source,
) []types.Chunk {
	t.Helper()
	out := make(chan types.Chunk, 100)
	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- src.Chunks(ctx, out)
		close(out)
	}()

	var chunks []types.Chunk
	for c := range out {
		chunks = append(chunks, c)
	}
	require.NoError(t, <-errCh)
	return chunks
}

func TestDirectoryChunks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "config.py"),
		[]byte(`password = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`+"\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "logo.png"),
		[]byte{0x89, 0x50, 0x4E, 0x47},
		0o644,
	))

	src := NewDirectory(dir, 0, nil)
	chunks := collectChunks(t, src)

	require.Len(t, chunks, 1)
	assert.Equal(t, "config.py", chunks[0].FilePath)
	assert.Contains(t, chunks[0].Content, "sk_live_")
	assert.Equal(t, 1, chunks[0].LineStart)
}

func TestDirectoryExcludes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "main.go"),
		[]byte("package main\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "secret.env"),
		[]byte("API_KEY=test\n"),
		0o644,
	))

	src := NewDirectory(dir, 0, []string{"*.env"})
	chunks := collectChunks(t, src)

	require.Len(t, chunks, 1)
	assert.Equal(t, "main.go", chunks[0].FilePath)
}

func TestDirectorySkipsDotGit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git", "objects")
	require.NoError(t, os.MkdirAll(gitDir, 0o755)) //nolint:gosec
	require.NoError(t, os.WriteFile(               //nolint:gosec
		filepath.Join(gitDir, "data"),
		[]byte("git internal data\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "app.go"),
		[]byte("package main\n"),
		0o644,
	))

	src := NewDirectory(dir, 0, nil)
	chunks := collectChunks(t, src)

	require.Len(t, chunks, 1)
	assert.Equal(t, "app.go", chunks[0].FilePath)
}

func TestDirectoryMaxSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "small.txt"),
		[]byte("small\n"),
		0o644,
	))
	bigContent := make([]byte, 2*1024*1024)
	for i := range bigContent {
		bigContent[i] = 'x'
	}
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "big.txt"),
		bigContent,
		0o644,
	))

	src := NewDirectory(dir, 1024*1024, nil)
	chunks := collectChunks(t, src)

	require.Len(t, chunks, 1)
	assert.Equal(t, "small.txt", chunks[0].FilePath)
}

func TestDirectoryChunking(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	var lines string
	for i := range 120 {
		lines += "line " + string(rune('A'+i%26)) + "\n"
	}
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "long.txt"),
		[]byte(lines),
		0o644,
	))

	src := NewDirectory(dir, 0, nil)
	chunks := collectChunks(t, src)

	require.GreaterOrEqual(t, len(chunks), 2)
	assert.Equal(t, 1, chunks[0].LineStart)
	assert.Equal(t, 51, chunks[1].LineStart)
}

func TestDirectoryContextCancel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for i := range 10 {
		name := filepath.Join(dir, "file"+string(rune('0'+i))+".txt")
		require.NoError(t, os.WriteFile( //nolint:gosec
			name, []byte("content\n"), 0o644,
		))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := NewDirectory(dir, 0, nil)
	out := make(chan types.Chunk, 100)
	err := src.Chunks(ctx, out)
	close(out)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestDirectoryString(t *testing.T) {
	t.Parallel()
	src := NewDirectory("/tmp/test", 0, nil)
	assert.Equal(t, "directory:/tmp/test", src.String())
}

func TestGitChunks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "secret.py"),
		[]byte(`api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`+"\n"),
		0o644,
	))
	_, err = wt.Add("secret.py")
	require.NoError(t, err)

	_, err = wt.Commit("add secret", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	src := NewGit(dir, "", "", 0, false, 0, nil)
	chunks := collectChunks(t, src)

	require.GreaterOrEqual(t, len(chunks), 1)
	assert.Equal(t, "secret.py", chunks[0].FilePath)
	assert.Contains(t, chunks[0].Content, "sk_live_")
	assert.NotEmpty(t, chunks[0].CommitSHA)
	assert.Equal(t, "test@example.com", chunks[0].Author)
}

func TestGitStagedOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "committed.txt"),
		[]byte("committed content\n"),
		0o644,
	))
	_, err = wt.Add("committed.txt")
	require.NoError(t, err)
	_, err = wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "staged.txt"),
		[]byte("new staged content\n"),
		0o644,
	))
	_, err = wt.Add("staged.txt")
	require.NoError(t, err)

	src := NewGit(dir, "", "", 0, true, 0, nil)
	chunks := collectChunks(t, src)

	found := false
	for _, c := range chunks {
		if c.FilePath == "staged.txt" {
			found = true
			assert.Contains(t, c.Content, "new staged content")
		}
	}
	assert.True(t, found, "expected to find staged.txt chunk")
}

func TestGitDepthLimit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	for i := range 5 {
		name := "file" + string(rune('0'+i)) + ".txt"
		require.NoError(t, os.WriteFile( //nolint:gosec
			filepath.Join(dir, name),
			[]byte("content "+name+"\n"),
			0o644,
		))
		_, err = wt.Add(name)
		require.NoError(t, err)
		_, err = wt.Commit("commit "+name, &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test",
				Email: "test@example.com",
				When:  time.Now().Add(time.Duration(i) * time.Minute),
			},
		})
		require.NoError(t, err)
	}

	src := NewGit(dir, "", "", 2, false, 0, nil)
	chunks := collectChunks(t, src)

	files := make(map[string]bool)
	for _, c := range chunks {
		files[c.FilePath] = true
	}
	assert.LessOrEqual(t, len(files), 5)
}

func TestGitExcludes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "keep.go"),
		[]byte("package main\n"),
		0o644,
	))
	require.NoError(t, os.WriteFile( //nolint:gosec
		filepath.Join(dir, "skip.lock"),
		[]byte("lock data\n"),
		0o644,
	))
	_, err = wt.Add("keep.go")
	require.NoError(t, err)
	_, err = wt.Add("skip.lock")
	require.NoError(t, err)

	_, err = wt.Commit("add files", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)

	src := NewGit(dir, "", "", 0, false, 0, []string{".lock"})
	chunks := collectChunks(t, src)

	for _, c := range chunks {
		assert.NotContains(t, c.FilePath, ".lock")
	}
}

func TestGitString(t *testing.T) {
	t.Parallel()
	src := NewGit("/tmp/repo", "", "", 0, false, 0, nil)
	assert.Equal(t, "git:/tmp/repo", src.String())
}

func TestSplitIntoChunks(t *testing.T) {
	t.Parallel()

	var lines []string
	for i := range 120 {
		lines = append(lines, "line "+string(rune('A'+i%26)))
	}
	content := ""
	for i, l := range lines {
		if i > 0 {
			content += "\n"
		}
		content += l
	}

	chunks := splitIntoChunks(
		content, "test.txt", "abc123", "dev@test.com", time.Now(),
	)

	require.Len(t, chunks, 3)
	assert.Equal(t, 1, chunks[0].LineStart)
	assert.Equal(t, 51, chunks[1].LineStart)
	assert.Equal(t, 101, chunks[2].LineStart)
	assert.Equal(t, "abc123", chunks[0].CommitSHA)
	assert.Equal(t, "dev@test.com", chunks[0].Author)
}

func TestSplitIntoChunksEmpty(t *testing.T) {
	t.Parallel()
	chunks := splitIntoChunks(
		"", "test.txt", "", "", time.Time{},
	)
	assert.Empty(t, chunks)
}

func TestIsBinaryExt(t *testing.T) {
	t.Parallel()

	assert.True(t, isBinaryExt("image.png"))
	assert.True(t, isBinaryExt("data.PDF"))
	assert.True(t, isBinaryExt("app.exe"))
	assert.True(t, isBinaryExt("model.onnx"))
	assert.True(t, isBinaryExt("font.otf"))
	assert.True(t, isBinaryExt("data.parquet"))
	assert.True(t, isBinaryExt("archive.xz"))
	assert.True(t, isBinaryExt("package.deb"))
	assert.True(t, isBinaryExt("movie.mkv"))
	assert.False(t, isBinaryExt("main.go"))
	assert.False(t, isBinaryExt("config.yaml"))
	assert.False(t, isBinaryExt("script.py"))
}
