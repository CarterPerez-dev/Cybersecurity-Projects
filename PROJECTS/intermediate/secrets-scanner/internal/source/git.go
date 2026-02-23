// ©AngelaMos | 2026
// git.go

package source

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

type Git struct {
	RepoPath   string
	Branch     string
	Since      string
	Depth      int
	StagedOnly bool
	MaxSize    int64
	Excludes   []string
}

func NewGit(
	repoPath string,
	branch string,
	since string,
	depth int,
	stagedOnly bool,
	maxSize int64,
	excludes []string,
) *Git {
	if maxSize <= 0 {
		maxSize = defaultMaxFileSize
	}
	return &Git{
		RepoPath:   repoPath,
		Branch:     branch,
		Since:      since,
		Depth:      depth,
		StagedOnly: stagedOnly,
		MaxSize:    maxSize,
		Excludes:   excludes,
	}
}

func (g *Git) String() string {
	return "git:" + g.RepoPath
}

func (g *Git) Chunks(
	ctx context.Context, out chan<- types.Chunk,
) error {
	repo, err := git.PlainOpen(g.RepoPath)
	if err != nil {
		return fmt.Errorf("open repository: %w", err)
	}

	if g.StagedOnly {
		return g.scanStaged(ctx, repo, out)
	}

	return g.scanHistory(ctx, repo, out)
}

func (g *Git) scanStaged(
	ctx context.Context,
	repo *git.Repository,
	out chan<- types.Chunk,
) error {
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("worktree: %w", err)
	}

	status, err := wt.Status()
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}

	idx, err := repo.Storer.Index()
	if err != nil {
		return fmt.Errorf("index: %w", err)
	}

	for _, entry := range idx.Entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		fileStatus := status.File(entry.Name)
		if fileStatus.Staging == git.Unmodified &&
			fileStatus.Worktree == git.Unmodified {
			continue
		}

		if g.isExcluded(entry.Name) || isBinaryExt(entry.Name) {
			continue
		}

		blob, blobErr := repo.BlobObject(entry.Hash)
		if blobErr != nil {
			continue
		}

		if blob.Size > g.MaxSize {
			continue
		}

		content, readErr := readBlob(blob)
		if readErr != nil {
			continue
		}

		chunks := splitIntoChunks(
			content, entry.Name, "", "", time.Time{},
		)
		for _, chunk := range chunks {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- chunk:
			}
		}
	}

	return nil
}

func (g *Git) scanHistory( //nolint:gocognit
	ctx context.Context,
	repo *git.Repository,
	out chan<- types.Chunk,
) error {
	ref, err := g.resolveRef(repo)
	if err != nil {
		return err
	}

	logOpts := &git.LogOptions{
		From:  ref.Hash(),
		Order: git.LogOrderCommitterTime,
	}

	if g.Since != "" {
		sinceTime, parseErr := time.Parse("2006-01-02", g.Since)
		if parseErr == nil {
			logOpts.Since = &sinceTime
		}
	}

	iter, err := repo.Log(logOpts)
	if err != nil {
		return fmt.Errorf("git log: %w", err)
	}
	defer iter.Close()

	count := 0
	return iter.ForEach(func(c *object.Commit) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if g.Depth > 0 && count >= g.Depth {
			return storer.ErrStop
		}
		count++

		tree, treeErr := c.Tree()
		if treeErr != nil {
			return nil //nolint:nilerr
		}

		return tree.Files().ForEach(func(f *object.File) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			if g.isExcluded(f.Name) || isBinaryExt(f.Name) {
				return nil
			}

			if f.Size > g.MaxSize {
				return nil
			}

			isBin, binErr := f.IsBinary()
			if binErr != nil || isBin {
				return nil //nolint:nilerr
			}

			content, readErr := f.Contents()
			if readErr != nil {
				return nil //nolint:nilerr
			}

			author := ""
			if c.Author.Email != "" {
				author = c.Author.Email
			}

			chunks := splitIntoChunks(
				content,
				f.Name,
				c.Hash.String(),
				author,
				c.Author.When,
			)
			for _, chunk := range chunks {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case out <- chunk:
				}
			}

			return nil
		})
	})
}

func (g *Git) resolveRef(
	repo *git.Repository,
) (*plumbing.Reference, error) {
	if g.Branch != "" {
		ref, err := repo.Reference(
			plumbing.NewBranchReferenceName(g.Branch),
			true,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"resolve branch %s: %w", g.Branch, err,
			)
		}
		return ref, nil
	}

	ref, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("resolve HEAD: %w", err)
	}
	return ref, nil
}

func (g *Git) isExcluded(path string) bool {
	for _, pattern := range g.Excludes {
		if matched, _ := filepath.Match( //nolint:errcheck
			pattern, filepath.Base(path),
		); matched {
			return true
		}
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func readBlob(blob *object.Blob) (string, error) {
	reader, err := blob.Reader()
	if err != nil {
		return "", err
	}
	defer reader.Close() //nolint:errcheck

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func splitIntoChunks(
	content string,
	filePath string,
	commitSHA string,
	author string,
	commitDate time.Time,
) []types.Chunk {
	lines := strings.Split(content, "\n")
	var chunks []types.Chunk

	for i := 0; i < len(lines); i += 50 {
		end := i + 50
		if end > len(lines) {
			end = len(lines)
		}

		chunkContent := strings.Join(lines[i:end], "\n")
		if strings.TrimSpace(chunkContent) == "" {
			continue
		}

		chunks = append(chunks, types.Chunk{
			Content:    chunkContent,
			FilePath:   filePath,
			LineStart:  i + 1,
			CommitSHA:  commitSHA,
			Author:     author,
			CommitDate: commitDate,
		})
	}

	return chunks
}
