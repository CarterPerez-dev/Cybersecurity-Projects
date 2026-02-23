// ©AngelaMos | 2026
// pipeline.go

package engine

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/CarterPerez-dev/portia/internal/rules"
	"github.com/CarterPerez-dev/portia/internal/source"
	"github.com/CarterPerez-dev/portia/internal/ui"
	"github.com/CarterPerez-dev/portia/pkg/types"
)

type Pipeline struct {
	registry *rules.Registry
	detector *Detector
	workers  int
	verbose  bool
}

func NewPipeline(reg *rules.Registry) *Pipeline {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	if workers > 16 {
		workers = 16
	}

	return &Pipeline{
		registry: reg,
		detector: NewDetector(reg),
		workers:  workers,
	}
}

func (p *Pipeline) SetVerbose(v bool) {
	p.verbose = v
}

func (p *Pipeline) Run( //nolint:gocognit
	ctx context.Context, src source.Source,
) (*types.ScanResult, error) {
	chunks := make(chan types.Chunk, p.workers*4)
	findingsCh := make(chan types.Finding, p.workers*4)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(chunks)
		return src.Chunks(gctx, chunks)
	})

	var detectWg sync.WaitGroup
	var seenFiles sync.Map
	var filesScanned atomic.Int64

	for range p.workers {
		detectWg.Add(1)
		g.Go(func() error {
			defer detectWg.Done()
			for chunk := range chunks {
				if gctx.Err() != nil {
					return gctx.Err()
				}

				if _, loaded := seenFiles.LoadOrStore(
					chunk.FilePath,
					true,
				); !loaded {
					filesScanned.Add(1)
					if p.verbose {
						fmt.Printf("  %s %s\n",
							ui.Dim("scanning"),
							ui.Dim(chunk.FilePath))
					}
				}

				results := p.detector.Detect(chunk)
				for _, f := range results {
					select {
					case <-gctx.Done():
						return gctx.Err()
					case findingsCh <- f:
					}
				}
			}
			return nil
		})
	}

	go func() {
		detectWg.Wait()
		close(findingsCh)
	}()

	var mu sync.Mutex
	var allFindings []types.Finding

	g.Go(func() error {
		for f := range findingsCh {
			mu.Lock()
			allFindings = append(allFindings, f)
			mu.Unlock()
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	totalFiles := int(filesScanned.Load())

	result := &types.ScanResult{
		Findings:      dedup(allFindings),
		TotalFiles:    totalFiles,
		TotalRules:    p.registry.Len(),
		TotalFindings: len(allFindings),
	}

	return result, nil
}

func dedup(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	var unique []types.Finding

	for _, f := range findings {
		key := f.RuleID + "|" + f.FilePath + "|" +
			f.Secret + "|" + f.CommitSHA
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, f)
	}

	return unique
}
