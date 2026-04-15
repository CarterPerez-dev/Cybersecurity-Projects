/*
©AngelaMos | 2026
scanner.go

Scanner registry that collects and runs all persistence scanners

Maintains an ordered slice of scanners registered at init time.
RunAll iterates each scanner in parallel using errgroup, collects
findings under a mutex, and returns the merged result set. Each
scanner module calls Register in its init function to add itself.
*/

package scanner

import (
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

var registry []types.Scanner

func Register(s types.Scanner) {
	registry = append(registry, s)
}

func All() []types.Scanner {
	return registry
}

func RunAll(root string) []types.Finding {
	var (
		mu  sync.Mutex
		all []types.Finding
		g   errgroup.Group
	)

	slog.Debug(
		"starting scan",
		"root", root,
		"scanners", len(registry),
	)

	for _, s := range registry {
		g.Go(func() error {
			slog.Debug(
				"scanner started", "name", s.Name(),
			)
			results := s.Scan(root)
			slog.Debug(
				"scanner finished",
				"name", s.Name(),
				"findings", len(results),
			)
			mu.Lock()
			all = append(all, results...)
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait() //nolint:errcheck

	slog.Debug(
		"scan complete", "total_findings", len(all),
	)
	return all
}
