// ©AngelaMos | 2026
// scanner.go

package scanner

import (
	"os"
	"path/filepath"

	"github.com/CarterPerez-dev/bomber/internal/graph"
	"github.com/CarterPerez-dev/bomber/internal/parser"
	"github.com/CarterPerez-dev/bomber/pkg/types"
)

var skipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
	".tox":         true,
	"target":       true,
}

type Scanner struct {
	registry *parser.Registry
}

func New(registry *parser.Registry) *Scanner {
	return &Scanner{registry: registry}
}

func (s *Scanner) Scan(dir string) (*types.ScanResult, error) {
	result := &types.ScanResult{}
	ecosystemSet := make(map[types.Ecosystem]bool)

	dirs := discoverDirs(dir)

	for _, d := range dirs {
		matched := s.registry.Detect(d)
		for _, p := range matched {
			g, err := p.Parse(d)
			if err != nil {
				continue
			}
			result.Graphs = append(result.Graphs, g)
			ecosystemSet[p.Ecosystem()] = true
		}
	}

	for _, g := range result.Graphs {
		all := graph.AllPackages(g)
		result.TotalPkgs += len(all)
		result.DirectPkgs += len(graph.DirectPackages(g))
	}

	for eco := range ecosystemSet {
		result.Ecosystems = append(result.Ecosystems, eco)
	}

	return result, nil
}

func discoverDirs(root string) []string {
	dirs := []string{root}

	entries, err := os.ReadDir(root)
	if err != nil {
		return dirs
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if skipDirs[entry.Name()] {
			continue
		}
		subDir := filepath.Join(root, entry.Name())
		dirs = append(dirs, discoverDirs(subDir)...)
	}

	return dirs
}
