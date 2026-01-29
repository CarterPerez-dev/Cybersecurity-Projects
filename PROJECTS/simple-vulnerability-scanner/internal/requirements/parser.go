// ©AngelaMos | 2026
// parser.go

package requirements

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CarterPerez-dev/angela/pkg/types"
)

// ParseFile reads a requirements.txt and extracts all dependency declarations
func ParseFile(path string) ([]types.Dependency, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"open %s: file not found", path,
			)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck

	var deps []types.Dependency
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" ||
			strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-") {
			continue
		}

		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		dep := parseLine(line)
		if dep.Name != "" {
			deps = append(deps, dep)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if len(deps) == 0 {
		return nil, fmt.Errorf(
			"%s: no dependencies found", path,
		)
	}
	return deps, nil
}

func parseLine(s string) types.Dependency {
	var dep types.Dependency

	if idx := strings.Index(s, ";"); idx >= 0 {
		dep.Markers = strings.TrimSpace(s[idx+1:])
		s = strings.TrimSpace(s[:idx])
	}

	if start := strings.Index(s, "["); start >= 0 {
		end := strings.Index(s, "]")
		if end > start {
			for _, e := range strings.Split(s[start+1:end], ",") {
				dep.Extras = append(
					dep.Extras,
					strings.TrimSpace(e),
				)
			}
			s = s[:start] + s[end+1:]
		}
	}

	if idx := strings.IndexAny(s, "><=!~"); idx >= 0 {
		dep.Name = strings.TrimSpace(s[:idx])
		dep.Spec = strings.TrimSpace(s[idx:])
	} else {
		dep.Name = strings.TrimSpace(s)
	}

	return dep
}
