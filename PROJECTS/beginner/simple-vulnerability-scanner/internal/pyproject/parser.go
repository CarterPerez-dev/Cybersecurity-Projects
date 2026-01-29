// ©AngelaMos | 2026
// parser.go

package pyproject

import (
	"fmt"
	"os"
	"strings"

	"github.com/CarterPerez-dev/angela/pkg/types"
	toml "github.com/pelletier/go-toml/v2"
)

type pyProjectFile struct {
	Project struct {
		Name                 string              `toml:"name"`
		Version              string              `toml:"version"`
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
}

// ParseFile reads a pyproject.toml and extracts all dependency declarations
func ParseFile(path string) ([]types.Dependency, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"open %s: file not found (run from your project root)",
				path,
			)
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var proj pyProjectFile
	if err := toml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf(
			"parse %s: invalid TOML syntax: %w", path, err,
		)
	}

	var deps []types.Dependency

	for _, raw := range proj.Project.Dependencies {
		deps = append(deps, ParseDependency(raw, ""))
	}

	for group, entries := range proj.Project.OptionalDependencies {
		for _, raw := range entries {
			deps = append(deps, ParseDependency(raw, group))
		}
	}

	if len(deps) == 0 {
		return nil, fmt.Errorf(
			"%s: no dependencies found in [project.dependencies] or [project.optional-dependencies]",
			path,
		)
	}
	return deps, nil
}

// ParseDependency splits a PEP 508 dependency string into its components
func ParseDependency(raw, group string) types.Dependency {
	dep := types.Dependency{Group: group}
	s := strings.TrimSpace(raw)

	if idx := strings.Index(s, ";"); idx >= 0 {
		dep.Markers = strings.TrimSpace(s[idx+1:])
		s = s[:idx]
	}
	s = strings.TrimSpace(s)

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

// ExtractMinVersion returns the first pinned or lower-bound version from a
// PEP 440 version specifier string. Returns empty if no version is specified.
func ExtractMinVersion(spec string) string {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, ">="):
			return strings.TrimSpace(part[2:])
		case strings.HasPrefix(part, "=="):
			return strings.TrimSuffix(
				strings.TrimSpace(part[2:]),
				".*",
			)
		case strings.HasPrefix(part, "~="):
			return strings.TrimSpace(part[2:])
		}
	}
	return ""
}
