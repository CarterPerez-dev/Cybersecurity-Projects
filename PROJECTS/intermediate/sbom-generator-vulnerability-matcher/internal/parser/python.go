// ©AngelaMos | 2026
// python.go

package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/pelletier/go-toml/v2"
)

type PythonParser struct{}

func NewPythonParser() *PythonParser {
	return &PythonParser{}
}

func (p *PythonParser) Ecosystem() types.Ecosystem {
	return types.EcosystemPython
}

func (p *PythonParser) Detect(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "pyproject.toml"))
	return err == nil
}

func (p *PythonParser) Parse(dir string) (*types.DependencyGraph, error) {
	pyPath := filepath.Join(dir, "pyproject.toml")
	data, err := os.ReadFile(pyPath)
	if err != nil {
		return nil, fmt.Errorf("read pyproject.toml: %w", err)
	}

	var proj pyprojectTOML
	if err := toml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("parse pyproject.toml: %w", err)
	}

	root := types.Package{
		Name:      proj.Project.Name,
		Version:   proj.Project.Version,
		Ecosystem: types.EcosystemPython,
		PURL:      fmt.Sprintf("pkg:pypi/%s@%s", proj.Project.Name, proj.Project.Version),
		Direct:    true,
	}
	graph := types.NewDependencyGraph(root)

	directNames := make(map[string]bool)
	for _, dep := range proj.Project.Dependencies {
		name := extractPyPkgName(dep)
		directNames[strings.ToLower(name)] = true
	}
	for _, groups := range proj.DependencyGroups {
		for _, dep := range groups {
			name := extractPyPkgName(dep)
			directNames[strings.ToLower(name)] = true
		}
	}

	lockPath := filepath.Join(dir, "uv.lock")
	lockData, err := os.ReadFile(lockPath)
	if err == nil {
		parseUVLock(lockData, graph, root.PURL, directNames)
	} else {
		parseFromPyproject(proj, graph, root.PURL)
	}

	return graph, nil
}

type pyprojectTOML struct {
	Project struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Dependencies []string `toml:"dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]string `toml:"dependency-groups"`
}

type uvLockfile struct {
	Packages []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name         string         `toml:"name"`
	Version      string         `toml:"version"`
	Source       uvSource       `toml:"source"`
	Dependencies []uvDependency `toml:"dependencies"`
}

type uvSource struct {
	Registry string `toml:"registry"`
	Virtual  string `toml:"virtual"`
}

type uvDependency struct {
	Name string `toml:"name"`
}

func parseUVLock(
	data []byte,
	graph *types.DependencyGraph,
	rootPURL string,
	directNames map[string]bool,
) {
	var lock uvLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return
	}

	purlMap := make(map[string]string)

	for _, pkg := range lock.Packages {
		if pkg.Source.Virtual != "" {
			continue
		}

		normalizedName := strings.ToLower(pkg.Name)
		isDirect := directNames[normalizedName]
		depth := 2
		if isDirect {
			depth = 1
		}

		purl := fmt.Sprintf("pkg:pypi/%s@%s", normalizedName, pkg.Version)
		purlMap[normalizedName] = purl

		dep := types.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Ecosystem:  types.EcosystemPython,
			PURL:       purl,
			Direct:     isDirect,
			DepthLevel: depth,
		}
		graph.AddPackage(dep)

		if isDirect {
			graph.AddEdge(rootPURL, purl)
		}
	}

	for _, pkg := range lock.Packages {
		if pkg.Source.Virtual != "" {
			continue
		}
		parentName := strings.ToLower(pkg.Name)
		parentPURL := purlMap[parentName]
		if parentPURL == "" {
			continue
		}
		for _, dep := range pkg.Dependencies {
			childPURL := purlMap[strings.ToLower(dep.Name)]
			if childPURL != "" {
				graph.AddEdge(parentPURL, childPURL)
			}
		}
	}
}

func parseFromPyproject(
	proj pyprojectTOML,
	graph *types.DependencyGraph,
	rootPURL string,
) {
	for _, dep := range proj.Project.Dependencies {
		name := extractPyPkgName(dep)
		purl := fmt.Sprintf("pkg:pypi/%s", strings.ToLower(name))
		pkg := types.Package{
			Name:       name,
			Ecosystem:  types.EcosystemPython,
			PURL:       purl,
			Direct:     true,
			DepthLevel: 1,
		}
		graph.AddPackage(pkg)
		graph.AddEdge(rootPURL, purl)
	}
}

var pyVersionRe = regexp.MustCompile(`[><=!~;]`)

func extractPyPkgName(spec string) string {
	loc := pyVersionRe.FindStringIndex(spec)
	if loc != nil {
		return strings.TrimSpace(spec[:loc[0]])
	}
	return strings.TrimSpace(spec)
}
