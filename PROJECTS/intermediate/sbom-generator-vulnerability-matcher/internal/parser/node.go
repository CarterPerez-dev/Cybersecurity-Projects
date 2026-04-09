// ©AngelaMos | 2026
// node.go

package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"gopkg.in/yaml.v3"
)

var nodeSemverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

type NodeParser struct{}

func NewNodeParser() *NodeParser {
	return &NodeParser{}
}

func (p *NodeParser) Ecosystem() types.Ecosystem {
	return types.EcosystemNode
}

func (p *NodeParser) Detect(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "package.json"))
	return err == nil
}

func (p *NodeParser) Parse(dir string) (*types.DependencyGraph, error) {
	pkgPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}

	root := types.Package{
		Name:      pkg.Name,
		Version:   pkg.Version,
		Ecosystem: types.EcosystemNode,
		PURL:      fmt.Sprintf("pkg:npm/%s@%s", encodePURLName(pkg.Name), pkg.Version),
		Direct:    true,
	}
	graph := types.NewDependencyGraph(root)

	directNames := make(map[string]bool)
	for name := range pkg.Dependencies {
		directNames[name] = true
	}
	for name := range pkg.DevDependencies {
		directNames[name] = true
	}

	lockPath := filepath.Join(dir, "pnpm-lock.yaml")
	lockData, err := os.ReadFile(lockPath)
	if err == nil {
		parsePnpmLock(lockData, graph, root.PURL, directNames)
	} else {
		parseFromPackageJSON(pkg, graph, root.PURL)
	}

	return graph, nil
}

type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type pnpmLockfile struct {
	Packages  map[string]pnpmPackage  `yaml:"packages"`
	Snapshots map[string]pnpmSnapshot `yaml:"snapshots"`
}

type pnpmPackage struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}

type pnpmSnapshot struct {
	Dependencies map[string]string `yaml:"dependencies"`
}

func parsePnpmLock(
	data []byte,
	graph *types.DependencyGraph,
	rootPURL string,
	directNames map[string]bool,
) {
	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return
	}

	for key, pkgEntry := range lock.Packages {
		name, version := splitPnpmKey(key)
		if name == "" {
			continue
		}

		isDirect := directNames[name]
		depth := 2
		if isDirect {
			depth = 1
		}

		purl := fmt.Sprintf("pkg:npm/%s@%s", encodePURLName(name), version)
		pkg := types.Package{
			Name:       name,
			Version:    version,
			Ecosystem:  types.EcosystemNode,
			PURL:       purl,
			Direct:     isDirect,
			DepthLevel: depth,
		}

		if pkgEntry.Resolution.Integrity != "" {
			pkg.Checksums = append(pkg.Checksums, types.Checksum{
				Algorithm: "SHA-512",
				Value:     pkgEntry.Resolution.Integrity,
			})
		}

		graph.AddPackage(pkg)
		if isDirect {
			graph.AddEdge(rootPURL, purl)
		}
	}

	for key, snap := range lock.Snapshots {
		parentName, parentVersion := splitPnpmKey(key)
		parentPURL := fmt.Sprintf("pkg:npm/%s@%s", encodePURLName(parentName), parentVersion)
		for depName, depVersion := range snap.Dependencies {
			childPURL := fmt.Sprintf("pkg:npm/%s@%s", encodePURLName(depName), depVersion)
			graph.AddEdge(parentPURL, childPURL)
		}
	}
}

func parseFromPackageJSON(
	pkg packageJSON,
	graph *types.DependencyGraph,
	rootPURL string,
) {
	for name, version := range pkg.Dependencies {
		cleanVersion := cleanNodeVersion(version)
		purl := fmt.Sprintf("pkg:npm/%s@%s", encodePURLName(name), cleanVersion)
		dep := types.Package{
			Name:       name,
			Version:    cleanVersion,
			Ecosystem:  types.EcosystemNode,
			PURL:       purl,
			Direct:     true,
			DepthLevel: 1,
		}
		graph.AddPackage(dep)
		graph.AddEdge(rootPURL, purl)
	}
	for name, version := range pkg.DevDependencies {
		cleanVersion := cleanNodeVersion(version)
		purl := fmt.Sprintf("pkg:npm/%s@%s", encodePURLName(name), cleanVersion)
		dep := types.Package{
			Name:       name,
			Version:    cleanVersion,
			Ecosystem:  types.EcosystemNode,
			PURL:       purl,
			Direct:     true,
			DepthLevel: 1,
		}
		graph.AddPackage(dep)
		graph.AddEdge(rootPURL, purl)
	}
}

func splitPnpmKey(key string) (string, string) {
	atIdx := strings.LastIndex(key, "@")
	if atIdx <= 0 {
		return "", ""
	}
	return key[:atIdx], key[atIdx+1:]
}

func cleanNodeVersion(constraint string) string {
	match := nodeSemverRe.FindString(constraint)
	if match != "" {
		return match
	}
	return strings.TrimLeft(constraint, "^~>=< ")
}

func encodePURLName(name string) string {
	if strings.HasPrefix(name, "@") {
		return strings.Replace(name, "@", "%40", 1)
	}
	return name
}
