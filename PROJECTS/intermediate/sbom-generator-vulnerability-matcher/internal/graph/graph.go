// ©AngelaMos | 2026
// graph.go

package graph

import "github.com/CarterPerez-dev/bomber/pkg/types"

func AllPackages(g *types.DependencyGraph) []types.Package {
	pkgs := make([]types.Package, 0, len(g.Nodes))
	for _, pkg := range g.Nodes {
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

func DirectPackages(g *types.DependencyGraph) []types.Package {
	var pkgs []types.Package
	for _, pkg := range g.Nodes {
		if pkg.Direct && pkg.PURL != g.Root.PURL {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

func TransitivePackages(g *types.DependencyGraph) []types.Package {
	var pkgs []types.Package
	for _, pkg := range g.Nodes {
		if !pkg.Direct && pkg.PURL != g.Root.PURL {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

func MaxDepth(g *types.DependencyGraph) int {
	maxVal := 0
	for _, pkg := range g.Nodes {
		if pkg.DepthLevel > maxVal {
			maxVal = pkg.DepthLevel
		}
	}
	return maxVal
}

func DetectCycles(g *types.DependencyGraph) [][]string {
	var cycles [][]string
	visited := make(map[string]bool)
	inStack := make(map[string]bool)

	var dfs func(purl string, path []string)
	dfs = func(purl string, path []string) {
		if inStack[purl] {
			for i, p := range path {
				if p == purl {
					cycle := make([]string, len(path)-i)
					copy(cycle, path[i:])
					cycles = append(cycles, cycle)
					return
				}
			}
			return
		}
		if visited[purl] {
			return
		}

		visited[purl] = true
		inStack[purl] = true
		path = append(path, purl)

		for _, child := range g.Edges[purl] {
			dfs(child, path)
		}

		inStack[purl] = false
	}

	for purl := range g.Nodes {
		if !visited[purl] {
			dfs(purl, nil)
		}
	}

	return cycles
}

func MergeGraphs(graphs []*types.DependencyGraph) *types.DependencyGraph {
	if len(graphs) == 0 {
		root := types.Package{Name: "merged", PURL: "pkg:merged/root"}
		return types.NewDependencyGraph(root)
	}
	if len(graphs) == 1 {
		return graphs[0]
	}

	root := types.Package{Name: "merged", PURL: "pkg:merged/root"}
	merged := types.NewDependencyGraph(root)

	for _, g := range graphs {
		for purl, pkg := range g.Nodes {
			merged.Nodes[purl] = pkg
		}
		for parent, children := range g.Edges {
			merged.Edges[parent] = append(merged.Edges[parent], children...)
		}
		merged.AddEdge(root.PURL, g.Root.PURL)
	}

	return merged
}
