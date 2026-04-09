// ©AngelaMos | 2026
// graph_test.go

package graph

import (
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestGraph() *types.DependencyGraph {
	root := types.Package{Name: "root", PURL: "pkg:test/root@1.0.0"}
	g := types.NewDependencyGraph(root)

	a := types.Package{Name: "a", PURL: "pkg:test/a@1.0.0", Direct: true, DepthLevel: 1}
	b := types.Package{Name: "b", PURL: "pkg:test/b@1.0.0", Direct: true, DepthLevel: 1}
	c := types.Package{Name: "c", PURL: "pkg:test/c@1.0.0", Direct: false, DepthLevel: 2}

	g.AddPackage(a)
	g.AddPackage(b)
	g.AddPackage(c)
	g.AddEdge(root.PURL, a.PURL)
	g.AddEdge(root.PURL, b.PURL)
	g.AddEdge(a.PURL, c.PURL)
	g.AddEdge(b.PURL, c.PURL)

	return g
}

func TestAllPackages(t *testing.T) {
	g := makeTestGraph()
	pkgs := AllPackages(g)
	assert.Len(t, pkgs, 4)
}

func TestDirectPackages(t *testing.T) {
	g := makeTestGraph()
	pkgs := DirectPackages(g)
	assert.Len(t, pkgs, 2)
}

func TestTransitivePackages(t *testing.T) {
	g := makeTestGraph()
	pkgs := TransitivePackages(g)
	assert.Len(t, pkgs, 1)
}

func TestMaxDepth(t *testing.T) {
	g := makeTestGraph()
	assert.Equal(t, 2, MaxDepth(g))
}

func TestDetectCyclesNone(t *testing.T) {
	g := makeTestGraph()
	cycles := DetectCycles(g)
	assert.Empty(t, cycles)
}

func TestDetectCyclesFound(t *testing.T) {
	root := types.Package{Name: "root", PURL: "pkg:test/root@1.0.0"}
	g := types.NewDependencyGraph(root)

	a := types.Package{Name: "a", PURL: "pkg:test/a@1.0.0"}
	b := types.Package{Name: "b", PURL: "pkg:test/b@1.0.0"}

	g.AddPackage(a)
	g.AddPackage(b)
	g.AddEdge(root.PURL, a.PURL)
	g.AddEdge(a.PURL, b.PURL)
	g.AddEdge(b.PURL, a.PURL)

	cycles := DetectCycles(g)
	require.NotEmpty(t, cycles)
}

func TestMergeGraphs(t *testing.T) {
	g1 := makeTestGraph()

	root2 := types.Package{Name: "root2", PURL: "pkg:test/root2@1.0.0"}
	g2 := types.NewDependencyGraph(root2)
	d := types.Package{Name: "d", PURL: "pkg:test/d@1.0.0"}
	g2.AddPackage(d)
	g2.AddEdge(root2.PURL, d.PURL)

	merged := MergeGraphs([]*types.DependencyGraph{g1, g2})
	assert.Len(t, AllPackages(merged), 7)
}

func TestMergeGraphsEmpty(t *testing.T) {
	merged := MergeGraphs(nil)
	assert.Equal(t, "merged", merged.Root.Name)
}

func TestMergeGraphsSingle(t *testing.T) {
	g := makeTestGraph()
	merged := MergeGraphs([]*types.DependencyGraph{g})
	assert.Equal(t, g, merged)
}
