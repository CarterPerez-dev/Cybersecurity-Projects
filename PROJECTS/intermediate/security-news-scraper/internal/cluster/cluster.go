// ©AngelaMos | 2026
// cluster.go

package cluster

import (
	"sort"
	"strconv"
	"strings"

	"github.com/CarterPerez-dev/nadezhda/internal/normalize"
)

type Item struct {
	ID       int64
	SourceID int64
	Title    string
	CVEs     []string
	Time     int64
}

type Cluster struct {
	Key         string
	Members     []int64
	SourceCount int
	FirstSeen   int64
	LastSeen    int64
}

type tokenized struct {
	item   Item
	tokens map[string]struct{}
	cves   map[string]struct{}
}

func Compute(items []Item, jaccardThreshold float64, windowSeconds int64) []Cluster {
	n := len(items)
	prepared := make([]tokenized, n)
	for i, it := range items {
		prepared[i] = tokenized{
			item:   it,
			tokens: tokenSet(it.Title),
			cves:   stringSet(it.CVEs),
		}
	}

	uf := newUnionFind(n)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if abs64(prepared[i].item.Time-prepared[j].item.Time) > windowSeconds {
				continue
			}
			sharedCVE := shareAny(prepared[i].cves, prepared[j].cves)
			crossSource := prepared[i].item.SourceID != prepared[j].item.SourceID
			titleMatch := crossSource &&
				jaccard(prepared[i].tokens, prepared[j].tokens) >= jaccardThreshold
			if sharedCVE || titleMatch {
				uf.union(i, j)
			}
		}
	}

	groups := make(map[int][]int)
	for i := 0; i < n; i++ {
		root := uf.find(i)
		groups[root] = append(groups[root], i)
	}

	clusters := make([]Cluster, 0, len(groups))
	for _, members := range groups {
		clusters = append(clusters, buildCluster(prepared, members))
	}
	sort.Slice(clusters, func(a, b int) bool {
		if clusters[a].FirstSeen != clusters[b].FirstSeen {
			return clusters[a].FirstSeen < clusters[b].FirstSeen
		}
		return clusters[a].Members[0] < clusters[b].Members[0]
	})
	return clusters
}

func buildCluster(prepared []tokenized, members []int) Cluster {
	earliest := prepared[members[0]].item
	ids := make([]int64, 0, len(members))
	sources := make(map[int64]struct{}, len(members))
	first := earliest.Time
	last := earliest.Time
	for _, m := range members {
		it := prepared[m].item
		ids = append(ids, it.ID)
		sources[it.SourceID] = struct{}{}
		if it.Time < first {
			first = it.Time
		}
		if it.Time > last {
			last = it.Time
		}
		if it.Time < earliest.Time || (it.Time == earliest.Time && it.ID < earliest.ID) {
			earliest = it
		}
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	return Cluster{
		Key:         strconv.FormatInt(earliest.ID, 10),
		Members:     ids,
		SourceCount: len(sources),
		FirstSeen:   first,
		LastSeen:    last,
	}
}

func tokenSet(title string) map[string]struct{} {
	fields := strings.Fields(normalize.NormalizeTitle(title))
	set := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		set[f] = struct{}{}
	}
	return set
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v != "" {
			set[v] = struct{}{}
		}
	}
	return set
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	small, large := a, b
	if len(small) > len(large) {
		small, large = large, small
	}
	intersection := 0
	for k := range small {
		if _, ok := large[k]; ok {
			intersection++
		}
	}
	union := len(a) + len(b) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func shareAny(a, b map[string]struct{}) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	small, large := a, b
	if len(small) > len(large) {
		small, large = large, small
	}
	for k := range small {
		if _, ok := large[k]; ok {
			return true
		}
	}
	return false
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

type unionFind struct {
	parent []int
	rank   []int
}

func newUnionFind(n int) *unionFind {
	uf := &unionFind{parent: make([]int, n), rank: make([]int, n)}
	for i := range uf.parent {
		uf.parent[i] = i
	}
	return uf
}

func (uf *unionFind) find(x int) int {
	for uf.parent[x] != x {
		uf.parent[x] = uf.parent[uf.parent[x]]
		x = uf.parent[x]
	}
	return x
}

func (uf *unionFind) union(a, b int) {
	ra, rb := uf.find(a), uf.find(b)
	if ra == rb {
		return
	}
	if uf.rank[ra] < uf.rank[rb] {
		ra, rb = rb, ra
	}
	uf.parent[rb] = ra
	if uf.rank[ra] == uf.rank[rb] {
		uf.rank[ra]++
	}
}
