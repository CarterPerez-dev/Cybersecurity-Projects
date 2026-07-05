// ©AngelaMos | 2026
// cluster_test.go

package cluster

import (
	"sort"
	"testing"
)

const bigWindow = 1 << 40

func sizes(clusters []Cluster) []int {
	out := make([]int, len(clusters))
	for i, c := range clusters {
		out[i] = len(c.Members)
	}
	sort.Ints(out)
	return out
}

func findCluster(clusters []Cluster, id int64) Cluster {
	for _, c := range clusters {
		for _, m := range c.Members {
			if m == id {
				return c
			}
		}
	}
	return Cluster{}
}

func TestComputeTitleSimilarityGroups(t *testing.T) {
	items := []Item{
		{ID: 1, SourceID: 1, Title: "Acme Corp data breach exposes millions", Time: 100},
		{ID: 2, SourceID: 2, Title: "Acme Corp data breach exposed millions", Time: 200},
		{ID: 3, SourceID: 3, Title: "Acme Corp data breach hits millions", Time: 300},
		{ID: 4, SourceID: 4, Title: "Linux kernel 7 released with new scheduler", Time: 400},
	}
	clusters := Compute(items, 0.6, bigWindow)

	if got := sizes(clusters); len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("cluster sizes = %v, want [1 3]", got)
	}
	c := findCluster(clusters, 1)
	if len(c.Members) != 3 {
		t.Errorf("article 1 cluster size = %d, want 3", len(c.Members))
	}
	if c.SourceCount != 3 {
		t.Errorf("SourceCount = %d, want 3 (three distinct outlets)", c.SourceCount)
	}
	if c.Key != "1" {
		t.Errorf("cluster key = %q, want 1 (earliest article)", c.Key)
	}
	if c.FirstSeen != 100 || c.LastSeen != 300 {
		t.Errorf("span = [%d,%d], want [100,300]", c.FirstSeen, c.LastSeen)
	}
}

func TestComputeSameSourceTitlesDoNotMerge(t *testing.T) {
	items := []Item{
		{ID: 1, SourceID: 1, Title: "CISA Adds One Known Exploited Vulnerability to Catalog", Time: 100},
		{ID: 2, SourceID: 1, Title: "CISA Adds One Known Exploited Vulnerability to Catalog", Time: 200},
	}
	if got := sizes(Compute(items, 0.6, bigWindow)); len(got) != 2 {
		t.Errorf("same-source identical titles sizes = %v, want [1 1] (clustering is cross-outlet)", got)
	}
}

func TestComputeSharedCVEJoinsRegardlessOfSource(t *testing.T) {
	items := []Item{
		{ID: 1, SourceID: 1, Title: "Router vendor patches critical flaw", Time: 100, CVEs: []string{"CVE-2026-1111"}},
		{ID: 2, SourceID: 1, Title: "Enterprise gear gets emergency update", Time: 200, CVEs: []string{"CVE-2026-1111"}},
		{ID: 3, SourceID: 2, Title: "Totally unrelated privacy story", Time: 300, CVEs: []string{"CVE-2026-9999"}},
	}
	clusters := Compute(items, 0.6, bigWindow)
	if got := sizes(clusters); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("cluster sizes = %v, want [1 2]", got)
	}
	joined := findCluster(clusters, 1)
	if len(joined.Members) != 2 {
		t.Error("shared-CVE articles should join even from the same source")
	}
	if joined.SourceCount != 1 {
		t.Errorf("SourceCount = %d, want 1 (a same-source cluster is NOT multi-source)", joined.SourceCount)
	}
}

func TestComputeThresholdBoundary(t *testing.T) {
	items := []Item{
		{ID: 1, SourceID: 1, Title: "alpha bravo charlie delta", Time: 100},
		{ID: 2, SourceID: 2, Title: "alpha bravo charlie echo", Time: 200},
	}
	if got := sizes(Compute(items, 0.6, bigWindow)); len(got) != 1 || got[0] != 2 {
		t.Errorf("at threshold 0.6 (jaccard==0.6) sizes = %v, want [2] (>= joins)", got)
	}
	if got := sizes(Compute(items, 0.61, bigWindow)); len(got) != 2 {
		t.Errorf("at threshold 0.61 sizes = %v, want [1 1] (below threshold)", got)
	}
}

func TestComputeWindowSeparates(t *testing.T) {
	items := []Item{
		{ID: 1, SourceID: 1, Title: "identical breaking headline text", Time: 0},
		{ID: 2, SourceID: 2, Title: "identical breaking headline text", Time: 200},
	}
	if got := sizes(Compute(items, 0.6, 100)); len(got) != 2 {
		t.Errorf("outside window sizes = %v, want [1 1] (time gap > window)", got)
	}
	if got := sizes(Compute(items, 0.6, 300)); len(got) != 1 || got[0] != 2 {
		t.Errorf("inside window sizes = %v, want [2]", got)
	}
}

func TestComputeKeyIsEarliestByTime(t *testing.T) {
	items := []Item{
		{ID: 10, SourceID: 1, Title: "shared story about the incident", Time: 500},
		{ID: 20, SourceID: 2, Title: "shared story about the incident", Time: 100},
	}
	clusters := Compute(items, 0.6, bigWindow)
	if len(clusters) != 1 {
		t.Fatalf("clusters = %d, want 1", len(clusters))
	}
	if clusters[0].Key != "20" {
		t.Errorf("key = %q, want 20 (earliest by time, not lowest id)", clusters[0].Key)
	}
	if clusters[0].FirstSeen != 100 || clusters[0].LastSeen != 500 {
		t.Errorf("span = [%d,%d], want [100,500]", clusters[0].FirstSeen, clusters[0].LastSeen)
	}
}

func TestComputeTransitiveChain(t *testing.T) {
	items := []Item{
		{ID: 1, SourceID: 1, Title: "one two three four five", Time: 100},
		{ID: 2, SourceID: 2, Title: "one two three four six", Time: 100},
		{ID: 3, SourceID: 3, Title: "one two three six five", Time: 100},
	}
	clusters := Compute(items, 0.6, bigWindow)
	if len(clusters) != 1 || len(clusters[0].Members) != 3 {
		t.Errorf("transitive similarity should merge all three, got %d clusters", len(clusters))
	}
}

func TestComputeEmpty(t *testing.T) {
	if c := Compute(nil, 0.6, bigWindow); len(c) != 0 {
		t.Errorf("empty input -> %d clusters, want 0", len(c))
	}
}
