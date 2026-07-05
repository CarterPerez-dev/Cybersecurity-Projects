// ©AngelaMos | 2026
// rebuild.go

package cluster

import (
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

type Stats struct {
	Total       int
	MultiSource int
	LargestSize int
}

func Rebuild(st *store.Store, jaccardThreshold float64, windowSeconds, sinceUnix int64) (Stats, error) {
	candidates, err := st.ClusterCandidates(sinceUnix)
	if err != nil {
		return Stats{}, err
	}
	cveMap, err := st.ArticleCVEMap()
	if err != nil {
		return Stats{}, err
	}

	items := make([]Item, len(candidates))
	for i, c := range candidates {
		items[i] = Item{ID: c.ID, SourceID: c.SourceID, Title: c.Title, Time: c.Time, CVEs: cveMap[c.ID]}
	}

	clusters := Compute(items, jaccardThreshold, windowSeconds)

	rows := make([]store.ClusterRow, len(clusters))
	stats := Stats{Total: len(clusters)}
	for i, c := range clusters {
		rows[i] = store.ClusterRow{
			Key: c.Key, Members: c.Members, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
		}
		if c.SourceCount > 1 {
			stats.MultiSource++
		}
		if size := len(c.Members); size > stats.LargestSize {
			stats.LargestSize = size
		}
	}

	if err := st.ReplaceClusters(rows); err != nil {
		return Stats{}, err
	}
	return stats, nil
}
