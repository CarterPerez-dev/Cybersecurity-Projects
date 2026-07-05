// ©AngelaMos | 2026
// enrich.go

package enrich

import (
	"context"
	"time"

	"github.com/CarterPerez-dev/nadezhda/internal/cve"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const secondsPerHour = 3600

type Clients struct {
	NVD  *cve.NVDClient
	KEV  *cve.KEVClient
	EPSS *cve.EPSSClient
}

type Stats struct {
	Total    int
	Enriched int
	NotFound int
	KEVHits  int
	Errors   int
}

func Run(ctx context.Context, st *store.Store, clients Clients, now time.Time, positiveTTLHours, negativeTTLHours int) (Stats, error) {
	positiveTTL := int64(positiveTTLHours) * secondsPerHour
	negativeTTL := int64(negativeTTLHours) * secondsPerHour

	ids, err := st.CVEsNeedingEnrichment(now.Unix(), positiveTTL, negativeTTL)
	if err != nil {
		return Stats{}, err
	}
	if len(ids) == 0 {
		return Stats{}, nil
	}

	catalog, err := clients.KEV.Fetch(ctx)
	if err != nil {
		return Stats{}, err
	}

	epssScores, _ := clients.EPSS.Fetch(ctx, ids)
	if epssScores == nil {
		epssScores = map[string]cve.EPSSScore{}
	}

	stats := Stats{Total: len(ids)}
	for _, id := range ids {
		nvdRes, err := clients.NVD.Fetch(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			stats.Errors++
			continue
		}

		rec := store.CVE{ID: id, EnrichedAt: now.Unix()}
		if nvdRes.Found {
			rec.EnrichStatus = store.EnrichStatusOK
			rec.Description = nvdRes.Description
			rec.CVSSScore = nvdRes.CVSSScore
			rec.CVSSVersion = nvdRes.CVSSVersion
			rec.CVSSSeverity = nvdRes.CVSSSeverity
			rec.CVSSVector = nvdRes.CVSSVector
			rec.CWE = nvdRes.CWE
			rec.NVDPublished = nvdRes.Published
			rec.NVDModified = nvdRes.Modified
		} else {
			rec.EnrichStatus = store.EnrichStatusNotFound
		}

		if entry, ok := catalog.Lookup(id); ok {
			rec.IsKEV = true
			rec.KEVDateAdded = entry.DateAdded
			rec.KEVRansomware = entry.Ransomware
		}

		if score, ok := epssScores[id]; ok {
			epssVal := score.EPSS
			percentileVal := score.Percentile
			rec.EPSS = &epssVal
			rec.EPSSPercentile = &percentileVal
		}

		if err := st.UpdateCVEEnrichment(rec); err != nil {
			stats.Errors++
			continue
		}
		if nvdRes.Found {
			stats.Enriched++
		} else {
			stats.NotFound++
		}
		if rec.IsKEV {
			stats.KEVHits++
		}
	}
	return stats, nil
}
