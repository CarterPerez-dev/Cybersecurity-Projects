// ©AngelaMos | 2026
// ingest.go

package ingest

import (
	"bytes"
	"context"
	"errors"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/CarterPerez-dev/nadezhda/internal/config"
	"github.com/CarterPerez-dev/nadezhda/internal/cve"
	"github.com/CarterPerez-dev/nadezhda/internal/fetch"
	"github.com/CarterPerez-dev/nadezhda/internal/normalize"
	"github.com/CarterPerez-dev/nadezhda/internal/parse"
	"github.com/CarterPerez-dev/nadezhda/internal/source"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

type SourceResult struct {
	Name        string
	Parsed      int
	New         int
	Duplicates  int
	CVEs        int
	ItemErrors  int
	NotModified bool
	Err         error
}

type Summary struct {
	Results []SourceResult
}

func (s Summary) Totals() (newArticles, duplicates, failed int) {
	for _, r := range s.Results {
		newArticles += r.New
		duplicates += r.Duplicates
		if r.Err != nil {
			failed++
		}
	}
	return newArticles, duplicates, failed
}

func Run(ctx context.Context, fc *fetch.Client, st *store.Store, cfg config.Config, targets []source.Source, now time.Time) (Summary, error) {
	results := make([]SourceResult, len(targets))

	workers := cfg.Fetch.Workers
	if workers < 1 {
		workers = 1
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)

	for i, src := range targets {
		results[i].Name = src.Name
		g.Go(func() error {
			process(gctx, fc, st, cfg, src, now, &results[i])
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return Summary{Results: results}, err
	}
	return Summary{Results: results}, nil
}

func process(ctx context.Context, fc *fetch.Client, st *store.Store, cfg config.Config, src source.Source, now time.Time, out *SourceResult) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Fetch.SourceTimeoutSeconds)*time.Second)
	defer cancel()

	id, err := st.UpsertSource(store.SourceInput{
		Name: src.Name, Title: src.Title, URL: src.URL, Type: string(src.Type),
		Weight: src.Weight, Tags: src.Tags, Enabled: src.Enabled,
	})
	if err != nil {
		out.Err = err
		return
	}

	prev, _, err := st.GetFetchState(id)
	if err != nil {
		out.Err = err
		return
	}

	res, err := fc.Fetch(ctx, fetch.Request{
		URL: src.URL, ETag: prev.ETag, LastModified: prev.LastModified,
	})
	if err != nil {
		out.Err = err
		return
	}

	if res.NotModified {
		out.NotModified = true
		out.Err = st.UpsertFetchState(id, store.FetchState{
			ETag: prev.ETag, LastModified: prev.LastModified,
			LastFetched: now.Unix(), LastStatus: int64(res.Status),
		})
		return
	}

	items, err := parse.Feed(bytes.NewReader(res.Body))
	if err != nil {
		out.Err = err
		return
	}
	out.Parsed = len(items)

	for _, it := range items {
		storeItem(st, cfg, id, it, now, out)
	}

	if err := st.UpsertFetchState(id, store.FetchState{
		ETag: res.ETag, LastModified: res.LastModified,
		LastFetched: now.Unix(), LastStatus: int64(res.Status),
	}); err != nil && out.Err == nil {
		out.Err = err
	}
}

func storeItem(st *store.Store, cfg config.Config, sourceID int64, it parse.Item, now time.Time, out *SourceResult) {
	if it.Link == "" {
		out.ItemErrors++
		return
	}
	canonical, err := normalize.CanonicalURL(it.Link, cfg.Cluster.TrackingParams)
	if err != nil {
		out.ItemErrors++
		return
	}

	summary := normalize.StripHTML(it.Summary)
	body := normalize.StripHTML(it.Body)

	var publishedAt int64
	if !it.Published.IsZero() {
		publishedAt = it.Published.Unix()
	}

	id, err := st.InsertArticle(store.Article{
		SourceID:     sourceID,
		CanonicalURL: canonical,
		ContentHash:  normalize.ContentHash(canonical),
		TitleHash:    normalize.TitleHash(normalize.NormalizeTitle(it.Title)),
		Title:        it.Title,
		Summary:      summary,
		Body:         body,
		Author:       it.Author,
		PublishedAt:  publishedAt,
		FetchedAt:    now.Unix(),
	})
	switch {
	case err == nil:
		out.New++
		linkCVEs(st, id, cve.Extract(it.Title, summary, body), out)
	case errors.Is(err, store.ErrDuplicate):
		out.Duplicates++
	default:
		out.ItemErrors++
	}
}

func linkCVEs(st *store.Store, articleID int64, ids []string, out *SourceResult) {
	for _, id := range ids {
		if err := st.UpsertCVEStub(id); err != nil {
			out.ItemErrors++
			continue
		}
		if err := st.LinkArticleCVE(articleID, id); err != nil {
			out.ItemErrors++
			continue
		}
		out.CVEs++
	}
}
