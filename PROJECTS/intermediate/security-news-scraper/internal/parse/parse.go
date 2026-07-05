// ©AngelaMos | 2026
// parse.go

package parse

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
)

type Item struct {
	Title      string
	Link       string
	Summary    string
	Body       string
	Author     string
	Published  time.Time
	Categories []string
}

var timeLayouts = []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, time.RFC3339}

func Feed(r io.Reader) ([]Item, error) {
	feed, err := gofeed.NewParser().Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	items := make([]Item, 0, len(feed.Items))
	for _, it := range feed.Items {
		items = append(items, Item{
			Title:      strings.TrimSpace(it.Title),
			Link:       strings.TrimSpace(it.Link),
			Summary:    it.Description,
			Body:       it.Content,
			Author:     author(it),
			Published:  published(it),
			Categories: it.Categories,
		})
	}
	return items, nil
}

func author(it *gofeed.Item) string {
	if it.Author != nil && it.Author.Name != "" {
		return it.Author.Name
	}
	if len(it.Authors) > 0 {
		return it.Authors[0].Name
	}
	return ""
}

func published(it *gofeed.Item) time.Time {
	if it.PublishedParsed != nil {
		return it.PublishedParsed.UTC()
	}
	if it.UpdatedParsed != nil {
		return it.UpdatedParsed.UTC()
	}
	raw := strings.TrimSpace(it.Published)
	if raw == "" {
		raw = strings.TrimSpace(it.Updated)
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
