// ©AngelaMos | 2026
// parse_test.go

package parse

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const feedsDir = "../../testdata/feeds"

func loadFeed(t *testing.T, name string) []Item {
	t.Helper()
	f, err := os.Open(filepath.Join(feedsDir, name))
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	items, err := Feed(f)
	if err != nil {
		t.Fatalf("Feed(%s): %v", name, err)
	}
	return items
}

func TestFeedGolden(t *testing.T) {
	cases := []struct {
		file      string
		wantItems int
		fullBody  bool
	}{
		{"krebs.xml", 3, true},
		{"theregister.xml", 3, true},
		{"thehackernews.xml", 3, false},
		{"bleepingcomputer.xml", 3, false},
		{"securityweek.xml", 3, false},
		{"darkreading.xml", 3, false},
		{"cisa.xml", 3, false},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			items := loadFeed(t, tc.file)
			if len(items) != tc.wantItems {
				t.Fatalf("items = %d, want %d", len(items), tc.wantItems)
			}
			for i, it := range items {
				if it.Title == "" {
					t.Errorf("item %d: empty title", i)
				}
				if it.Link == "" {
					t.Errorf("item %d: empty link", i)
				}
				if it.Published.IsZero() {
					t.Errorf("item %d (%q): published time did not parse", i, it.Title)
				}
				if tc.fullBody && it.Body == "" {
					t.Errorf("item %d (%q): expected full body, got empty", i, it.Title)
				}
			}
		})
	}
}

func TestFeedExactPublishedTime(t *testing.T) {
	cases := []struct {
		file string
		raw  string
	}{
		{"thehackernews.xml", "Sat, 04 Jul 2026 18:17:53 +0530"},
		{"krebs.xml", "Thu, 02 Jul 2026 19:27:33 +0000"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			want, err := time.Parse(time.RFC1123Z, tc.raw)
			if err != nil {
				t.Fatalf("parse expected time: %v", err)
			}
			items := loadFeed(t, tc.file)
			if !items[0].Published.Equal(want) {
				t.Errorf("published = %s, want %s", items[0].Published, want.UTC())
			}
		})
	}
}

func TestFeedExactTitles(t *testing.T) {
	cases := []struct {
		file  string
		title string
	}{
		{"krebs.xml", "FBI Seizes NetNut Proxy Platform, Popa Botnet"},
		{"thehackernews.xml", "U.S. Government Entity Paid Kairos $1 Million in Data-Theft Extortion Case"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			items := loadFeed(t, tc.file)
			if items[0].Title != tc.title {
				t.Errorf("first title = %q, want %q", items[0].Title, tc.title)
			}
		})
	}
}
