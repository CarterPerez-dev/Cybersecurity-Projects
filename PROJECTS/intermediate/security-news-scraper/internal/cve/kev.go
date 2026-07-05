// ©AngelaMos | 2026
// kev.go

package cve

import (
	"context"
	"net/http"
)

const (
	KEVEndpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	kevRansomwareKnown = "Known"
)

type KEVEntry struct {
	DateAdded  string
	Ransomware bool
}

type KEVCatalog struct {
	Version  string
	Released string
	Entries  map[string]KEVEntry
}

func (c KEVCatalog) Lookup(cveID string) (KEVEntry, bool) {
	e, ok := c.Entries[cveID]
	return e, ok
}

type KEVClient struct {
	http    *http.Client
	baseURL string
}

func NewKEVClient(client *http.Client, baseURL string) *KEVClient {
	return &KEVClient{http: client, baseURL: baseURL}
}

func (c *KEVClient) Fetch(ctx context.Context) (KEVCatalog, error) {
	var raw kevRaw
	if err := getJSON(ctx, c.http, c.baseURL, nil, &raw); err != nil {
		return KEVCatalog{}, err
	}
	entries := make(map[string]KEVEntry, len(raw.Vulnerabilities))
	for _, v := range raw.Vulnerabilities {
		entries[v.CveID] = KEVEntry{
			DateAdded:  v.DateAdded,
			Ransomware: v.KnownRansomwareCampaignUse == kevRansomwareKnown,
		}
	}
	return KEVCatalog{Version: raw.CatalogVersion, Released: raw.DateReleased, Entries: entries}, nil
}

type kevRaw struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}
