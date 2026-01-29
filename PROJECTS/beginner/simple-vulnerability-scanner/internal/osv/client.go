// ©AngelaMos | 2026
// client.go

package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CarterPerez-dev/angela/pkg/types"
	"golang.org/x/sync/errgroup"
)

const (
	batchEndpoint = "https://api.osv.dev/v1/querybatch"
	vulnEndpoint  = "https://api.osv.dev/v1/vulns/"
	userAgent     = "angela/0.1.0 (https://github.com/CarterPerez-dev/angela)"
	maxHydrate    = 15
)

// Client queries the OSV.dev API for known vulnerabilities
type Client struct {
	http *http.Client
}

// NewClient creates an OSV client with sensible defaults
func NewClient() *Client {
	return &Client{
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// PackageQuery identifies a single package+version to check
type PackageQuery struct {
	Name    string
	Version string
}

type batchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Package pkg    `json:"package"`
	Version string `json:"version"`
}

type pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns []vulnRef `json:"vulns"`
}

type vulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type osvVuln struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Aliases          []string       `json:"aliases"`
	Severity         []severity     `json:"severity"`
	Affected         []affected     `json:"affected"`
	References       []reference    `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type affected struct {
	Package pkg   `json:"package"`
	Ranges  []rng `json:"ranges"`
}

type rng struct {
	Type   string  `json:"type"`
	Events []event `json:"events"`
}

type event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ScanPackages checks a list of packages for known vulnerabilities and returns
// per-package results with full vulnerability details. Duplicates caused by
// overlapping CVE/GHSA identifiers are removed.
func (c *Client) ScanPackages(
	ctx context.Context,
	packages []PackageQuery,
) (map[string][]types.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	batch, err := c.queryBatch(ctx, packages)
	if err != nil {
		return nil, fmt.Errorf("osv batch query: %w", err)
	}

	allIDs := collectUniqueIDs(batch)
	if len(allIDs) == 0 {
		return nil, nil
	}

	vulnMap, err := c.hydrateAll(ctx, allIDs)
	if err != nil {
		return nil, fmt.Errorf("osv hydrate: %w", err)
	}

	return buildResults(packages, batch, vulnMap), nil
}

func (c *Client) queryBatch(
	ctx context.Context,
	packages []PackageQuery,
) (*batchResponse, error) {
	queries := make([]query, len(packages))
	for i, p := range packages {
		queries[i] = query{
			Package: pkg{Name: p.Name, Ecosystem: "PyPI"},
			Version: p.Version,
		}
	}

	body, err := json.Marshal(batchRequest{Queries: queries})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, batchEndpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv returned %d", resp.StatusCode)
	}

	var result batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode batch response: %w", err)
	}
	return &result, nil
}

func (c *Client) fetchVuln(
	ctx context.Context,
	id string,
) (*osvVuln, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, vulnEndpoint+id, nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"osv vuln %s returned %d", id, resp.StatusCode,
		)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var v osvVuln
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decode vuln %s: %w", id, err)
	}
	return &v, nil
}

func (c *Client) hydrateAll(
	ctx context.Context,
	ids []string,
) (map[string]*osvVuln, error) {
	var mu sync.Mutex
	result := make(map[string]*osvVuln, len(ids))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxHydrate)

	for _, id := range ids {
		g.Go(func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf(
						"panic hydrating %s: %v", id, r,
					)
				}
			}()

			v, fetchErr := c.fetchVuln(ctx, id)
			if fetchErr != nil {
				return fetchErr
			}
			mu.Lock()
			result[id] = v
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return result, nil
}

func collectUniqueIDs(batch *batchResponse) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, r := range batch.Results {
		for _, v := range r.Vulns {
			if !seen[v.ID] {
				seen[v.ID] = true
				ids = append(ids, v.ID)
			}
		}
	}
	return ids
}

func buildResults(
	packages []PackageQuery,
	batch *batchResponse,
	vulnMap map[string]*osvVuln,
) map[string][]types.Vulnerability {
	results := make(map[string][]types.Vulnerability)

	for i, br := range batch.Results {
		if len(br.Vulns) == 0 {
			continue
		}

		name := packages[i].Name
		seen := make(map[string]bool)

		for _, vr := range br.Vulns {
			ov, ok := vulnMap[vr.ID]
			if !ok {
				continue
			}

			if isDuplicate(ov, seen) {
				continue
			}

			seen[ov.ID] = true
			for _, alias := range ov.Aliases {
				seen[alias] = true
			}

			results[name] = append(results[name], toVulnerability(ov))
		}
	}
	return results
}

func isDuplicate(v *osvVuln, seen map[string]bool) bool {
	if seen[v.ID] {
		return true
	}
	for _, alias := range v.Aliases {
		if seen[alias] {
			return true
		}
	}
	return false
}

func toVulnerability(v *osvVuln) types.Vulnerability {
	return types.Vulnerability{
		ID:       v.ID,
		Aliases:  v.Aliases,
		Summary:  v.Summary,
		Severity: extractSeverity(v),
		FixedIn:  extractFixed(v.Affected),
		Link:     extractLink(v.References),
	}
}

func extractSeverity(v *osvVuln) string {
	for _, s := range v.Severity {
		if s.Type != "CVSS_V3" && s.Type != "CVSS_V4" {
			continue
		}

		if score, err := strconv.ParseFloat(s.Score, 64); err == nil {
			return classifyScore(score)
		}

		if idx := strings.LastIndex(s.Score, "/"); idx >= 0 {
			chunk := s.Score[idx+1:]
			if score, err := strconv.ParseFloat(chunk, 64); err == nil {
				return classifyScore(score)
			}
		}
	}

	if v.DatabaseSpecific != nil {
		if sev, ok := v.DatabaseSpecific["severity"].(string); ok {
			return strings.ToUpper(sev)
		}
	}

	return "UNKNOWN"
}

func classifyScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MODERATE"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func extractFixed(affected []affected) string {
	for _, a := range affected {
		if !strings.EqualFold(a.Package.Ecosystem, "PyPI") {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func extractLink(refs []reference) string {
	for _, r := range refs {
		if r.Type == "ADVISORY" {
			return r.URL
		}
	}
	for _, r := range refs {
		if r.Type == "WEB" || r.Type == "REPORT" {
			return r.URL
		}
	}
	if len(refs) > 0 {
		return refs[0].URL
	}
	return ""
}
