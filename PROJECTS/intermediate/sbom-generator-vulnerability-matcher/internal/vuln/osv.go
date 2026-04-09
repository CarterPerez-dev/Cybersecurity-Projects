// ©AngelaMos | 2026
// osv.go

package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/CarterPerez-dev/bomber/internal/config"
	"github.com/CarterPerez-dev/bomber/pkg/types"
)

type OSVClient struct {
	baseURL    string
	httpClient *http.Client
}

type osvOption func(*OSVClient)

func WithOSVBaseURL(url string) osvOption {
	return func(c *OSVClient) {
		c.baseURL = url
	}
}

func NewOSVClient(opts ...osvOption) *OSVClient {
	c := &OSVClient{
		baseURL: config.OSVBaseURL,
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *OSVClient) Source() string {
	return config.OSVSourceName
}

func (c *OSVClient) Query(ctx context.Context, packages []types.Package) ([]types.VulnMatch, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	var allMatches []types.VulnMatch

	for i := 0; i < len(packages); i += config.OSVBatchSize {
		if err := ctx.Err(); err != nil {
			return allMatches, err
		}

		end := i + config.OSVBatchSize
		if end > len(packages) {
			end = len(packages)
		}
		batch := packages[i:end]

		matches, err := c.queryBatch(ctx, batch)
		if err != nil {
			return allMatches, fmt.Errorf("osv batch query: %w", err)
		}
		allMatches = append(allMatches, matches...)
	}

	return allMatches, nil
}

func (c *OSVClient) queryBatch(ctx context.Context, packages []types.Package) ([]types.VulnMatch, error) {
	queries := make([]osvQuery, len(packages))
	for i, pkg := range packages {
		queries[i] = osvQuery{
			Package: osvQueryPackage{
				PURL: pkg.PURL,
			},
		}
	}

	reqBody := osvBatchRequest{Queries: queries}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + "/v1/querybatch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv api error %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var matches []types.VulnMatch
	for i, result := range batchResp.Results {
		if i >= len(packages) {
			break
		}
		pkg := packages[i]
		for _, v := range result.Vulns {
			published, _ := time.Parse(time.RFC3339, v.Published)
			match := types.VulnMatch{
				Package: pkg,
				Vulnerability: types.Vulnerability{
					ID:        v.ID,
					Aliases:   v.Aliases,
					Summary:   v.Summary,
					Source:    config.OSVSourceName,
					Severity:  parseSeverityFromOSV(v),
					Score:     parseScoreFromOSV(v),
					Published: published,
				},
			}

			if len(v.Affected) > 0 && len(v.Affected[0].Ranges) > 0 {
				r := v.Affected[0].Ranges[0]
				match.Vulnerability.AffectedRange = formatRange(r.Events)
				match.Vulnerability.FixVersion = extractFixVersion(r.Events)
			}

			matches = append(matches, match)
		}
	}

	return matches, nil
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvQueryPackage `json:"package"`
}

type osvQueryPackage struct {
	PURL string `json:"purl"`
}

type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string        `json:"id"`
	Summary   string        `json:"summary"`
	Published string        `json:"published"`
	Aliases   []string      `json:"aliases"`
	Severity  []osvSeverity `json:"severity"`
	Affected  []osvAffected `json:"affected"`
	DBSpec    struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

func parseSeverityFromOSV(v osvVuln) types.Severity {
	if v.DBSpec.Severity != "" {
		return types.ParseSeverity(v.DBSpec.Severity)
	}

	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			score := parseCVSSScore(s.Score)
			return scoreToSeverity(score)
		}
	}

	return types.SeverityNone
}

func parseScoreFromOSV(v osvVuln) float64 {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			return parseCVSSScore(s.Score)
		}
	}
	return 0
}

func scoreToSeverity(score float64) types.Severity {
	switch {
	case score >= 9.0:
		return types.SeverityCritical
	case score >= 7.0:
		return types.SeverityHigh
	case score >= 4.0:
		return types.SeverityMedium
	case score > 0:
		return types.SeverityLow
	default:
		return types.SeverityNone
	}
}

func formatRange(events []osvEvent) string {
	var parts []string
	for _, e := range events {
		if e.Introduced != "" {
			parts = append(parts, ">= "+e.Introduced)
		}
		if e.Fixed != "" {
			parts = append(parts, "< "+e.Fixed)
		}
	}
	return strings.Join(parts, ", ")
}

func extractFixVersion(events []osvEvent) string {
	for _, e := range events {
		if e.Fixed != "" {
			return e.Fixed
		}
	}
	return ""
}
