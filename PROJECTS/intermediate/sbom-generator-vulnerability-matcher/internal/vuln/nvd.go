// ©AngelaMos | 2026
// nvd.go

package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CarterPerez-dev/bomber/internal/config"
	"github.com/CarterPerez-dev/bomber/pkg/types"
)

type NVDClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	mu         sync.Mutex
	lastReq    time.Time
	rateDelay  time.Duration
}

type nvdOption func(*NVDClient)

func WithNVDBaseURL(url string) nvdOption {
	return func(c *NVDClient) {
		c.baseURL = url
	}
}

func WithNVDAPIKey(key string) nvdOption {
	return func(c *NVDClient) {
		c.apiKey = key
		c.rateDelay = config.NVDRateWithKey
	}
}

func NewNVDClient(opts ...nvdOption) *NVDClient {
	c := &NVDClient{
		baseURL:   config.NVDBaseURL,
		rateDelay: config.NVDRateWithoutKey,
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *NVDClient) Source() string {
	return config.NVDSourceName
}

func (c *NVDClient) Query(ctx context.Context, packages []types.Package) ([]types.VulnMatch, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	var allMatches []types.VulnMatch

	for _, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return allMatches, err
		}

		c.rateLimit(ctx)

		matches, err := c.queryPackage(ctx, pkg)
		if err != nil {
			continue
		}
		allMatches = append(allMatches, matches...)
	}

	return allMatches, nil
}

func (c *NVDClient) queryPackage(ctx context.Context, pkg types.Package) ([]types.VulnMatch, error) {
	params := url.Values{}
	params.Set("virtualMatchString", buildCPEString(pkg))

	reqURL := c.baseURL + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create nvd request: %w", err)
	}

	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("nvd api error %d: %s", resp.StatusCode, string(body))
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("decode nvd response: %w", err)
	}

	var matches []types.VulnMatch
	for _, item := range nvdResp.Vulnerabilities {
		cve := item.CVE
		published, _ := time.Parse(time.RFC3339, cve.Published)
		match := types.VulnMatch{
			Package: pkg,
			Vulnerability: types.Vulnerability{
				ID:        cve.ID,
				Summary:   extractDescription(cve.Descriptions),
				Source:    config.NVDSourceName,
				Published: published,
			},
		}

		if len(cve.Metrics.CVSSV31) > 0 {
			metric := cve.Metrics.CVSSV31[0]
			match.Vulnerability.Score = metric.Data.BaseScore
			match.Vulnerability.Severity = types.ParseSeverity(metric.Data.BaseSeverity)
		}

		matches = append(matches, match)
	}

	return matches, nil
}

func buildCPEString(pkg types.Package) string {
	product := pkg.Name
	if idx := strings.LastIndex(product, "/"); idx >= 0 {
		product = product[idx+1:]
	}
	product = strings.ToLower(product)

	version := strings.TrimPrefix(pkg.Version, "v")
	if version == "" {
		version = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", product, version)
}

func (c *NVDClient) rateLimit(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elapsed := time.Since(c.lastReq)
	if elapsed < c.rateDelay {
		wait := c.rateDelay - elapsed
		timer := time.NewTimer(wait)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
	c.lastReq = time.Now()
}

type nvdResponse struct {
	Vulnerabilities []nvdVulnItem `json:"vulnerabilities"`
}

type nvdVulnItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSV31 []nvdCVSSV31 `json:"cvssMetricV31"`
}

type nvdCVSSV31 struct {
	Data nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func extractDescription(descs []nvdDescription) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}
