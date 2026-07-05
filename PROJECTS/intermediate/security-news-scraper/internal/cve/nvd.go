// ©AngelaMos | 2026
// nvd.go

package cve

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/time/rate"
)

const (
	NVDEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	nvdAPIKeyHeader = "apiKey"
	nvdRateNoKey    = 5.0 / 30.0
	nvdRateWithKey  = 50.0 / 30.0
	nvdMaxRetries   = 3
	nvdBackoffBase  = 2 * time.Second
	langEnglish     = "en"
)

type NVDResult struct {
	Found        bool
	Description  string
	CVSSScore    *float64
	CVSSVersion  string
	CVSSSeverity string
	CVSSVector   string
	CWE          string
	Published    string
	Modified     string
}

type NVDClient struct {
	http        *http.Client
	baseURL     string
	apiKey      string
	limiter     *rate.Limiter
	backoffBase time.Duration
}

func NewNVDClient(client *http.Client, baseURL, apiKey string) *NVDClient {
	limit := nvdRateNoKey
	if apiKey != "" {
		limit = nvdRateWithKey
	}
	return &NVDClient{
		http:        client,
		baseURL:     baseURL,
		apiKey:      apiKey,
		limiter:     rate.NewLimiter(rate.Limit(limit), 1),
		backoffBase: nvdBackoffBase,
	}
}

func (c *NVDClient) Fetch(ctx context.Context, cveID string) (NVDResult, error) {
	endpoint := c.baseURL + "?" + url.Values{"cveId": {cveID}}.Encode()
	header := http.Header{}
	if c.apiKey != "" {
		header[nvdAPIKeyHeader] = []string{c.apiKey}
	}

	var env nvdEnvelope
	for attempt := 0; attempt <= nvdMaxRetries; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, c.backoffBase*time.Duration(1<<(attempt-1))); err != nil {
				return NVDResult{}, err
			}
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return NVDResult{}, err
		}
		err := getJSON(ctx, c.http, endpoint, header, &env)
		if err == nil {
			break
		}
		if !retriable(err) || attempt == nvdMaxRetries {
			return NVDResult{}, err
		}
	}

	if env.TotalResults == 0 || len(env.Vulnerabilities) == 0 {
		return NVDResult{Found: false}, nil
	}
	return env.Vulnerabilities[0].CVE.toResult(), nil
}

func retriable(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.code == http.StatusTooManyRequests || se.code >= http.StatusInternalServerError
	}
	return true
}

type nvdEnvelope struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string         `json:"id"`
	Published    string         `json:"published"`
	LastModified string         `json:"lastModified"`
	Descriptions []nvdLangValue `json:"descriptions"`
	Weaknesses   []struct {
		Description []nvdLangValue `json:"description"`
	} `json:"weaknesses"`
	Metrics nvdMetrics `json:"metrics"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	BaseSeverity string      `json:"baseSeverity"`
	CVSSData     nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func (v nvdCVE) toResult() NVDResult {
	res := NVDResult{
		Found:       true,
		Description: english(v.Descriptions),
		Published:   v.Published,
		Modified:    v.LastModified,
	}
	for _, w := range v.Weaknesses {
		if cwe := english(w.Description); cwe != "" {
			res.CWE = cwe
			break
		}
	}
	if m, ok := v.Metrics.selected(); ok {
		score := m.CVSSData.BaseScore
		res.CVSSScore = &score
		res.CVSSVersion = m.CVSSData.Version
		res.CVSSVector = m.CVSSData.VectorString
		res.CVSSSeverity = m.CVSSData.BaseSeverity
		if res.CVSSSeverity == "" {
			res.CVSSSeverity = m.BaseSeverity
		}
	}
	return res
}

func (m nvdMetrics) selected() (nvdMetric, bool) {
	for _, tier := range [][]nvdMetric{m.V40, m.V31, m.V30, m.V2} {
		if len(tier) > 0 {
			return tier[0], true
		}
	}
	return nvdMetric{}, false
}

func english(values []nvdLangValue) string {
	for _, lv := range values {
		if lv.Lang == langEnglish {
			return lv.Value
		}
	}
	return ""
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
