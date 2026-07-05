// ©AngelaMos | 2026
// epss.go

package cve

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/time/rate"
)

const (
	EPSSEndpoint = "https://api.first.org/data/v1/epss"

	epssBatchSize = 100
	epssRate      = 5
)

type EPSSScore struct {
	EPSS       float64
	Percentile float64
}

type EPSSClient struct {
	http    *http.Client
	baseURL string
	limiter *rate.Limiter
}

func NewEPSSClient(client *http.Client, baseURL string) *EPSSClient {
	return &EPSSClient{
		http:    client,
		baseURL: baseURL,
		limiter: rate.NewLimiter(rate.Limit(epssRate), 1),
	}
}

func (c *EPSSClient) Fetch(ctx context.Context, cveIDs []string) (map[string]EPSSScore, error) {
	out := make(map[string]EPSSScore, len(cveIDs))
	for _, batch := range chunk(cveIDs, epssBatchSize) {
		if err := c.limiter.Wait(ctx); err != nil {
			return out, err
		}
		endpoint := c.baseURL + "?" + url.Values{"cve": {strings.Join(batch, ",")}}.Encode()
		var raw epssRaw
		if err := getJSON(ctx, c.http, endpoint, nil, &raw); err != nil {
			return out, err
		}
		for _, d := range raw.Data {
			epss, err1 := strconv.ParseFloat(d.EPSS, 64)
			percentile, err2 := strconv.ParseFloat(d.Percentile, 64)
			if err1 != nil || err2 != nil {
				continue
			}
			out[d.CVE] = EPSSScore{EPSS: epss, Percentile: percentile}
		}
	}
	return out, nil
}

func chunk(ids []string, size int) [][]string {
	var out [][]string
	for i := 0; i < len(ids); i += size {
		end := i + size
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, ids[i:end])
	}
	return out
}

type epssRaw struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}
