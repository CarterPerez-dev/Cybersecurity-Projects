// ©AngelaMos | 2026
// cvelist.go

package cve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

const (
	CVEListEndpoint = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"

	cvelistRate       = 15
	cvelistMaxRetries = 2
	cvelistBackoff    = time.Second
	cvelistBucketTail = 3
	cveIDParts        = 3
	langEnPrefix      = "en"

	cvssCriticalMin = 9.0
	cvssHighMin     = 7.0
	cvssMediumMin   = 4.0

	cvssVersion2Prefix = "2"

	sevCritical = "CRITICAL"
	sevHigh     = "HIGH"
	sevMedium   = "MEDIUM"
	sevLow      = "LOW"
	sevNone     = "NONE"
)

type CoreResult struct {
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

type CVESource interface {
	Fetch(ctx context.Context, cveID string) (CoreResult, error)
}

type CVEListClient struct {
	http        *http.Client
	baseURL     string
	limiter     *rate.Limiter
	backoffBase time.Duration
}

func NewCVEListClient(client *http.Client, baseURL string) *CVEListClient {
	return &CVEListClient{
		http:        client,
		baseURL:     strings.TrimRight(baseURL, "/"),
		limiter:     rate.NewLimiter(rate.Limit(cvelistRate), 1),
		backoffBase: cvelistBackoff,
	}
}

func (c *CVEListClient) Fetch(ctx context.Context, cveID string) (CoreResult, error) {
	endpoint, err := c.recordURL(cveID)
	if err != nil {
		return CoreResult{}, err
	}

	var rec cvelistRecord
	for attempt := 0; attempt <= cvelistMaxRetries; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, c.backoffBase*time.Duration(1<<(attempt-1))); err != nil {
				return CoreResult{}, err
			}
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return CoreResult{}, err
		}
		err := getJSON(ctx, c.http, endpoint, nil, &rec)
		if err == nil {
			return rec.toResult(), nil
		}
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return CoreResult{Found: false}, nil
		}
		if !retriable(err) || attempt == cvelistMaxRetries {
			return CoreResult{}, err
		}
	}
	return CoreResult{Found: false}, nil
}

func (c *CVEListClient) recordURL(cveID string) (string, error) {
	parts := strings.Split(cveID, "-")
	if len(parts) != cveIDParts || parts[0] != "CVE" {
		return "", fmt.Errorf("cve: malformed id %q", cveID)
	}
	num := parts[2]
	if len(num) <= cvelistBucketTail {
		return "", fmt.Errorf("cve: short id %q", cveID)
	}
	bucket := num[:len(num)-cvelistBucketTail] + "xxx"
	return fmt.Sprintf("%s/%s/%s/%s.json", c.baseURL, parts[1], bucket, cveID), nil
}

type cvelistRecord struct {
	CVEMetadata struct {
		DatePublished string `json:"datePublished"`
		DateUpdated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cvelistContainer   `json:"cna"`
		ADP []cvelistContainer `json:"adp"`
	} `json:"containers"`
}

type cvelistContainer struct {
	Descriptions []cvelistLangValue `json:"descriptions"`
	ProblemTypes []struct {
		Descriptions []struct {
			Lang  string `json:"lang"`
			CweID string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	Metrics []cvelistMetric `json:"metrics"`
}

type cvelistLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type cvelistMetric struct {
	V40 *cvelistCVSS `json:"cvssV4_0"`
	V31 *cvelistCVSS `json:"cvssV3_1"`
	V30 *cvelistCVSS `json:"cvssV3_0"`
	V2  *cvelistCVSS `json:"cvssV2_0"`
}

type cvelistCVSS struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

func (rec cvelistRecord) containers() []cvelistContainer {
	out := make([]cvelistContainer, 0, len(rec.Containers.ADP)+1)
	out = append(out, rec.Containers.CNA)
	out = append(out, rec.Containers.ADP...)
	return out
}

func (rec cvelistRecord) toResult() CoreResult {
	res := CoreResult{
		Found:       true,
		Description: rec.description(),
		CWE:         rec.cwe(),
		Published:   rec.CVEMetadata.DatePublished,
		Modified:    rec.CVEMetadata.DateUpdated,
	}
	if cv := rec.cvss(); cv != nil {
		score := cv.BaseScore
		res.CVSSScore = &score
		res.CVSSVersion = cv.Version
		res.CVSSVector = cv.VectorString
		res.CVSSSeverity = cv.BaseSeverity
		if res.CVSSSeverity == "" {
			res.CVSSSeverity = severityFromScore(score, cv.Version)
		}
	}
	return res
}

func (rec cvelistRecord) cvss() *cvelistCVSS {
	tiers := []func(cvelistMetric) *cvelistCVSS{
		func(m cvelistMetric) *cvelistCVSS { return m.V40 },
		func(m cvelistMetric) *cvelistCVSS { return m.V31 },
		func(m cvelistMetric) *cvelistCVSS { return m.V30 },
		func(m cvelistMetric) *cvelistCVSS { return m.V2 },
	}
	containers := rec.containers()
	for _, pick := range tiers {
		for _, c := range containers {
			for _, m := range c.Metrics {
				if cv := pick(m); cv != nil {
					return cv
				}
			}
		}
	}
	return nil
}

func (rec cvelistRecord) cwe() string {
	for _, c := range rec.containers() {
		for _, pt := range c.ProblemTypes {
			for _, d := range pt.Descriptions {
				if d.CweID != "" {
					return d.CweID
				}
			}
		}
	}
	return ""
}

func (rec cvelistRecord) description() string {
	for _, c := range rec.containers() {
		for _, d := range c.Descriptions {
			if strings.HasPrefix(d.Lang, langEnPrefix) && strings.TrimSpace(d.Value) != "" {
				return d.Value
			}
		}
	}
	for _, c := range rec.containers() {
		for _, d := range c.Descriptions {
			if strings.TrimSpace(d.Value) != "" {
				return d.Value
			}
		}
	}
	return ""
}

func severityFromScore(score float64, version string) string {
	switch {
	case score <= 0:
		return sevNone
	case score >= cvssCriticalMin && !strings.HasPrefix(version, cvssVersion2Prefix):
		return sevCritical
	case score >= cvssHighMin:
		return sevHigh
	case score >= cvssMediumMin:
		return sevMedium
	default:
		return sevLow
	}
}
