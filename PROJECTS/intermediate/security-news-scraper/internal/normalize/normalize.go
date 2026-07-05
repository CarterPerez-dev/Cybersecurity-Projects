// ©AngelaMos | 2026
// normalize.go

package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/PuerkitoBio/goquery"
)

const (
	wildcardSuffix = "*"
	trailingSlash  = "/"
)

func CanonicalURL(raw string, trackingParams []string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("normalize: parse url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("normalize: url %q has no host", raw)
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.RawFragment = ""

	if q := u.Query(); len(q) > 0 {
		for key := range q {
			if isTracking(key, trackingParams) {
				q.Del(key)
			}
		}
		u.RawQuery = q.Encode()
	}

	u.Path = strings.TrimRight(u.Path, trailingSlash)
	if u.RawPath != "" {
		u.RawPath = strings.TrimRight(u.RawPath, trailingSlash)
	}

	return u.String(), nil
}

func isTracking(key string, trackingParams []string) bool {
	lowered := strings.ToLower(key)
	for _, p := range trackingParams {
		if strings.HasSuffix(p, wildcardSuffix) {
			if strings.HasPrefix(lowered, strings.TrimSuffix(p, wildcardSuffix)) {
				return true
			}
			continue
		}
		if lowered == p {
			return true
		}
	}
	return false
}

func NormalizeTitle(title string) string {
	var b strings.Builder
	b.Grow(len(title))
	prevSpace := false
	for _, r := range strings.ToLower(title) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevSpace = false
			continue
		}
		if !prevSpace {
			b.WriteByte(' ')
			prevSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

func StripHTML(s string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(s))
	if err != nil {
		return collapseWhitespace(s)
	}
	doc.Find("script,style").Remove()
	return collapseWhitespace(doc.Text())
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func ContentHash(canonicalURL string) string {
	return sha256Hex(canonicalURL)
}

func TitleHash(normalizedTitle string) string {
	return sha256Hex(normalizedTitle)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
