// ©AngelaMos | 2026
// entropy.go

package rules

import (
	"math"
	"strings"
)

const (
	Base64Charset       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
	HexCharset          = "0123456789abcdefABCDEF"
	AlphanumericCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

var (
	base64Set       = buildCharsetSet(Base64Charset)
	hexSet          = buildCharsetSet(HexCharset)
	alphanumericSet = buildCharsetSet(AlphanumericCharset)
)

type EntropyToken struct {
	Value   string
	Entropy float64
}

func ShannonEntropy(data, charset string) float64 {
	if len(data) == 0 {
		return 0.0
	}

	filtered := data
	if charset != "" {
		cs := charsetSet(charset)
		var b strings.Builder
		b.Grow(len(data))
		for _, c := range data {
			if cs[c] {
				b.WriteRune(c)
			}
		}
		filtered = b.String()
		if len(filtered) == 0 {
			return 0.0
		}
	}

	freq := make(map[rune]int)
	for _, c := range filtered {
		freq[c]++
	}

	length := float64(len([]rune(filtered)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func DetectCharset(s string) string {
	hexCount := 0
	b64Count := 0
	total := 0

	for _, c := range s {
		total++
		if hexSet[c] {
			hexCount++
		}
		if base64Set[c] {
			b64Count++
		}
	}

	if total == 0 {
		return "alphanumeric"
	}

	hexRatio := float64(hexCount) / float64(total)
	b64Ratio := float64(b64Count) / float64(total)

	if hexRatio == 1.0 && isAllHexChars(s) {
		return "hex"
	}
	if b64Ratio >= 0.95 {
		return "base64"
	}
	return "alphanumeric"
}

func ExtractHighEntropyTokens(
	line string,
	charset string,
	threshold float64,
	minLen int,
) []EntropyToken {
	cs := charsetSet(charset)
	var tokens []EntropyToken
	var current []rune

	for _, c := range line {
		if cs[c] {
			current = append(current, c)
		} else {
			if len(current) >= minLen {
				token := string(current)
				ent := ShannonEntropy(token, charset)
				if ent >= threshold {
					tokens = append(tokens, EntropyToken{
						Value:   token,
						Entropy: math.Round(ent*1000) / 1000,
					})
				}
			}
			current = current[:0]
		}
	}

	if len(current) >= minLen {
		token := string(current)
		ent := ShannonEntropy(token, charset)
		if ent >= threshold {
			tokens = append(tokens, EntropyToken{
				Value:   token,
				Entropy: math.Round(ent*1000) / 1000,
			})
		}
	}

	return tokens
}

func charsetSet(charset string) map[rune]bool {
	switch charset {
	case Base64Charset:
		return base64Set
	case HexCharset:
		return hexSet
	case AlphanumericCharset:
		return alphanumericSet
	default:
		return buildCharsetSet(charset)
	}
}

func buildCharsetSet(charset string) map[rune]bool {
	s := make(map[rune]bool, len(charset))
	for _, c := range charset {
		s[c] = true
	}
	return s
}

func isAllHexChars(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
