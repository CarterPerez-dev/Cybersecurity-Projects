// ©AngelaMos | 2026
// prompt.go

package ai

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	systemPrompt = `You are a senior security-content strategist helping a creator turn cybersecurity news into content. You are given a cluster of related news articles (one story covered by one or more outlets), optionally with referenced CVEs and their exploit signals. Produce content ideation for the story.

Respond with a SINGLE JSON object and NOTHING else. No prose, no markdown, no code fences. The object has exactly these keys:
  "summary": a 2-3 sentence plain-language summary of the story.
  "why":     one paragraph on why it matters to a security audience (impact, who is affected, exploitation).
  "angles":  an array of 3 to 5 distinct content angles or hooks a creator could lead with.
  "format":  the single best-fit format, one of: "blog", "newsletter", "video".

Ground every claim in the provided material. Do not invent CVEs, vendors, or facts not present in the input.`

	jsonObjectOpen  byte = '{'
	jsonObjectClose byte = '}'
)

func buildPrompt(req IdeationRequest) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "Story cluster: %d article(s) across %d outlet(s), spanning ~%dh.\n\n", req.ClusterSize, len(req.Sources), req.SpanHours)
	if len(req.Sources) > 0 {
		fmt.Fprintf(&b, "Outlets: %s\n\n", strings.Join(req.Sources, ", "))
	}
	b.WriteString("Headlines:\n")
	for _, t := range req.Titles {
		fmt.Fprintf(&b, "- %s\n", t)
	}
	if len(req.CVEs) > 0 {
		b.WriteString("\nReferenced CVEs:\n")
		for _, c := range req.CVEs {
			b.WriteString("- " + c.ID)
			if c.CVSS != nil {
				fmt.Fprintf(&b, " CVSS %.1f", *c.CVSS)
			}
			if c.KEV {
				b.WriteString(" [KEV: known exploited]")
			}
			if c.EPSS != nil {
				fmt.Fprintf(&b, " EPSS %.2f", *c.EPSS)
			}
			b.WriteString("\n")
		}
	}
	return systemPrompt, b.String()
}

func parseResult(text string) (IdeationResult, error) {
	for _, obj := range jsonObjectCandidates(text) {
		var res IdeationResult
		if err := json.Unmarshal([]byte(obj), &res); err != nil {
			continue
		}
		res.Format = normalizeFormat(res.Format)
		if strings.TrimSpace(res.Summary) != "" && len(res.Angles) > 0 {
			return res, nil
		}
	}
	return IdeationResult{}, fmt.Errorf("ai: no usable JSON ideation object in model output")
}

func jsonObjectCandidates(text string) []string {
	var out []string
	for i := 0; i < len(text); {
		if text[i] != jsonObjectOpen {
			i++
			continue
		}
		end := balancedObjectEnd(text, i)
		if end < 0 {
			break
		}
		out = append(out, text[i:end+1])
		i = end + 1
	}
	return out
}

func balancedObjectEnd(text string, start int) int {
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(text); i++ {
		ch := text[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case jsonObjectOpen:
			depth++
		case jsonObjectClose:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func normalizeFormat(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case FormatNewsletter:
		return FormatNewsletter
	case FormatVideo:
		return FormatVideo
	default:
		return FormatBlog
	}
}
