// ©AngelaMos | 2026
// detector.go

package engine

import (
	"strings"

	"github.com/CarterPerez-dev/portia/internal/rules"
	"github.com/CarterPerez-dev/portia/pkg/types"
)

type Detector struct {
	registry *rules.Registry
}

func NewDetector(reg *rules.Registry) *Detector {
	return &Detector{registry: reg}
}

func (d *Detector) Detect(chunk types.Chunk) []types.Finding { //nolint:gocognit
	lines := strings.Split(chunk.Content, "\n")
	var findings []types.Finding

	matched := d.registry.MatchKeywords(chunk.Content)
	for _, rule := range matched {
		for i, line := range lines {
			matches := rule.Pattern.FindAllStringSubmatchIndex(
				line, -1,
			)
			if len(matches) == 0 {
				continue
			}

			for _, loc := range matches {
				secret := extractSecret(line, loc, rule.SecretGroup)
				if secret == "" {
					continue
				}

				match := line[loc[0]:loc[1]]

				finding := types.Finding{
					RuleID:      rule.ID,
					Description: rule.Description,
					Severity:    rule.Severity,
					Match:       match,
					Secret:      secret,
					FilePath:    chunk.FilePath,
					LineNumber:  chunk.LineStart + i,
					LineContent: line,
					CommitSHA:   chunk.CommitSHA,
					Author:      chunk.Author,
					CommitDate:  chunk.CommitDate,
				}

				if rule.Entropy != nil {
					charset := rules.DetectCharset(secret)
					var charsetStr string
					switch charset {
					case "hex":
						charsetStr = rules.HexCharset
					case "base64":
						charsetStr = rules.Base64Charset
					default:
						charsetStr = rules.AlphanumericCharset
					}
					entropy := rules.ShannonEntropy(
						secret, charsetStr,
					)
					finding.Entropy = entropy

					if entropy < *rule.Entropy {
						continue
					}
				}

				if !FilterFinding(&finding, rule) {
					continue
				}

				findings = append(findings, finding)
			}
		}
	}

	findings = append(
		findings,
		d.detectHighEntropy(chunk, lines, findings)...,
	)

	return findings
}

var entropyCharsets = []struct {
	charset   string
	threshold float64
}{
	{rules.Base64Charset, 4.5},
	{rules.HexCharset, 3.5},
}

func (d *Detector) detectHighEntropy(
	chunk types.Chunk,
	lines []string,
	existing []types.Finding,
) []types.Finding {
	var findings []types.Finding
	dummyRule := &types.Rule{}

	for i, line := range lines {
		if !HasAssignmentOperator(line) {
			continue
		}
		lineNum := chunk.LineStart + i

		for _, cs := range entropyCharsets {
			tokens := rules.ExtractHighEntropyTokens(
				line, cs.charset, cs.threshold, 20,
			)
			for _, token := range tokens {
				if isAlreadyCaught(
					token.Value, lineNum, existing,
				) {
					continue
				}
				if isAlreadyCaught(
					token.Value, lineNum, findings,
				) {
					continue
				}

				finding := types.Finding{
					RuleID:      "high-entropy-string",
					Description: "High Entropy String",
					Severity:    types.SeverityMedium,
					Match:       token.Value,
					Secret:      token.Value,
					Entropy:     token.Entropy,
					FilePath:    chunk.FilePath,
					LineNumber:  lineNum,
					LineContent: line,
					CommitSHA:   chunk.CommitSHA,
					Author:      chunk.Author,
					CommitDate:  chunk.CommitDate,
				}

				if !FilterFinding(&finding, dummyRule) {
					continue
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func isAlreadyCaught(
	token string, lineNum int, existing []types.Finding,
) bool {
	for _, f := range existing {
		if f.LineNumber == lineNum &&
			(strings.Contains(f.Secret, token) ||
				strings.Contains(token, f.Secret)) {
			return true
		}
	}
	return false
}

func extractSecret(
	line string, loc []int, group int,
) string {
	if group > 0 && len(loc) > group*2+1 {
		start := loc[group*2]
		end := loc[group*2+1]
		if start >= 0 && end >= 0 {
			return line[start:end]
		}
	}
	if len(loc) >= 2 {
		return line[loc[0]:loc[1]]
	}
	return ""
}
