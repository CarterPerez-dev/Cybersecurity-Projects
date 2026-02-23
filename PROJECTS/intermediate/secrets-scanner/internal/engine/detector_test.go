// ©AngelaMos | 2026
// detector_test.go

package engine

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/portia/internal/rules"
	"github.com/CarterPerez-dev/portia/pkg/types"
)

func testRegistry() *rules.Registry {
	reg := rules.NewRegistry()
	reg.Register(&types.Rule{
		ID:          "test-aws-key",
		Description: "AWS Access Key ID",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"AKIA"},
		Pattern: regexp.MustCompile(
			`\b((?:AKIA)[0-9A-Z]{16})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	})
	reg.Register(&types.Rule{
		ID:          "test-generic-password",
		Description: "Generic Password",
		Severity:    types.SeverityHigh,
		Keywords:    []string{"password"},
		Pattern: regexp.MustCompile(
			`(?i)password\s*[:=]\s*['"]([^'"]{8,})['"]`,
		),
		SecretGroup: 1,
		Entropy:     func() *float64 { f := 3.0; return &f }(),
		SecretType:  types.SecretTypePassword,
	})
	reg.Register(&types.Rule{
		ID:          "test-stripe-key",
		Description: "Stripe Live Key",
		Severity:    types.SeverityCritical,
		Keywords:    []string{"sk_live_"},
		Pattern: regexp.MustCompile(
			`\b(sk_live_[a-zA-Z0-9]{24,})\b`,
		),
		SecretGroup: 1,
		SecretType:  types.SecretTypeAPIKey,
	})
	return reg
}

func TestDetectAWSKey(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{ //nolint:gosec
		Content:   `aws_key = "AKIAIOSFODNN7EXAMPLE"`,
		FilePath:  "config.py",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	require.Len(t, findings, 1)
	assert.Equal(t, "test-aws-key", findings[0].RuleID)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", findings[0].Secret) //nolint:gosec
	assert.Equal(t, "config.py", findings[0].FilePath)
	assert.Equal(t, 1, findings[0].LineNumber)
	assert.Equal(t, types.SeverityCritical, findings[0].Severity)
}

func TestDetectStripeKey(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{ //nolint:gosec
		Content:   `STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc`,
		FilePath:  "env.sh",
		LineStart: 10,
	}

	findings := d.Detect(chunk)
	require.Len(t, findings, 1)
	assert.Equal(t, "test-stripe-key", findings[0].RuleID)
	assert.Equal(t,
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		findings[0].Secret,
	)
}

func TestDetectPasswordWithEntropy(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{
		Content:   `password = "xK9mP2vL5nQ8jR3t"`,
		FilePath:  "config.ini",
		LineStart: 5,
	}

	findings := d.Detect(chunk)
	require.Len(t, findings, 1)
	assert.Equal(t, "test-generic-password", findings[0].RuleID)
	assert.Greater(t, findings[0].Entropy, 3.0)
}

func TestDetectPasswordLowEntropyFiltered(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{
		Content:   `password = "aaaaaaaaaa"`,
		FilePath:  "config.ini",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	assert.Empty(t, findings)
}

func TestDetectNoKeywords(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{
		Content:   "just some normal code here",
		FilePath:  "main.go",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	assert.Empty(t, findings)
}

func TestDetectPlaceholderFiltered(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{
		Content:   `password = "your-password-here"`,
		FilePath:  "config.py",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	assert.Empty(t, findings)
}

func TestDetectMultipleFindings(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{
		Content: `aws_key = "AKIAIOSFODNN7EXAMPLE"` + "\n" +
			`stripe = sk_live_4eC39HqLyjWDarjtT1zdp7dc`,
		FilePath:  "config.py",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	require.Len(t, findings, 2)

	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	assert.True(t, ruleIDs["test-aws-key"])
	assert.True(t, ruleIDs["test-stripe-key"])
}

func TestDetectLineNumbers(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{
		Content: "line 1\n" +
			"line 2\n" +
			`AKIAIOSFODNN7EXAMPLE` + "\n" +
			"line 4\n",
		FilePath:  "data.txt",
		LineStart: 10,
	}

	findings := d.Detect(chunk)
	require.Len(t, findings, 1)
	assert.Equal(t, 12, findings[0].LineNumber)
}

func TestDetectAllowedPathFiltered(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{ //nolint:gosec
		Content:   `AKIAIOSFODNN7EXAMPLE`,
		FilePath:  "go.sum",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	assert.Empty(t, findings)
}

func TestExtractSecret(t *testing.T) {
	t.Parallel()

	line := `key = "AKIAIOSFODNN7EXAMPLE"` //nolint:gosec
	loc := []int{7, 27, 7, 27}
	got := extractSecret(line, loc, 1)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", got)

	got = extractSecret(line, loc, 0)
	assert.Equal(t, `AKIAIOSFODNN7EXAMPLE`, got)

	got = extractSecret(line, []int{}, 1)
	assert.Empty(t, got)
}

func TestDetectHighEntropy(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{
		Content:   `secret = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0u"`,
		FilePath:  "config.py",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	require.Len(t, findings, 1)
	assert.Equal(t, "high-entropy-string", findings[0].RuleID)
	assert.Equal(t, types.SeverityMedium, findings[0].Severity)
	assert.Greater(t, findings[0].Entropy, 4.0)
}

func TestDetectHighEntropyNotDuplicated(t *testing.T) {
	t.Parallel()
	d := NewDetector(testRegistry())

	chunk := types.Chunk{ //nolint:gosec
		Content:   `aws_key = "AKIAIOSFODNN7EXAMPLE"`,
		FilePath:  "config.py",
		LineStart: 1,
	}

	findings := d.Detect(chunk)
	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	assert.True(t, ruleIDs["test-aws-key"])
	assert.False(
		t,
		ruleIDs["high-entropy-string"],
		"entropy detector should not duplicate rule findings",
	)
}
