// ©AngelaMos | 2026
// cvss_test.go

package vuln

import (
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCVSSKnownVectors(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		score  float64
	}{
		{
			name:   "CVE-2023-44487 HTTP/2 rapid reset",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			score:  7.5,
		},
		{
			name:   "max severity all high",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			score:  10.0,
		},
		{
			name:   "log4shell CVE-2021-44228",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			score:  10.0,
		},
		{
			name:   "local low impact",
			vector: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
			score:  1.8,
		},
		{
			name:   "network medium complexity",
			vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			score:  8.1,
		},
		{
			name:   "scope changed low priv",
			vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
			score:  6.4,
		},
		{
			name:   "physical access required",
			vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			score:  6.8,
		},
		{
			name:   "adjacent network",
			vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			score:  8.8,
		},
		{
			name:   "scope changed high priv",
			vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
			score:  8.8,
		},
		{
			name:   "all none impact",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			score:  0.0,
		},
		{
			name:   "CVE-2022-41723 net/http2 resource",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			score:  7.5,
		},
		{
			name:   "CVSS 3.0 prefix also supported",
			vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			score:  9.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCVSSScore(tt.vector)
			assert.InDelta(t, tt.score, got, 0.1,
				"vector=%s expected=%.1f got=%.1f", tt.vector, tt.score, got)
		})
	}
}

func TestCVSSInvalidVectors(t *testing.T) {
	assert.Equal(t, 0.0, parseCVSSScore(""))
	assert.Equal(t, 0.0, parseCVSSScore("not-a-vector"))
	assert.Equal(t, 0.0, parseCVSSScore("CVSS:2.0/AV:N"))
	assert.Equal(t, 0.0, parseCVSSScore("CVSS:3.1/AV:N"))
	assert.Equal(t, 0.0, parseCVSSScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
}

func TestCVSSRoundUp(t *testing.T) {
	assert.Equal(t, 4.1, cvssRoundUp(4.02))
	assert.Equal(t, 4.0, cvssRoundUp(4.0))
	assert.Equal(t, 0.0, cvssRoundUp(0.0))
	assert.Equal(t, 10.0, cvssRoundUp(10.0))
}

func TestScoreToSeverity(t *testing.T) {
	assert.Equal(t, types.SeverityCritical, scoreToSeverity(9.8))
	assert.Equal(t, types.SeverityCritical, scoreToSeverity(9.0))
	assert.Equal(t, types.SeverityHigh, scoreToSeverity(8.9))
	assert.Equal(t, types.SeverityHigh, scoreToSeverity(7.0))
	assert.Equal(t, types.SeverityMedium, scoreToSeverity(6.9))
	assert.Equal(t, types.SeverityMedium, scoreToSeverity(4.0))
	assert.Equal(t, types.SeverityLow, scoreToSeverity(3.9))
	assert.Equal(t, types.SeverityLow, scoreToSeverity(0.1))
	assert.Equal(t, types.SeverityNone, scoreToSeverity(0.0))
}
