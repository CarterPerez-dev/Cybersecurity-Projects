// ©AngelaMos | 2026
// config.go

package config

import "time"

const (
	ToolName    = "bomber"
	ToolVersion = "0.1.0"
	ToolVendor  = "CarterPerez-dev"

	DefaultCacheTTLHours = 24
	DefaultCachePath     = ".bomber/cache.db"

	OSVBaseURL  = "https://api.osv.dev"
	NVDBaseURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	HTTPTimeout = 30 * time.Second

	OSVBatchSize      = 1000
	OSVSourceName     = "osv"
	NVDSourceName     = "nvd"
	NVDRateWithKey    = 200 * time.Millisecond
	NVDRateWithoutKey = 1700 * time.Millisecond

	SPDXVersion      = "SPDX-2.3"
	SPDXDataLicense  = "CC0-1.0"
	CycloneDXFormat  = "CycloneDX"
	CycloneDXVersion = "1.5"
)
