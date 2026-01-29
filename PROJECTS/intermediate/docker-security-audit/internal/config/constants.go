/*
AngelaMos | 2026
constants.go
*/

package config

import "time"

// Scanner configuration constants for concurrency, rate limiting, and timeouts.
const (
	MaxWorkers         = 50
	DefaultWorkerCount = 20
	RateLimitPerSecond = 50
	RateLimitBurst     = 50

	DefaultTimeout    = 30 * time.Second
	InspectTimeout    = 10 * time.Second
	ConnectionTimeout = 5 * time.Second

	MaxTotalFindings = 10000

	SARIFMaxResults = 25000

	MinEntropyForSecret = 4.5
	MinSecretLength     = 16
)
