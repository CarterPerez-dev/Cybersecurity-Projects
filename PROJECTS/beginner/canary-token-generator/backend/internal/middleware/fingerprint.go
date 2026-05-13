// ©AngelaMos | 2026
// fingerprint.go

package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

const (
	fingerprintHexLen = 16

	rateLimitKeyByFingerprintPrefix = "ratelimit:fp:"
)

func ExtractFingerprint(r *http.Request) string {
	raw := RealIP(r) + "|" + r.UserAgent()
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:fingerprintHexLen]
}

func KeyByFingerprint(r *http.Request) string {
	return rateLimitKeyByFingerprintPrefix + ExtractFingerprint(r)
}
