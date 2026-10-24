// ©AngelaMos | 2026
// token.go

package secretfile

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

const (
	// Payload is the fixed part of the message. These experiments are about the
	// KEY the target verifies with, so the key is the only thing that varies
	// between a valid credential and the control.
	Payload = "khaos-range-secret-probe"

	// The message carries a NONCE as well, which is what lets the control be
	// freshly minted per request while staying signed with the same key. A
	// fixed credential can be answered from one cached refusal, and the
	// catalogue census refuses an experiment whose control repeats - measured
	// against a gateway that failed open with a cache TTL longer than the
	// fault window and reported a clean pass.
	separator = "."
	parts     = 3
)

// Token is HMAC-SHA256 over a fixed payload, shared by khaos and the range
// fixture so that neither can drift from the other about what a valid
// credential is.
//
// An EMPTY key is the whole point of the empty-secret fault: crypto/hmac
// computes happily with a zero-length key, and a token signed with it verifies
// against a verifier that read an empty secret and did not check its length.
func Token(secret []byte, nonce string) string {
	return Payload + separator + nonce + separator +
		hex.EncodeToString(sign(secret, nonce))
}

func sign(secret []byte, nonce string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(Payload + separator + nonce))

	return mac.Sum(nil)
}

// Verify is constant-time and does NOT check the key's length, which is the
// defect the `unchecked` fixture mode carries deliberately. The caller decides
// whether an empty key is acceptable.
func Verify(token string, secret []byte) bool {
	fields := strings.Split(token, separator)
	if len(fields) != parts || fields[0] != Payload {
		return false
	}

	presented, err := hex.DecodeString(fields[parts-1])
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(presented, sign(secret, fields[1])) == 1
}
