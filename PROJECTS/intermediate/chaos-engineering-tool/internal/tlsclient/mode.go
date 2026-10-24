// ©AngelaMos | 2026
// mode.go

package tlsclient

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Mode is one way a TLS client can be wrong. crypto/x509 performs no
// revocation checking of any kind, so Correct is a REFERENCE IMPLEMENTATION
// rather than a wrapper, and each mode below removes one piece of it.
type Mode string

const (
	// Correct refuses everything a correct client should refuse.
	Correct Mode = "closed"

	// SkipVerify is InsecureSkipVerify: no chain, no hostname, no validity.
	SkipVerify Mode = "skip-verify"

	// SkipHostname checks the chain and skips only the name.
	SkipHostname Mode = "skip-hostname"

	// TrustPresentedCA anchors on whatever chain the server sent.
	TrustPresentedCA Mode = "trust-presented-ca"

	// NoRevocationCheck is Go's own default: correct Go, incorrect client.
	NoRevocationCheck Mode = "no-revocation-check"

	// SoftFailOCSP asks, then proceeds on anything short of a usable answer.
	SoftFailOCSP Mode = "soft-fail-ocsp"

	// StaleAccepted checks the status and never the freshness window.
	StaleAccepted Mode = "stale-accepted"

	// LooseOCSPParse uses ParseResponse, which binds nothing to the leaf.
	LooseOCSPParse Mode = "loose-ocsp-parse"

	// NoCRLFreshness does the whole CRL check except NextUpdate.
	NoCRLFreshness Mode = "no-crl-freshness"

	// TrustStaple believes the staple without checking it is a response.
	TrustStaple Mode = "trust-staple"

	// NoKeyFloor, NoLifetimePolicy and NoKeyUsagePolicy drop the three policy
	// checks x509 lacks; Verify never reads a leaf's basic KeyUsage bits.
	NoKeyFloor       Mode = "no-key-floor"
	NoLifetimePolicy Mode = "no-lifetime-policy"
	NoKeyUsagePolicy Mode = "no-key-usage-policy"

	// DialOnly never reads a byte. Under TLS 1.3 a server's rejection of the
	// client certificate does not surface at Dial, only on the first read.
	DialOnly Mode = "dial-only"

	// PolicyInPeerCallback puts its policy in VerifyPeerCertificate and reuses
	// sessions, and crypto/tls skips that callback on a resumed handshake.
	PolicyInPeerCallback Mode = "policy-in-peer-callback"
)

const (
	errUnknownMode = "%w: %q (known modes: %s)"
	modeSep        = ", "
)

var ErrUnknownMode = errors.New("no such reference client mode")

func Modes() []string {
	return []string{
		string(Correct),
		string(SkipVerify),
		string(SkipHostname),
		string(TrustPresentedCA),
		string(NoRevocationCheck),
		string(SoftFailOCSP),
		string(StaleAccepted),
		string(LooseOCSPParse),
		string(NoCRLFreshness),
		string(TrustStaple),
		string(NoKeyFloor),
		string(NoLifetimePolicy),
		string(NoKeyUsagePolicy),
		string(DialOnly),
		string(PolicyInPeerCallback),
	}
}

// ParseMode refuses an unimplemented name rather than falling back to Correct.
func ParseMode(name string) (Mode, error) {
	if !slices.Contains(Modes(), name) {
		return "", fmt.Errorf(
			errUnknownMode,
			ErrUnknownMode,
			name,
			strings.Join(Modes(), modeSep),
		)
	}

	return Mode(name), nil
}

func (m Mode) checksChain() bool {
	return m != SkipVerify
}

func (m Mode) checksHostname() bool {
	return m != SkipVerify && m != SkipHostname
}

func (m Mode) checksRevocation() bool {
	switch m {
	case SkipVerify, NoRevocationCheck:
		return false
	default:
		return true
	}
}

func (m Mode) hardFails() bool {
	return m != SoftFailOCSP
}

// Separate predicates, because the modes break CRL and OCSP freshness apart.
func (m Mode) checksCRLFreshness() bool {
	return m != StaleAccepted && m != NoCRLFreshness
}

func (m Mode) checksOCSPFreshness() bool {
	return m != StaleAccepted
}

func (m Mode) bindsResponse() bool {
	return m != LooseOCSPParse
}

func (m Mode) checksKeyFloor() bool {
	return m != SkipVerify && m != NoKeyFloor
}

func (m Mode) checksLifetime() bool {
	return m != SkipVerify && m != NoLifetimePolicy
}

func (m Mode) checksKeyUsage() bool {
	return m != SkipVerify && m != NoKeyUsagePolicy
}

func (m Mode) reads() bool {
	return m != DialOnly
}

func (m Mode) resumes() bool {
	return m == PolicyInPeerCallback || m == Correct
}

func (m Mode) rechecksPerConnection() bool {
	return m != PolicyInPeerCallback
}
