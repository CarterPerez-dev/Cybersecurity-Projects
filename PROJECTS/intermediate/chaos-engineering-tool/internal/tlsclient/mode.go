// ©AngelaMos | 2026
// mode.go

package tlsclient

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Mode is one way a TLS client can be wrong, drawn from the fail-open taxonomy
// in research 04 and 07.
//
// Correct is a REFERENCE IMPLEMENTATION, not a wrapper around crypto/tls.
// Go verifies the chain, the hostname and the validity window and then stops,
// because `crypto/x509` performs no revocation checking of any kind. So the
// correct client here is Go's verification PLUS the layer Go does not have:
// the six-step CRL check, OCSP with freshness and certificate binding, a key
// floor and a lifetime policy. Every broken mode below removes exactly one
// piece of that layer, which is what makes a differential meaningful.
type Mode string

const (
	// Correct refuses everything a correct client should refuse. It is the
	// control for every other mode and the only one khaos ships as an example
	// worth copying.
	Correct Mode = "closed"

	// SkipVerify is InsecureSkipVerify. It is first because it is the single
	// most common fail-open in real code: it turns off the chain, the hostname
	// and the validity window in one assignment, and it is what people reach
	// for when a certificate error blocks a deploy.
	SkipVerify Mode = "skip-verify"

	// SkipHostname verifies the chain and skips only the name. It is a real and
	// subtler shape than SkipVerify: the connection is to a provably valid
	// certificate for somebody else.
	SkipHostname Mode = "skip-hostname"

	// TrustPresentedCA builds its trust anchors out of whatever the server
	// sent, which accepts any self-consistent chain. This is the shape a
	// developer writes when "add the CA to the pool" is the error they are
	// trying to silence.
	TrustPresentedCA Mode = "trust-presented-ca"

	// NoRevocationCheck is Go's own default behaviour, stated as a mode. It
	// verifies the chain properly and never asks whether the certificate was
	// revoked, which is correct Go and an incorrect client.
	NoRevocationCheck Mode = "no-revocation-check"

	// SoftFailOCSP asks and then proceeds whenever it does not get a usable
	// answer: a transport failure, a TryLater, an Unknown. Research 04 calls
	// soft-fail the reason revocation is near-useless in practice.
	SoftFailOCSP Mode = "soft-fail-ocsp"

	// StaleAccepted checks the status and never the freshness window, so a
	// replayed or cached Good is trusted forever.
	StaleAccepted Mode = "stale-accepted"

	// LooseOCSPParse calls ParseResponse instead of ParseResponseForCert. That
	// one word stops the response being bound to the certificate, so a Good
	// minted for a different serial is accepted. It is the cheapest total
	// bypass of revocation checking in the whole taxonomy.
	LooseOCSPParse Mode = "loose-ocsp-parse"

	// NoCRLFreshness performs the whole CRL check except step five. It fetches,
	// verifies the signature and scans the serials, and never looks at
	// NextUpdate, so a three-week-old list is authoritative.
	NoCRLFreshness Mode = "no-crl-freshness"

	// TrustStaple reads the stapled response and believes it without checking
	// that it is a response at all. Go never parses a staple, so whatever the
	// server attached arrives verbatim.
	TrustStaple Mode = "trust-staple"

	// NoKeyFloor, NoLifetimePolicy and NoKeyUsagePolicy drop the three policy
	// checks x509 does not have. They exist so that each trap Go accepts has
	// both a mode that catches it and a mode that does not, which is the only
	// way those experiments can distinguish a target with a policy of its own
	// from one with none.
	//
	// NoKeyUsagePolicy is the subtlest of the three. Verify enforces EXTENDED
	// key usage, nested down the chain, and never looks at the basic KeyUsage
	// bits on a leaf. A leaf whose KeyUsage omits digitalSignature is unusable
	// for TLS under RFC 5280 section 4.2.1.3 and Go will not say a word about
	// it, so a correct client has to check it here or not at all.
	NoKeyFloor       Mode = "no-key-floor"
	NoLifetimePolicy Mode = "no-lifetime-policy"
	NoKeyUsagePolicy Mode = "no-key-usage-policy"
)

const (
	errUnknownMode = "%w: %q (known modes: %s)"
	modeSep        = ", "
)

// ErrUnknownMode is a name this package has no client for.
var ErrUnknownMode = errors.New("no such reference client mode")

// Modes is every mode, Correct first. Tests census against this.
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
	}
}

// ParseMode resolves a mode name, refusing anything it does not implement
// rather than silently falling back to Correct. A range fixture that quietly
// became correct would report every experiment as fail-closed.
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

// checksChain reports whether the mode lets crypto/x509 build and check the
// path at all.
func (m Mode) checksChain() bool {
	return m != SkipVerify
}

// checksHostname reports whether the mode matches the name it asked for.
func (m Mode) checksHostname() bool {
	return m != SkipVerify && m != SkipHostname
}

// checksRevocation reports whether the mode asks about revocation in any way.
// Go's default is false, which is the whole reason this family exists.
func (m Mode) checksRevocation() bool {
	switch m {
	case SkipVerify, NoRevocationCheck:
		return false
	default:
		return true
	}
}

// hardFails reports whether a revocation answer the mode could not obtain is
// treated as a refusal. A soft-failing client proceeds, which is Langley's
// seat belt that unbuckles in a crash.
func (m Mode) hardFails() bool {
	return m != SoftFailOCSP
}

// checksCRLFreshness and checksOCSPFreshness are SEPARATE, because the modes
// break them separately. Nothing in the standard library checks either one.
//
// A single predicate covering both was wrong and the matrix caught it:
// NoCRLFreshness is named for the CRL and was silently disabling the OCSP
// freshness check as well, so a stale OCSP response was accepted by a client
// whose only declared defect was about certificate revocation lists.
func (m Mode) checksCRLFreshness() bool {
	return m != StaleAccepted && m != NoCRLFreshness
}

func (m Mode) checksOCSPFreshness() bool {
	return m != StaleAccepted
}

// bindsResponse reports whether the mode checks that an OCSP response is about
// the certificate in hand.
func (m Mode) bindsResponse() bool {
	return m != LooseOCSPParse
}

// checksKeyFloor and checksLifetime are the two policies x509 does not have, so
// a mode without them is not breaking any rule Go enforces.
func (m Mode) checksKeyFloor() bool {
	return m != SkipVerify && m != NoKeyFloor
}

func (m Mode) checksLifetime() bool {
	return m != SkipVerify && m != NoLifetimePolicy
}

// checksKeyUsage reports whether the mode enforces the basic KeyUsage bits,
// which crypto/x509 never does on a leaf.
func (m Mode) checksKeyUsage() bool {
	return m != SkipVerify && m != NoKeyUsagePolicy
}
