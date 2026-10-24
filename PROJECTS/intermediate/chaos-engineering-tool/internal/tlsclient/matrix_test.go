// ©AngelaMos | 2026
// matrix_test.go

package tlsclient_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/tlsclient"
)

// The matrix. Every trap khaos's authority can arm, judged by every reference
// client, in both directions.
//
// The expectation is DERIVED rather than recorded. Each trap names the one
// check that catches it, each mode names the checks it still performs, and the
// cell is the conjunction. A table of observed results would pass no matter
// what the client did; this one disagrees with the client whenever either the
// reasoning or the implementation is wrong, and both have been.

// guard is the check a trap can only be caught by.
type guard int

const (
	// byAnchor is a fault in WHO signed the certificate: the signature itself,
	// or the path up to a trusted root. It is separate from byValidity because
	// TrustPresentedCA defeats this one and not the other. Putting the served
	// leaf into the root pool makes it a trusted anchor, and crypto/x509 does
	// not check the signature on a certificate it already trusts, so a SHA-1
	// leaf sails through while an expired one still does not.
	//
	// The matrix found that: sha1-signature was the only chain fault
	// TrustPresentedCA accepted, which is what forced this split.
	byAnchor guard = iota

	// byLeaf is a defect in the LEAF itself, which no amount of trusting the
	// presented chain can hide, because the leaf is the certificate being
	// judged either way.
	byLeaf

	// byAnyVerification is defeated only by InsecureSkipVerify. It exists for
	// one trap: withholding the intermediate breaks the chain AND the
	// revocation path, because a client that cannot see the issuer cannot check
	// a CRL signature or an OCSP response from it either. So even the mode that
	// trusts whatever arrived refuses it, through the second route rather than
	// the first.
	byAnyVerification

	byHostname
	byKeyFloor
	byLifetime
	byKeyUsage

	// A list or responder that SAYS the certificate is bad. Which CHANNEL
	// carries the answer decides who can see it, so these are three guards
	// rather than one.
	//
	// byCRLStatus is carried by the revocation list, which even a
	// staple-trusting client goes on to consult. byStapledStatus is carried by
	// the stapled response, which that client accepts without reading.
	// byStapledAmbiguity is a stapled "unknown", invisible to the same client
	// and also waved through by a soft-failing one.
	byCRLStatus
	byStapledStatus
	byStapledAmbiguity

	// The remaining revocation guards are one per CHECK, not one per channel,
	// because the modes break different checks on different channels and a
	// single quality guard got four cells wrong. LooseOCSPParse breaks OCSP
	// binding and leaves CRL freshness intact; NoCRLFreshness is the mirror
	// image. Lumping them together predicted that each would accept both
	// faults, and the matrix refused each prediction.
	byCRLFreshness
	byOCSPFreshness
	byOCSPBinding
	byOCSPSignature
	byStapleValidity

	// byAvailability is an answer that could not be obtained at all, which only
	// a hard-failing client treats as a refusal.
	byAvailability

	byReading

	// byNothing is a trap no client-side check can catch. CASwap is the only
	// one, and that is the finding rather than a gap: once the anchor is
	// replaced the chain is genuinely valid, and only pinning or certificate
	// transparency helps.
	byNothing
)

// catches is the semantic predicate: does this mode still perform the check
// that this guard represents.
func catches(mode tlsclient.Mode, by guard) bool {
	switch by {
	case byAnchor:
		// TrustPresentedCA defeats every defect ABOVE the leaf, not just the
		// signature. Adding the served certificates to the root pool lets the
		// leaf anchor ITSELF, and crypto/x509 then never consults the chain
		// above it, so an expired intermediate and a CA-level key-usage
		// constraint go unexamined along with the signature. Measured: those
		// two were the cells that refused this prediction.
		return mode != tlsclient.SkipVerify &&
			mode != tlsclient.TrustPresentedCA

	case byLeaf, byAnyVerification:
		return mode != tlsclient.SkipVerify

	case byHostname:
		return mode != tlsclient.SkipVerify &&
			mode != tlsclient.SkipHostname

	case byKeyFloor:
		return mode != tlsclient.SkipVerify &&
			mode != tlsclient.NoKeyFloor

	case byLifetime:
		return mode != tlsclient.SkipVerify &&
			mode != tlsclient.NoLifetimePolicy

	case byKeyUsage:
		return mode != tlsclient.SkipVerify &&
			mode != tlsclient.NoKeyUsagePolicy

	case byCRLStatus:
		return asks(mode)

	case byStapledStatus:
		return asks(mode) && mode != tlsclient.TrustStaple

	case byStapledAmbiguity:
		return asks(mode) &&
			mode != tlsclient.TrustStaple &&
			mode != tlsclient.SoftFailOCSP

	case byCRLFreshness:
		// Caught by anyone who asks and compares the list's window against the
		// clock. TrustStaple still gets here, because a staple answers about
		// OCSP and the CRL is consulted afterwards.
		return asks(mode) &&
			mode != tlsclient.StaleAccepted &&
			mode != tlsclient.NoCRLFreshness

	case byOCSPFreshness:
		// NOT excluded for SoftFailOCSP: a stale response is an answer that was
		// obtained, so there is nothing to soft-fail over, and the client
		// refuses it on freshness like any other.
		return asks(mode) &&
			mode != tlsclient.StaleAccepted &&
			mode != tlsclient.TrustStaple

	case byOCSPBinding:
		// SoftFailOCSP is excluded here and not above, because an unbound
		// response fails to PARSE, which is indistinguishable from not having
		// got one, and that is exactly what a soft-failing client proceeds on.
		return asks(mode) &&
			mode != tlsclient.LooseOCSPParse &&
			mode != tlsclient.TrustStaple &&
			mode != tlsclient.SoftFailOCSP

	case byOCSPSignature, byStapleValidity:
		return asks(mode) &&
			mode != tlsclient.TrustStaple &&
			mode != tlsclient.SoftFailOCSP

	case byAvailability:
		return mode != tlsclient.SkipVerify &&
			mode != tlsclient.NoRevocationCheck &&
			mode != tlsclient.SoftFailOCSP

	case byReading:
		return mode != tlsclient.DialOnly

	case byNothing:
		return false

	default:
		return false
	}
}

// asks is the precondition every revocation guard shares: a client that never
// consults revocation cannot catch anything about it, however correct the rest
// of its verification is. Go's own default is in this group.
func asks(mode tlsclient.Mode) bool {
	return mode != tlsclient.SkipVerify &&
		mode != tlsclient.NoRevocationCheck
}

func guardFor(kind pki.Kind) guard {
	switch kind {
	// In the leaf, so nothing hides them.
	case pki.LeafExpired, pki.LeafNotYetValid, pki.EKUClientAuthOnly:
		return byLeaf

	// Above the leaf, so trusting the presented chain hides them all.
	case pki.SelfSigned, pki.UntrustedCA,
		pki.NameConstraintViolation, pki.PathLengthExceeded,
		pki.SHA1Signature, pki.IntermediateExpired,
		pki.EKUConstrainedIntermediate:
		return byAnchor

	// These two break the chain AND the revocation path, so even the mode that
	// trusts whatever arrived refuses them, through the second route.
	//
	// MissingIntermediate withholds the issuer, and a client that cannot see
	// the issuer cannot check a CRL signature or an OCSP response from it.
	//
	// IssuerNotCA is the same shape for a different reason, traced to
	// crypto/x509: RevocationList.CheckSignatureFrom returns
	// ConstraintViolationError whenever the parent has BasicConstraintsValid
	// and IsCA false (x509.go:2569), BEFORE it looks at KeyUsage or the
	// signature. A CRL from a non-CA issuer is unusable by construction, so
	// this fault cannot be hidden by trusting the chain either.
	case pki.MissingIntermediate, pki.IssuerNotCA:
		return byAnyVerification

	case pki.WrongSAN, pki.CommonNameOnly, pki.NoIPSAN:
		return byHostname

	case pki.WeakKey:
		return byKeyFloor

	case pki.ExcessiveLifetime:
		return byLifetime

	case pki.KeyUsageWithoutDigitalSignature:
		return byKeyUsage

	case pki.RevokedViaCRL:
		return byCRLStatus

	case pki.OCSPRevoked:
		return byStapledStatus

	case pki.StaleCRL:
		return byCRLFreshness

	case pki.OCSPStale:
		return byOCSPFreshness

	case pki.OCSPWrongSerial:
		return byOCSPBinding

	case pki.OCSPWrongSigner:
		return byOCSPSignature

	case pki.StapleGarbage:
		return byStapleValidity

	// Unknown is soft-failable, because SoftFailOCSP is defined as proceeding
	// whenever it cannot get a USABLE answer and "I don't know about this
	// certificate" is not one. It is NOT grouped with the unreachable faults,
	// though, because khaos staples it: those three staple nothing at all, so a
	// staple-trusting client is forced to go and ask and then refuses, while
	// this one it reads and waves through.
	case pki.OCSPUnknown:
		return byStapledAmbiguity

	case pki.CRLUnreachable, pki.OCSPUnreachable, pki.OCSPTryLater:
		return byAvailability

	case pki.ClientCertExpired, pki.ClientCertAbsent:
		return byReading

	case pki.CASwap, pki.NoOCSPServer, pki.StapleAbsent:
		// NoOCSPServer and StapleAbsent are not caught by a refusal at all. A
		// correct client falls back to the other revocation channel and
		// rightly accepts, because the certificate is not revoked. What they
		// measure is whether the target ASKED, which the asked-census below
		// covers and an accept/refuse assertion cannot.
		return byNothing

	default:
		return byNothing
	}
}

const (
	host    = "dependency.khaos.invalid"
	timeout = 20 * time.Second

	// loopback is the name the NoIPSAN row asks for. A certificate with no IP
	// SANs is perfectly correct for a client dialling by NAME, so asking for
	// the host would record that trap as accepted by every mode and the
	// experiment built on it would measure nothing.
	loopback = "127.0.0.1"
)

// dialName is the server name a client asks for when judging this trap, which
// is not always the host the certificate was minted for.
func dialName(kind pki.Kind) string {
	if kind == pki.NoIPSAN {
		return loopback
	}

	return host
}

// armed stands up an authority with one trap and returns the address a client
// should dial. One authority is reused across every mode for the same trap,
// which is both faster and more honest: every mode judges the SAME served
// chain, which is what makes the row a differential.
func armed(t *testing.T, kind pki.Kind) (*pki.Authority, string) {
	t.Helper()

	a, err := pki.New(pki.Config{Host: host})
	if err != nil {
		t.Fatalf("build an authority: %v", err)
	}

	t.Cleanup(func() { _ = a.Close() })

	if err := a.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("bind revocation: %v", err)
	}

	if err := a.ListenTLS("127.0.0.1:0"); err != nil {
		t.Fatalf("bind the dependency: %v", err)
	}

	trap := pki.Trap{
		Kind:   kind,
		Host:   host,
		Window: pki.DefaultWindow,
		Bits:   pki.DefaultWeakBits,
		Days:   pki.DefaultExcessiveDays,
	}

	if kind == pki.PassThrough {
		if err := a.Disarm(); err != nil {
			t.Fatalf("disarm: %v", err)
		}
	} else if err := a.Arm(trap); err != nil {
		t.Fatalf("arm %s: %v", kind, err)
	}

	addr, err := a.TLSAddr()
	if err != nil {
		t.Fatalf("dependency address: %v", err)
	}

	return a, addr
}

func decide(
	t *testing.T,
	a *pki.Authority,
	addr string,
	mode tlsclient.Mode,
	asking string,
) tlsclient.Decision {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := tlsclient.New(tlsclient.Config{
		Mode:  mode,
		Host:  asking,
		Roots: a.TrustedPool(),
		Now:   a.Now,

		// The identity khaos is currently issuing, fetched the way the range's
		// gateway fetches it. Without this every mutual TLS row would be
		// refused because the client presented NOTHING, which is one of the two
		// faults, so the expired row would pass for the absent row's reason.
		Identity: identityFrom(t, a),
	})

	return client.Decide(ctx, addr)
}

// identityFrom fetches the client certificate khaos is issuing, or nil when it
// is issuing none. Nil is not a failure: it is the client-cert-absent fault.
func identityFrom(t *testing.T, a *pki.Authority) *tls.Certificate {
	t.Helper()

	base, err := a.Addr()
	if err != nil {
		return nil
	}

	response, err := http.Get("http://" + base + pki.RouteIdentity)
	if err != nil {
		return nil
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil
	}

	identity, err := tls.X509KeyPair(body, body)
	if err != nil {
		return nil
	}

	return &identity
}

func TestEveryTrapAgainstEveryReferenceClient(t *testing.T) {
	kinds := pki.Kinds()
	modes := tlsclient.Modes()

	if len(kinds) == 0 || len(modes) == 0 {
		t.Fatal("the matrix is empty, so it asserts nothing")
	}

	for _, name := range kinds {
		kind := pki.Kind(name)

		t.Run(name, func(t *testing.T) {
			a, addr := armed(t, kind)
			by := guardFor(kind)

			for _, modeName := range modes {
				mode := tlsclient.Mode(modeName)

				t.Run(modeName, func(t *testing.T) {
					decision := decide(
						t,
						a,
						addr,
						mode,
						dialName(kind),
					)
					wantRefusal := catches(mode, by)

					if wantRefusal && decision.Accepted {
						t.Fatalf(
							"%s accepted %s, but this mode still performs the check that catches it",
							mode,
							kind,
						)
					}

					if !wantRefusal && !decision.Accepted {
						t.Fatalf(
							"%s refused %s (%s), but this mode does not perform the check that catches it, so the refusal came from somewhere khaos did not intend",
							mode,
							kind,
							decision.Reason,
						)
					}
				})
			}
		})
	}
}

// The control for the whole matrix. The correct client has to accept an unarmed
// authority, or every refusal above could be khaos's own broken baseline.
func TestTheCorrectClientAcceptsAnUnarmedAuthority(t *testing.T) {
	a, addr := armed(t, pki.PassThrough)

	decision := decide(t, a, addr, tlsclient.Correct, host)

	if !decision.Accepted {
		t.Fatalf(
			"the correct client refused an honest dependency (%s); every cell in the matrix is measured against this",
			decision.Reason,
		)
	}

	// And it has to have LOOKED. A client that accepted without asking would
	// pass the line above while being exactly the fail-open this family exists
	// to find.
	if !decision.AskedOCSP && !decision.AskedCRL {
		t.Fatal(
			"the correct client accepted without consulting revocation at all, which is the NoRevocationCheck mode wearing the correct client's name",
		)
	}
}

// The two traps that no refusal can catch still have to be measurable, and the
// only thing that separates a target which fell back from one which shrugged is
// whether it asked. This is that assertion.
func TestFallbackTrapsAreMeasuredByWhatTheClientAsked(t *testing.T) {
	cases := []struct {
		kind pki.Kind
		want func(tlsclient.Decision) bool
		why  string
	}{
		{
			kind: pki.NoOCSPServer,
			want: func(d tlsclient.Decision) bool { return d.AskedCRL },
			why:  "fall back to the CRL when the certificate names no responder",
		},
		{
			kind: pki.StapleAbsent,
			want: func(d tlsclient.Decision) bool { return d.AskedOCSP },
			why:  "query the responder directly when no staple arrives",
		},
	}

	for _, each := range cases {
		t.Run(string(each.kind), func(t *testing.T) {
			a, addr := armed(t, each.kind)

			correct := decide(t, a, addr, tlsclient.Correct, host)
			if !correct.Accepted {
				t.Fatalf(
					"the correct client refused %s; the certificate is not revoked, so accepting is right and the finding is whether it asked",
					each.kind,
				)
			}

			if !each.want(correct) {
				t.Fatalf(
					"the correct client did not %s, so this trap cannot tell a target that falls back from one that shrugs",
					each.why,
				)
			}

			blind := decide(
				t,
				a,
				addr,
				tlsclient.NoRevocationCheck,
				host,
			)
			if blind.AskedCRL || blind.AskedOCSP {
				t.Fatalf(
					"the no-revocation-check client consulted revocation anyway, so the asked-census cannot distinguish the two",
				)
			}
		})
	}
}
