// ©AngelaMos | 2026
// verify_test.go

package pki

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

// outcome is what a correct client's verification does with a chain. It is the
// error TYPE plus the InvalidReason integer, never the error string: research
// 04 is explicit that the strings embed timestamps and name lists, so matching
// on them would make these assertions drift with the clock.
type outcome int

const (
	// accepted is a nil error from Verify. For seventeen of these traps that is
	// the CORRECT result and the whole point of the fault.
	accepted outcome = iota
	invalid
	hostname
	authority
)

func (o outcome) String() string {
	switch o {
	case accepted:
		return "accepted"
	case invalid:
		return "x509.CertificateInvalidError"
	case hostname:
		return "x509.HostnameError"
	case authority:
		return "x509.UnknownAuthorityError"
	default:
		return "unknown"
	}
}

// classify maps whatever Verify returned onto the taxonomy, so a trap that
// fails for an unexpected REASON is distinguishable from one that fails as
// designed.
func classify(err error) (outcome, x509.InvalidReason) {
	if err == nil {
		return accepted, 0
	}

	var bad x509.CertificateInvalidError
	if errors.As(err, &bad) {
		return invalid, bad.Reason
	}

	var wrongName x509.HostnameError
	if errors.As(err, &wrongName) {
		return hostname, 0
	}

	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return authority, 0
	}

	return -1, 0
}

type expectation struct {
	kind   Kind
	want   outcome
	reason x509.InvalidReason
	detail string

	// dialAs is the name the client asks for, and it is not always the host the
	// certificate was minted for. NoIPSAN is the reason this field exists: a
	// certificate with no IP SANs is perfectly correct for a client dialling by
	// NAME, and is only a fault for one dialling by address. Asserting it
	// through a DNS name would record it as accepted and the experiment built on
	// that row would measure nothing.
	dialAs string
}

// The table. Every row came from the research's measured fault table, and this
// test is the differential that keeps khaos's minting honest about it: if Go
// changes what it enforces, or if a defect builder stops expressing its fault,
// the row goes red rather than the experiment silently measuring nothing.
func faultTable() []expectation {
	return []expectation{
		// Validity. Both leaf faults share Reason 1 because there is no
		// separate not-yet-valid reason, so the Detail wording is the only
		// thing telling them apart. That trap is the reason detail exists here.
		{LeafExpired, invalid, x509.Expired, "is after", ""},
		{LeafNotYetValid, invalid, x509.Expired, "is before", ""},
		{IntermediateExpired, invalid, x509.Expired, "is after", ""},

		// Identity. NoIPSAN is dialled by address on purpose; see dialAs.
		{WrongSAN, hostname, 0, "", ""},
		{CommonNameOnly, hostname, 0, "", ""},
		{NoIPSAN, hostname, 0, "", loopbackIP},

		// Authority. These three are the family's reason for existing: all of
		// them are UnknownAuthorityError with no reason code and an identical
		// string, so nothing a target logs can tell an operator which happened.
		{SelfSigned, authority, 0, "", ""},
		{UntrustedCA, authority, 0, "", ""},
		{MissingIntermediate, authority, 0, "", ""},
		{IssuerNotCA, authority, 0, "", ""},
		{
			NameConstraintViolation,
			invalid,
			x509.CANotAuthorizedForThisName,
			"",
			"",
		},
		{PathLengthExceeded, invalid, x509.TooManyIntermediates, "", ""},

		// Algorithm. SHA-1 arrives wrapped inside an authority error, which is
		// itself the finding: a caller that does not unwrap blames the CA.
		{SHA1Signature, authority, 0, "", ""},

		{EKUClientAuthOnly, invalid, x509.IncompatibleUsage, "", ""},
		{EKUConstrainedIntermediate, invalid, x509.IncompatibleUsage, "", ""},

		// Policy. Go returns nil for all three. These do not test x509 at all;
		// they test whether the target has a floor of its own.
		{WeakKey, accepted, 0, "", ""},
		{ExcessiveLifetime, accepted, 0, "", ""},
		{KeyUsageWithoutDigitalSignature, accepted, 0, "", ""},

		// Revocation. Every one of these is accepted, because Go performs no
		// revocation checking of any kind and there is no option to turn it on.
		// That is the single most important fact in this family.
		{RevokedViaCRL, accepted, 0, "", ""},
		{StaleCRL, accepted, 0, "", ""},
		{CRLUnreachable, accepted, 0, "", ""},
		{OCSPRevoked, accepted, 0, "", ""},
		{OCSPUnknown, accepted, 0, "", ""},
		{OCSPTryLater, accepted, 0, "", ""},
		{OCSPUnreachable, accepted, 0, "", ""},
		{OCSPStale, accepted, 0, "", ""},
		{OCSPWrongSerial, accepted, 0, "", ""},
		{OCSPWrongSigner, accepted, 0, "", ""},
		{NoOCSPServer, accepted, 0, "", ""},
		{StapleGarbage, accepted, 0, "", ""},
		{StapleAbsent, accepted, 0, "", ""},

		// Trust store. Accepted BY CONSTRUCTION: khaos moved the anchor, so the
		// chain is genuinely valid under what the target now trusts. Nothing in
		// a client can detect this.
		{CASwap, accepted, 0, "", ""},

		// Mutual TLS. Accepted because the DEPENDENCY's certificate is
		// impeccable for both: the defect is in the target's own identity and
		// the rejection happens on khaos's side of the connection, which
		// Certificate.Verify knows nothing about. What a client sees depends on
		// the protocol version, and under TLS 1.3 it sees a successful Dial.
		{ClientCertExpired, accepted, 0, "", ""},
		{ClientCertAbsent, accepted, 0, "", ""},
	}
}

const (
	testHost = "dependency.khaos.invalid"

	// loopbackIP is what the NoIPSAN row dials. Verifying by address is the
	// only way that fault exists at all.
	loopbackIP = "127.0.0.1"
)

func authority_t(t *testing.T) *Authority {
	t.Helper()

	a, err := New(Config{Host: testHost})
	if err != nil {
		t.Fatalf("build an authority: %v", err)
	}

	t.Cleanup(func() { _ = a.Close() })

	return a
}

// verifyAsClient does exactly what a correct client does and nothing more: it
// anchors on the root the TARGET trusts, supplies only the intermediates the
// handshake actually presented, and checks the name it asked for.
//
// Supplying khaos's real intermediate here regardless of what was presented
// would quietly repair MissingIntermediate, and that row would then pass for
// the wrong reason.
func verifyAsClient(
	t *testing.T,
	a *Authority,
	chain *Chain,
	host string,
) error {
	t.Helper()

	intermediates, err := chain.PresentedPool()
	if err != nil {
		t.Fatalf("parse the presented chain: %v", err)
	}

	_, verifyErr := chain.Leaf.Verify(x509.VerifyOptions{
		Roots:         a.TrustedPool(),
		Intermediates: intermediates,
		DNSName:       host,
		CurrentTime:   a.Now(),
	})

	return verifyErr
}

func TestEveryTrapProducesTheMeasuredClientOutcome(t *testing.T) {
	table := faultTable()

	// The census. A trap without a row here is a fault khaos would arm and then
	// never check the meaning of, which is how a family ends up with an
	// experiment that measures nothing.
	if len(table) != len(Kinds()) {
		t.Fatalf(
			"the fault table has %d rows and khaos advertises %d traps; a new trap needs a row",
			len(table),
			len(Kinds()),
		)
	}

	for _, row := range table {
		t.Run(string(row.kind), func(t *testing.T) {
			a := authority_t(t)

			trap := Trap{
				Kind:   row.kind,
				Host:   testHost,
				Window: DefaultWindow,
				Bits:   DefaultWeakBits,
				Days:   DefaultExcessiveDays,
			}

			if err := a.Arm(trap); err != nil {
				t.Fatalf("arm %s: %v", row.kind, err)
			}

			chain, err := a.Served()
			if err != nil {
				t.Fatalf("served chain: %v", err)
			}

			host := testHost
			if row.dialAs != "" {
				host = row.dialAs
			}

			got, reason := classify(verifyAsClient(t, a, chain, host))

			if got != row.want {
				t.Fatalf(
					"%s verified as %s, want %s (err: %v)",
					row.kind,
					got,
					row.want,
					verifyAsClient(t, a, chain, host),
				)
			}

			if row.want == invalid && reason != row.reason {
				t.Fatalf(
					"%s gave InvalidReason %d, want %d; two traps sharing a reason are only distinguishable by it",
					row.kind,
					reason,
					row.reason,
				)
			}

			if row.detail != "" {
				assertDetail(t, verifyAsClient(t, a, chain, host), row)
			}
		})
	}
}

func assertDetail(t *testing.T, err error, row expectation) {
	t.Helper()

	var bad x509.CertificateInvalidError
	if !errors.As(err, &bad) {
		t.Fatalf(
			"%s: expected a CertificateInvalidError, got %v",
			row.kind,
			err,
		)
	}

	if !strings.Contains(bad.Detail, row.detail) {
		t.Fatalf(
			"%s detail is %q, which does not contain %q; expired and not-yet-valid share a reason code and this substring is the only thing separating them",
			row.kind,
			bad.Detail,
			row.detail,
		)
	}
}

// GoAccepts is the predicate that decides what an acceptance MEANS, so it must
// agree with what Go actually did rather than with what the catalogue claims.
// This is the differential: the table above is measured against crypto/x509,
// and this asserts the predicate matches the table row for row.
func TestGoAcceptsAgreesWithMeasuredVerification(t *testing.T) {
	for _, row := range faultTable() {
		t.Run(string(row.kind), func(t *testing.T) {
			claimed := GoAccepts(row.kind)
			measured := row.want == accepted

			if claimed != measured {
				t.Fatalf(
					"GoAccepts(%s) says %v but verification measured %v; the predicate decides whether an acceptance is a defect or merely the absence of a policy, so a wrong answer here makes khaos accuse a target of something that did not happen",
					row.kind,
					claimed,
					measured,
				)
			}
		})
	}
}

// The control for the whole file. If an unarmed authority served anything a
// correct client refused, every row above would be measuring khaos's own broken
// baseline rather than the trap.
func TestAnUnarmedAuthorityServesAChainAClientAccepts(t *testing.T) {
	a := authority_t(t)

	if err := a.Disarm(); err != nil {
		t.Fatalf("disarm: %v", err)
	}

	chain, err := a.Served()
	if err != nil {
		t.Fatalf("served chain: %v", err)
	}

	if err := verifyAsClient(t, a, chain, testHost); err != nil {
		t.Fatalf(
			"the honest chain was refused (%v); every fault in this family is measured against it, so a broken control establishes nothing",
			err,
		)
	}

	if chain.Leaf.NotAfter.Sub(chain.Leaf.NotBefore) >
		time.Duration(LifetimeCapDays)*24*time.Hour {
		t.Fatal(
			"the honest leaf is already over the lifetime cap, so the excessive-lifetime trap has nothing to exceed",
		)
	}
}
