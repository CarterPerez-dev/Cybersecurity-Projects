// ©AngelaMos | 2026
// revocation_test.go

package pki

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Every trap in the revocation group is ACCEPTED by crypto/x509, because Go
// performs no revocation checking of any kind. That makes the fault-table
// differential blind here: it cannot tell RevokedViaCRL from PassThrough,
// because both verify with a nil error and both complete a handshake.
//
// So this file is the group's only liveness evidence. Each case asserts the
// specific corruption in the bytes khaos actually serves, against the honest
// answer as its control. Without it, nine of these traps could be gutted to a
// no-op and the whole package would stay green.

// revocationCase is one trap and what has to be true of what khaos serves.
type revocationCase struct {
	kind Kind

	// assert reads the served artefacts and fails if the corruption is absent.
	assert func(t *testing.T, a *Authority, chain *Chain)
}

func revocationCases() []revocationCase {
	return []revocationCase{
		{RevokedViaCRL, assertCRLRevokesAndIsFresh},
		{StaleCRL, assertCRLRevokesAndIsStale},
		{CRLUnreachable, assertCRLRefuses},

		{OCSPRevoked, assertOCSPStatus(ocsp.Revoked)},
		{OCSPUnknown, assertOCSPStatus(ocsp.Unknown)},
		{OCSPTryLater, assertOCSPTryLater},
		{OCSPUnreachable, assertOCSPRefuses},
		{OCSPStale, assertOCSPStale},
		{OCSPWrongSerial, assertOCSPWrongSerial},
		{OCSPWrongSigner, assertOCSPWrongSigner},
		{NoOCSPServer, assertNoOCSPPointer},

		{StapleGarbage, assertStapleIsNotAnOCSPResponse},
		{StapleAbsent, assertNoStaple},
	}
}

// The census. A revocation trap without a case here is one khaos would arm,
// report as armed, and serve nothing different for.
func TestEveryRevocationTrapCorruptsWhatItServes(t *testing.T) {
	cases := revocationCases()

	if len(cases) != countRevocationKinds() {
		t.Fatalf(
			"this file covers %d revocation traps and the catalogue has %d; a new one needs a case here or it can be inert and stay green",
			len(cases),
			countRevocationKinds(),
		)
	}

	for _, each := range cases {
		t.Run(string(each.kind), func(t *testing.T) {
			a := listening(t)

			if err := a.Arm(Trap{
				Kind:   each.kind,
				Host:   a.Host(),
				Window: DefaultWindow,
			}); err != nil {
				t.Fatalf("arm %s: %v", each.kind, err)
			}

			chain, err := a.Served()
			if err != nil {
				t.Fatalf("served chain: %v", err)
			}

			each.assert(t, a, chain)
		})
	}
}

// countRevocationKinds is derived from GoAccepts rather than hand-counted, so
// the census cannot drift from the catalogue. The policy and trust-store traps
// are also accepted by Go but corrupt the certificate rather than its
// revocation, so they are excluded by name.
func countRevocationKinds() int {
	notRevocation := map[Kind]bool{
		WeakKey:                         true,
		ExcessiveLifetime:               true,
		KeyUsageWithoutDigitalSignature: true,
		CASwap:                          true,

		// Accepted by crypto/x509 like the rest of this group, but about the
		// TARGET's identity rather than about revocation. They have their own
		// two-sided observable in mutual.go.
		ClientCertExpired: true,
		ClientCertAbsent:  true,
	}

	count := 0

	for _, name := range Kinds() {
		kind := Kind(name)
		if GoAccepts(kind) && !notRevocation[kind] {
			count++
		}
	}

	return count
}

func servedCRL(t *testing.T, a *Authority) *x509.RevocationList {
	t.Helper()

	base, err := a.Addr()
	if err != nil {
		t.Fatalf("revocation address: %v", err)
	}

	der, err := fetch(schemeHTTP + base + RouteCRL)
	if err != nil {
		t.Fatalf("fetch the CRL: %v", err)
	}

	list, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parse the CRL: %v", err)
	}

	return list
}

func assertCRLRevokesAndIsFresh(
	t *testing.T,
	a *Authority,
	chain *Chain,
) {
	t.Helper()

	list := servedCRL(t, a)

	if !revokes(list, chain.Leaf.SerialNumber.String()) {
		t.Fatal("the served CRL does not revoke the served leaf")
	}

	if !list.NextUpdate.After(a.Now()) {
		t.Fatal(
			"the CRL is stale, which is a DIFFERENT fault; these two have to stay distinguishable or one alibis the other",
		)
	}
}

func assertCRLRevokesAndIsStale(
	t *testing.T,
	a *Authority,
	chain *Chain,
) {
	t.Helper()

	list := servedCRL(t, a)

	// The list must NOT revoke the leaf. This assertion was inverted in the
	// first draft and the matrix proved it wrong: a stale list that also
	// revokes the serial is caught by a client that ignores freshness, because
	// it still reaches the serial scan, so the broken client and the correct
	// one behave identically and the fault measures nothing.
	//
	// The fault is a three-week-old list that predates the revocation. The
	// staleness is the whole finding.
	if revokes(list, chain.Leaf.SerialNumber.String()) {
		t.Fatal(
			"the stale CRL also revokes the leaf, which makes a freshness-ignoring client refuse for the right answer by accident and the fault inert",
		)
	}

	if !list.NextUpdate.Before(a.Now()) {
		t.Fatalf(
			"the CRL's NextUpdate is %s, which is not in the past; this is then just RevokedViaCRL",
			list.NextUpdate,
		)
	}

	if !list.ThisUpdate.Before(list.NextUpdate) {
		t.Fatal(
			"ThisUpdate is not before NextUpdate, so the list is both stale and not yet issued and a client rejecting it cannot say which",
		)
	}
}

func assertCRLRefuses(t *testing.T, a *Authority, _ *Chain) {
	t.Helper()

	base, err := a.Addr()
	if err != nil {
		t.Fatalf("revocation address: %v", err)
	}

	if _, err := get(schemeHTTP + base + RouteCRL); err == nil {
		t.Fatal("the CRL endpoint still answered")
	}
}

func servedOCSP(t *testing.T, a *Authority) []byte {
	t.Helper()

	base, err := a.Addr()
	if err != nil {
		t.Fatalf("revocation address: %v", err)
	}

	der, err := fetch(schemeHTTP + base + RouteOCSP)
	if err != nil {
		t.Fatalf("fetch the OCSP response: %v", err)
	}

	return der
}

func assertOCSPStatus(want int) func(*testing.T, *Authority, *Chain) {
	return func(t *testing.T, a *Authority, chain *Chain) {
		t.Helper()

		response, err := ocsp.ParseResponseForCert(
			servedOCSP(t, a),
			chain.Leaf,
			chain.Issuer,
		)
		if err != nil {
			t.Fatalf("parse the response: %v", err)
		}

		if response.Status != want {
			t.Fatalf(
				"the responder answered status %d, want %d",
				response.Status,
				want,
			)
		}
	}
}

func assertOCSPTryLater(t *testing.T, a *Authority, chain *Chain) {
	t.Helper()

	_, err := ocsp.ParseResponseForCert(
		servedOCSP(t, a),
		chain.Leaf,
		chain.Issuer,
	)

	// TryLater is a RESPONSE STATUS, not a certificate status, so parsing is
	// supposed to fail. A nil error here would mean khaos served a real answer
	// and a soft-failing client was never given the chance to proceed on
	// nothing, which is the entire fault.
	if err == nil {
		t.Fatal(
			"the TryLater response parsed as a real answer, so the soft-fail trap is inert",
		)
	}

	var responseErr ocsp.ResponseError
	if !asResponseError(err, &responseErr) {
		t.Fatalf("expected an ocsp.ResponseError, got %v", err)
	}

	if responseErr.Status != ocsp.TryLater {
		t.Fatalf(
			"the responder answered response status %v, want TryLater",
			responseErr.Status,
		)
	}
}

func assertOCSPRefuses(t *testing.T, a *Authority, _ *Chain) {
	t.Helper()

	base, err := a.Addr()
	if err != nil {
		t.Fatalf("revocation address: %v", err)
	}

	if _, err := get(schemeHTTP + base + RouteOCSP); err == nil {
		t.Fatal("the OCSP endpoint still answered")
	}
}

func assertOCSPStale(t *testing.T, a *Authority, chain *Chain) {
	t.Helper()

	response, err := ocsp.ParseResponseForCert(
		servedOCSP(t, a),
		chain.Leaf,
		chain.Issuer,
	)
	// Measured: x/crypto/ocsp does NOT check freshness, so a stale response
	// parses with a nil error. That is the fault, so a parse failure here would
	// mean khaos had corrupted something else as well.
	if err != nil {
		t.Fatalf(
			"the stale response failed to parse (%v); x/crypto/ocsp does not check freshness, so this means something else is wrong with it too",
			err,
		)
	}

	if response.Status != ocsp.Good {
		t.Fatalf(
			"the stale response says status %d; it has to be Good, or a client refusing it is refusing the status and not the staleness",
			response.Status,
		)
	}

	if !response.NextUpdate.Before(a.Now()) {
		t.Fatalf(
			"NextUpdate is %s, which is not in the past, so the response is simply correct",
			response.NextUpdate,
		)
	}
}

func assertOCSPWrongSerial(t *testing.T, a *Authority, chain *Chain) {
	t.Helper()

	der := servedOCSP(t, a)

	// The whole fault in one pair of assertions, and it is why this trap is the
	// most valuable in the group: the bypass is one word of caller code.
	if _, err := ocsp.ParseResponseForCert(
		der,
		chain.Leaf,
		chain.Issuer,
	); err == nil {
		t.Fatal(
			"ParseResponseForCert accepted a response minted for another serial, so the trap is inert",
		)
	}

	loose, err := ocsp.ParseResponse(der, chain.Issuer)
	if err != nil {
		t.Fatalf(
			"ParseResponse rejected it too (%v); the fault only exists because that call does NOT bind the response to the certificate",
			err,
		)
	}

	if loose.Status != ocsp.Good {
		t.Fatalf(
			"the loose parse reports status %d, want Good; a caller reading Status has to be handed an apparently fine answer",
			loose.Status,
		)
	}

	if loose.SerialNumber.Cmp(chain.Leaf.SerialNumber) == 0 {
		t.Fatal(
			"the response is for the served leaf's own serial, so nothing is being substituted",
		)
	}
}

func assertOCSPWrongSigner(t *testing.T, a *Authority, chain *Chain) {
	t.Helper()

	if _, err := ocsp.ParseResponseForCert(
		servedOCSP(t, a),
		chain.Leaf,
		chain.Issuer,
	); err == nil {
		t.Fatal(
			"a response signed by an undelegated key was accepted, so the trap is inert",
		)
	}
}

func assertNoOCSPPointer(t *testing.T, _ *Authority, chain *Chain) {
	t.Helper()

	if len(chain.Leaf.OCSPServer) != 0 {
		t.Fatalf(
			"the leaf still names %v as a responder, so there is something to ask and the fault is inert",
			chain.Leaf.OCSPServer,
		)
	}

	// The CRL pointer has to SURVIVE. The fault asks what a target does when
	// OCSP is gone, and the honest answer is to fall back to the CRL; removing
	// both would make it an outage instead.
	if len(chain.Leaf.CRLDistributionPoints) == 0 {
		t.Fatal(
			"the leaf names no CRL distribution point either, so this is a total revocation outage rather than the end of OCSP",
		)
	}
}

func assertStapleIsNotAnOCSPResponse(
	t *testing.T,
	_ *Authority,
	chain *Chain,
) {
	t.Helper()

	if len(chain.Staple) == 0 {
		t.Fatal(
			"no staple was attached, which is the StapleAbsent fault and not this one",
		)
	}

	if _, err := ocsp.ParseResponse(chain.Staple, chain.Issuer); err == nil {
		t.Fatal(
			"the garbage staple parsed as a real OCSP response, so it is not garbage",
		)
	}
}

func assertNoStaple(t *testing.T, _ *Authority, chain *Chain) {
	t.Helper()

	if len(chain.Staple) != 0 {
		t.Fatalf(
			"a %d-byte staple was attached, so the fault is inert",
			len(chain.Staple),
		)
	}
}

// The control for the whole file. An unarmed authority has to serve a fresh CRL
// that revokes nothing and a Good, in-date, correctly signed OCSP response. If
// it did not, every assertion above would be comparing one broken answer with
// another.
func TestAnUnarmedAuthoritySaysTheCertificateIsFine(t *testing.T) {
	a := listening(t)

	chain, err := a.Served()
	if err != nil {
		t.Fatalf("served chain: %v", err)
	}

	list := servedCRL(t, a)

	if revokes(list, chain.Leaf.SerialNumber.String()) {
		t.Fatal("the honest CRL revokes the honest leaf")
	}

	if !list.NextUpdate.After(a.Now()) {
		t.Fatal("the honest CRL is already stale")
	}

	response, err := ocsp.ParseResponseForCert(
		servedOCSP(t, a),
		chain.Leaf,
		chain.Issuer,
	)
	if err != nil {
		t.Fatalf("the honest OCSP response does not parse: %v", err)
	}

	if response.Status != ocsp.Good {
		t.Fatalf("the honest responder says status %d", response.Status)
	}

	if !response.NextUpdate.After(a.Now()) {
		t.Fatal("the honest OCSP response is already stale")
	}

	if len(chain.Staple) == 0 {
		t.Fatal(
			"the honest chain carries no staple, so StapleAbsent has nothing to remove and that fault is inert",
		)
	}

	if time.Since(response.ProducedAt) > time.Hour {
		t.Fatalf(
			"the honest response was produced at %s, which is not now",
			response.ProducedAt,
		)
	}
}

// asResponseError unwraps an ocsp.ResponseError. x/crypto returns it by value,
// but errors.As handles that and survives a future wrap, which a bare type
// assertion would not.
func asResponseError(err error, into *ocsp.ResponseError) bool {
	return errors.As(err, into)
}
