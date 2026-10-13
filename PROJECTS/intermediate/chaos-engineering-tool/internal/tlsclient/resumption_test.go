// ©AngelaMos | 2026
// resumption_test.go

package tlsclient_test

import (
	"crypto/tls"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/tlsclient"
)

// The resumption hole, which does not fit the matrix because it is not a
// property of one connection.
//
// crypto/tls is explicit that VerifyPeerCertificate does NOT run on a resumed
// handshake, and its doc comment tells you to use VerifyConnection or disable
// tickets instead (common.go:645-677). So an application whose pinning, staple
// validation or revocation check lives in that hook has a policy enforced on
// the FIRST handshake and skipped on every resumption afterwards, for as long
// as the ticket lives -- which Go caps at seven days (common.go:983-985).
//
// Expiry cannot survive it. Go's client re-verifies the cached chain for
// NotAfter and chain validity before offering a ticket and drops the entry if
// it fails, which research 04 section 7.4 measured. REVOCATION survives,
// because nothing anywhere checks it.
//
// The sequence this asserts is the one khaos's own phases produce: establish a
// session while the certificate is good, then revoke it, then connect again.

// session stands up an authority and returns a dialable address plus a SHARED
// session cache. The cache has to be shared or nothing resumes, and a test
// whose client cached nothing would pass while proving the opposite.
func session(t *testing.T) (*pki.Authority, string, tls.ClientSessionCache) {
	t.Helper()

	a, addr := armed(t, pki.PassThrough)

	return a, addr, tls.NewLRUClientSessionCache(0)
}

func resuming(
	t *testing.T,
	a *pki.Authority,
	cache tls.ClientSessionCache,
	mode tlsclient.Mode,
) *tlsclient.Client {
	t.Helper()

	return tlsclient.New(tlsclient.Config{
		Mode:     mode,
		Host:     host,
		Roots:    a.TrustedPool(),
		Now:      a.Now,
		Sessions: cache,
	})
}

// The control for the whole file. A session has to be ESTABLISHED and then
// actually RESUMED, or every assertion below is about a full handshake and the
// hole is never reached.
func TestASessionIsEstablishedAndThenResumed(t *testing.T) {
	a, addr, cache := session(t)

	client := resuming(t, a, cache, tlsclient.PolicyInPeerCallback)

	first := client.Decide(t.Context(), addr)
	if !first.Accepted {
		t.Fatalf("the first connection was refused: %s", first.Reason)
	}

	if first.Resumed {
		t.Fatal(
			"the FIRST connection reported itself resumed, so this test cannot tell a full handshake from a resumption",
		)
	}

	second := client.Decide(t.Context(), addr)
	if !second.Accepted {
		t.Fatalf("the second connection was refused: %s", second.Reason)
	}

	if !second.Resumed {
		t.Fatal(
			"the second connection did not resume, so nothing below exercises the resumption hole at all",
		)
	}
}

// THE fault. A policy that lives in VerifyPeerCertificate is skipped on
// resumption, so a certificate revoked after the session was established keeps
// being used.
func TestARevokedCertificateSurvivesResumption(t *testing.T) {
	a, addr, cache := session(t)

	client := resuming(t, a, cache, tlsclient.PolicyInPeerCallback)

	// Establish and cache while the certificate is good, which is what khaos's
	// baseline phase does.
	if first := client.Decide(t.Context(), addr); !first.Accepted {
		t.Fatalf("the baseline connection was refused: %s", first.Reason)
	}

	// Revoke it, which is what arming the fault does.
	if err := a.Arm(pki.Trap{
		Kind: pki.RevokedViaCRL,
		Host: host,
	}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	after := client.Decide(t.Context(), addr)

	if !after.Resumed {
		t.Fatal(
			"the connection after revocation did not resume, so this proves nothing about resumption",
		)
	}

	if !after.Accepted {
		t.Fatal(
			"the resumed connection was refused, so this client re-checks revocation on resumption and the fault is not expressible against it",
		)
	}
}

// The other half, and the one that makes the finding a finding. A client whose
// policy runs per connection catches the same revocation on the same shared
// cache, so the hole is the HOOK and not resumption itself.
func TestACorrectClientCatchesRevocationDespiteResumption(t *testing.T) {
	a, addr, cache := session(t)

	client := resuming(t, a, cache, tlsclient.Correct)

	if first := client.Decide(t.Context(), addr); !first.Accepted {
		t.Fatalf("the baseline connection was refused: %s", first.Reason)
	}

	if err := a.Arm(pki.Trap{
		Kind: pki.RevokedViaCRL,
		Host: host,
	}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	after := client.Decide(t.Context(), addr)

	if after.Accepted {
		t.Fatal(
			"the correct client used a revoked certificate, so putting the policy in the peer callback is not what made the other client vulnerable",
		)
	}
}

// The hole is WIDER than revocation, and this measures how wide.
//
// A resumed handshake does not re-send the certificate, so the chain the server
// is serving NOW is irrelevant to it. For a client whose policy lives in
// VerifyPeerCertificate that means every certificate fault is invisible for the
// ticket's lifetime, not only the ones nothing checks: an expired leaf, which
// crypto/x509 refuses outright on a full handshake, is accepted here.
//
// This is NOT the case research 04 section 7.4 measured, and the first version
// of this test confused the two. There, the CACHED certificate itself expired
// while time passed, and Go's client correctly re-verified the cached chain for
// NotAfter, dropped the entry and fell back to a full handshake that failed
// closed. That behaviour is real and is not what happens when the server swaps
// to a different, expired certificate underneath a live ticket.
func TestAResumedSessionIgnoresWhatTheServerNowServes(t *testing.T) {
	a, addr, cache := session(t)

	client := resuming(t, a, cache, tlsclient.PolicyInPeerCallback)

	if first := client.Decide(t.Context(), addr); !first.Accepted {
		t.Fatalf("the baseline connection was refused: %s", first.Reason)
	}

	if err := a.Arm(pki.Trap{
		Kind:   pki.LeafExpired,
		Host:   host,
		Window: pki.DefaultWindow,
	}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	after := client.Decide(t.Context(), addr)

	if !after.Resumed {
		t.Fatal(
			"the connection did not resume, so this says nothing about what a resumed session ignores",
		)
	}

	if !after.Accepted {
		t.Fatal(
			"the resumed connection was refused, so this client does notice a swapped certificate and the hole is narrower than it looks",
		)
	}

	// And the contrast: a client that does NOT reuse sessions sees the expired
	// certificate and refuses it, so the acceptance above is the resumption and
	// not something about the chain khaos minted.
	fresh := resuming(t, a, cache, tlsclient.Correct)

	if direct := fresh.Decide(t.Context(), addr); direct.Accepted {
		t.Fatal(
			"a client doing a full handshake also accepted the expired certificate, so the resumed acceptance proves nothing",
		)
	}
}
