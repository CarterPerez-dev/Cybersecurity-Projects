// ©AngelaMos | 2026
// server_test.go

package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	loopbackAny  = "127.0.0.1:0"
	probeTimeout = 5 * time.Second
)

// listening stands the authority up on both of its listeners, which is how
// every experiment uses it: a TLS endpoint where khaos plays the dependency,
// and an HTTP endpoint for the revocation data its certificate points at.
func listening(t *testing.T) *Authority {
	t.Helper()

	a := authority_t(t)

	if err := a.Listen(loopbackAny); err != nil {
		t.Fatalf("bind the revocation endpoints: %v", err)
	}

	if err := a.ListenTLS(loopbackAny); err != nil {
		t.Fatalf("bind the dependency: %v", err)
	}

	if err := a.Disarm(); err != nil {
		t.Fatalf("mint the honest chain: %v", err)
	}

	return a
}

// dial does what the target does: connect over TLS, verifying against the root
// the target was configured to trust, and asking for the name it expects.
func dial(t *testing.T, a *Authority) error {
	t.Helper()

	addr, err := a.TLSAddr()
	if err != nil {
		t.Fatalf("dependency address: %v", err)
	}

	conn, dialErr := tls.DialWithDialer(
		&net.Dialer{Timeout: probeTimeout},
		network,
		addr,
		&tls.Config{
			RootCAs:    a.TrustedPool(),
			ServerName: a.Host(),
			MinVersion: tls.VersionTLS12,
		},
	)
	if dialErr != nil {
		return dialErr
	}

	defer func() { _ = conn.Close() }()

	return nil
}

// The control for the whole file. A target that cannot complete a handshake
// against an unarmed authority would make every fault below unattributable.
func TestAHandshakeSucceedsAgainstAnUnarmedAuthority(t *testing.T) {
	a := listening(t)

	if err := dial(t, a); err != nil {
		t.Fatalf(
			"the honest chain was refused over a real handshake (%v); every TLS fault is measured against this",
			err,
		)
	}
}

// The fault table verifies chains in isolation. This asserts the same verdict
// survives a real handshake, because a chain that is wrong on paper and fine
// over the wire would make every experiment in the family report HELD.
func TestTheServedChainFailsAHandshakeWhenGoRefusesIt(t *testing.T) {
	for _, row := range faultTable() {
		if row.want == accepted {
			// Go accepts these, so a handshake MUST succeed. Asserting the
			// opposite would be asserting khaos's own wrong expectation.
			continue
		}

		if row.dialAs != "" {
			// Dialled by address, which this helper does not do.
			continue
		}

		t.Run(string(row.kind), func(t *testing.T) {
			a := listening(t)

			if err := a.Arm(Trap{
				Kind:   row.kind,
				Host:   a.Host(),
				Window: DefaultWindow,
				Bits:   DefaultWeakBits,
				Days:   DefaultExcessiveDays,
			}); err != nil {
				t.Fatalf("arm %s: %v", row.kind, err)
			}

			if err := dial(t, a); err == nil {
				t.Fatalf(
					"%s completed a handshake, but crypto/x509 refuses this chain; the fault is inert over the wire",
					row.kind,
				)
			}
		})
	}
}

// The seventeen traps Go ACCEPTS have to complete a handshake, or the
// experiments built on them would be measuring a connection failure khaos
// caused rather than a policy the target lacks.
func TestTheServedChainCompletesAHandshakeWhenGoAcceptsIt(t *testing.T) {
	for _, row := range faultTable() {
		if row.want != accepted {
			continue
		}

		t.Run(string(row.kind), func(t *testing.T) {
			a := listening(t)

			if err := a.Arm(Trap{
				Kind:   row.kind,
				Host:   a.Host(),
				Window: DefaultWindow,
				Bits:   DefaultWeakBits,
				Days:   DefaultExcessiveDays,
			}); err != nil {
				t.Fatalf("arm %s: %v", row.kind, err)
			}

			if err := dial(t, a); err != nil {
				t.Fatalf(
					"%s failed a handshake (%v), but crypto/x509 accepts this chain; the experiment would report a refusal khaos caused",
					row.kind,
					err,
				)
			}
		})
	}
}

// The control for both unreachable traps. Their whole design rests on the
// health route staying up while one endpoint dies: if the whole listener went
// down, khaos could not tell "I broke the responder" from "I fell over", and
// the experiment would be unattributable.
func TestAnUnreachableEndpointLeavesHealthServing(t *testing.T) {
	cases := []struct {
		kind  Kind
		route string
	}{
		{CRLUnreachable, RouteCRL},
		{OCSPUnreachable, RouteOCSP},
	}

	for _, each := range cases {
		t.Run(string(each.kind), func(t *testing.T) {
			a := listening(t)

			base, err := a.Addr()
			if err != nil {
				t.Fatalf("revocation address: %v", err)
			}

			root := schemeHTTP + base

			if status, err := get(root + each.route); err != nil ||
				status != http.StatusOK {
				t.Fatalf(
					"%s is not reachable before the trap is armed (status %d, err %v), so its refusal afterwards would prove nothing",
					each.route,
					status,
					err,
				)
			}

			if err := a.Arm(Trap{
				Kind: each.kind,
				Host: a.Host(),
			}); err != nil {
				t.Fatalf("arm %s: %v", each.kind, err)
			}

			if _, err := get(root + each.route); err == nil {
				t.Fatalf(
					"%s still answered after %s was armed; the fault is inert",
					each.route,
					each.kind,
				)
			}

			status, err := get(root + RouteHealth)
			if err != nil || status != http.StatusOK {
				t.Fatalf(
					"the health route died with %s (status %d, err %v); khaos cannot then show it broke ONE endpoint rather than falling over",
					each.kind,
					status,
					err,
				)
			}
		})
	}
}

// A revoked certificate is only a finding if the CRL khaos serves actually says
// so. This checks the served bytes rather than the intent.
func TestTheServedCRLRevokesTheServedLeaf(t *testing.T) {
	a := listening(t)

	if err := a.Arm(Trap{
		Kind: RevokedViaCRL,
		Host: a.Host(),
	}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	chain, err := a.Served()
	if err != nil {
		t.Fatalf("served chain: %v", err)
	}

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

	if err := list.CheckSignatureFrom(chain.Issuer); err != nil {
		t.Fatalf(
			"the served CRL is not signed by the leaf's own issuer (%v); a client that checks the signature would discard it and read as fail-closed for the wrong reason",
			err,
		)
	}

	if !revokes(list, chain.Leaf.SerialNumber.String()) {
		t.Fatalf(
			"the served CRL does not list serial %s; khaos would be claiming a revocation it never published",
			chain.Leaf.SerialNumber,
		)
	}

	// Freshness, because a stale CRL is a DIFFERENT fault and this one must not
	// accidentally be it.
	if !list.NextUpdate.After(a.Now()) {
		t.Fatalf(
			"the CRL for %s is already stale (NextUpdate %s); that is the StaleCRL fault, and these two have to stay distinguishable",
			RevokedViaCRL,
			list.NextUpdate,
		)
	}
}

func revokes(list *x509.RevocationList, serial string) bool {
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.String() == serial {
			return true
		}
	}

	return false
}

func get(url string) (int, error) {
	client := &http.Client{Timeout: probeTimeout}

	response, err := client.Get(url)
	if err != nil {
		return 0, err
	}

	defer func() { _ = response.Body.Close() }()

	_, _ = io.Copy(io.Discard, response.Body)

	return response.StatusCode, nil
}

func fetch(url string) ([]byte, error) {
	client := &http.Client{Timeout: probeTimeout}

	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, errors.New(
			"revocation endpoint answered " + response.Status,
		)
	}

	return io.ReadAll(response.Body)
}

// SetBase must not be overwritten by Listen. This is the identity provider's
// most expensive bug restated as a test: there, Listen replaced the pinned
// issuer with its own listener address, every credential was refused on `iss`,
// and the run blamed the target. No unit test could see it because the value
// was only wrong once a container was involved.
func TestListenDoesNotOverwriteAPinnedBase(t *testing.T) {
	const pinned = "http://host.docker.internal:48123"

	a := authority_t(t)

	a.SetBase(pinned)

	if err := a.Listen(loopbackAny); err != nil {
		t.Fatalf("listen: %v", err)
	}

	if got := a.Base(); got != pinned {
		t.Fatalf(
			"Listen replaced the pinned base with %q; the target addresses khaos by a name khaos cannot see from its own listener, so every revocation fetch would fail for a reason unrelated to the trap",
			got,
		)
	}

	if err := a.Disarm(); err != nil {
		t.Fatalf("disarm: %v", err)
	}

	chain, err := a.Served()
	if err != nil {
		t.Fatalf("served chain: %v", err)
	}

	if len(chain.Leaf.CRLDistributionPoints) == 0 {
		t.Fatal("the honest leaf names no CRL distribution point")
	}

	if !strings.HasPrefix(chain.Leaf.CRLDistributionPoints[0], pinned) {
		t.Fatalf(
			"the leaf points at %q, not the pinned base; a target following it would reach nowhere",
			chain.Leaf.CRLDistributionPoints[0],
		)
	}
}
