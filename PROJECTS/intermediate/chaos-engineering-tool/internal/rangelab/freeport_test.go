// ©AngelaMos | 2026
// freeport_test.go

package rangelab

import (
	"net"
	"testing"
)

func TestAPortTakenOnAnyRequiredAddressIsNotFree(t *testing.T) {
	// A second loopback address stands in for the bridge gateway: it is a
	// different address on the same host, which is the whole property under
	// test, and it needs no daemon.
	const other = "127.0.0.2"

	probe, err := net.Listen("tcp", net.JoinHostPort(other, "0"))
	if err != nil {
		t.Skipf("this host has no second loopback address to bind: %v", err)
	}

	taken := probe.Addr().(*net.TCPAddr).Port

	defer func() { _ = probe.Close() }()

	// Free on 127.0.0.1 and taken on the other address, which is exactly the
	// case the old check passed.
	if !freeOn(taken, []string{loopback}) {
		t.Skipf(
			"port %d is also taken on loopback, so this case is not set up",
			taken,
		)
	}

	if freeOn(taken, []string{loopback, other}) {
		t.Fatalf(
			"port %d read as free while something is listening on it at %s; a tier binding that address would fail where khaos said it would not",
			taken,
			other,
		)
	}
}

// AND FreePort has to actually USE the extra addresses, which the case above
// does not prove: it calls the predicate directly, so a FreePort that ignored
// its argument passed it. Measured by gutting, which stayed green.
//
// This is deterministic rather than probabilistic. 192.0.2.1 is TEST-NET-1 and
// is not assigned to this host, so NO port can be bound on it -- every
// candidate fails, and the only way FreePort can succeed is by not testing the
// address it was given.
func TestFreePortActuallyTestsTheAddressesItIsGiven(t *testing.T) {
	const unbindable = "192.0.2.1"

	if _, err := net.Listen(
		"tcp",
		net.JoinHostPort(unbindable, "0"),
	); err == nil {
		t.Skip(
			"this host can bind TEST-NET-1, so it cannot stand in for an address no port is free on",
		)
	}

	if port, err := FreePort(unbindable); err == nil {
		t.Fatalf(
			"FreePort returned %d while checking an address it cannot bind any port on, so it is not testing the addresses it is given",
			port,
		)
	}

	// And without it, the same call still has to answer, or the guard is a
	// range that cannot come up.
	if _, err := FreePort(); err != nil {
		t.Fatalf("FreePort with no extra addresses failed: %v", err)
	}
}

// And the allocator still has to return something usable, or the fix is a
// range that cannot come up.
func TestFreePortsStillAnswersWithEveryPortDistinct(t *testing.T) {
	const other = "127.0.0.2"

	chosen, err := FreePorts(other)
	if err != nil {
		t.Fatalf("FreePorts: %v", err)
	}

	seen := map[int]bool{}

	for _, port := range []int{
		chosen.Gateway, chosen.Proxied, chosen.Proxy, chosen.Verifier,
		chosen.IdP, chosen.TLS, chosen.Authority, chosen.Dependency,
		chosen.DNS, chosen.DBGateway, chosen.Secret, chosen.Env,
		chosen.Authz, chosen.AuthzDep,
	} {
		if port < portFloor || port >= portCeil {
			t.Fatalf("port %d is outside the high range khaos picks from", port)
		}

		if seen[port] {
			t.Fatalf("port %d was handed out twice", port)
		}

		seen[port] = true

		if !freeOn(port, []string{loopback, other}) {
			t.Fatalf(
				"port %d was handed out while taken on one of the addresses it was checked against",
				port,
			)
		}
	}
}
