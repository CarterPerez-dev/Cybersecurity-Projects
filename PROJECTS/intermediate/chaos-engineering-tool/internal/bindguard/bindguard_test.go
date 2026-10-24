// ©AngelaMos | 2026
// bindguard_test.go

package bindguard

import (
	"errors"
	"strings"
	"testing"
)

const subject = "a listener under test"

// The syntactic branches, which are the ones no tier's own test reaches: the
// proxy's cases cover the wildcards and this host's routable address, and the
// authorization tier's cover the wildcards again, so a privileged port was
// refused by code nothing exercised. Loopback is in the same table because a
// guard that refuses everything is not a guard.
func TestTheGuardRefusesWhatItMustAndAcceptsLoopback(t *testing.T) {
	for _, row := range []struct {
		name string
		addr string
		want bool
	}{
		{name: "an ipv4 wildcard", addr: "0.0.0.0:45999", want: false},
		{name: "a bare port", addr: ":45999", want: false},
		{name: "an ipv6 wildcard", addr: "[::]:45999", want: false},
		{name: "a privileged port", addr: "127.0.0.1:80", want: false},
		{name: "the last privileged port", addr: "127.0.0.1:1023", want: false},
		{name: "not a host and port", addr: "not-an-address", want: false},
		{name: "a hostname rather than an ip", addr: "localhost:45999", want: false},
		{name: "no port at all", addr: "127.0.0.1", want: false},
		{name: "loopback on a high port", addr: "127.0.0.1:45999", want: true},
		{name: "loopback on an ephemeral port", addr: "127.0.0.1:0", want: true},
		{
			name: "the first unprivileged port",
			addr: "127.0.0.1:1024",
			want: true,
		},
		{name: "ipv6 loopback", addr: "[::1]:45999", want: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := Check(row.addr, subject)

			if row.want && err != nil {
				t.Fatalf(
					"%s was refused (%v); a guard that refuses an address khaos has to use stops the tier from running at all",
					row.addr,
					err,
				)
			}

			if row.want {
				return
			}

			if err == nil {
				t.Fatalf("%s was accepted", row.addr)
			}

			if !errors.Is(err, ErrUnsafeBind) {
				t.Fatalf("%s: err = %v, want ErrUnsafeBind", row.addr, err)
			}
		})
	}
}

// The refusal has to name what was about to be exposed, in the tier's own
// words, because one sentinel now serves several listeners and "khaos will not
// bind there" alone does not tell an operator which one.
func TestAWildcardRefusalNamesTheSubject(t *testing.T) {
	err := Check("0.0.0.0:45999", subject)
	if err == nil {
		t.Fatal("a wildcard was accepted")
	}

	if !strings.Contains(err.Error(), subject) {
		t.Fatalf(
			"the refusal does not say what it was about to expose: %v",
			err,
		)
	}
}

// Managed is the check a kernel bridge cannot satisfy. Measured on the
// development host when this was written: a CNI pod bridge at 10.42.0.1, a
// swarm gateway bridge at 172.23.0.1 and forty-nine user-defined bridges, one
// of them carrying nine containers of an unrelated project -- every one of them
// carrying the sysfs marker Check reads, and none of them an address khaos
// should serve an allow-everything listener on.
func TestManagedTakesTheAllowedSetFromTheDaemon(t *testing.T) {
	gateways := []string{"172.17.0.1", "10.244.244.1"}

	for _, row := range []struct {
		name string
		addr string
		set  []string
		want bool
	}{
		{
			name: "a gateway the daemon manages",
			addr: "172.17.0.1:45999",
			set:  gateways,
			want: true,
		},
		{
			name: "another one it manages",
			addr: "10.244.244.1:45999",
			set:  gateways,
			want: true,
		},
		{
			name: "loopback, which needs no daemon",
			addr: "127.0.0.1:45999",
			set:  nil,
			want: true,
		},
		{
			name: "a CNI pod bridge, which carries the sysfs marker",
			addr: "10.42.0.1:45999",
			set:  gateways,
			want: false,
		},
		{
			name: "a host interface enslaved to a bridge",
			addr: "192.168.1.183:45999",
			set:  gateways,
			want: false,
		},
		{
			name: "an empty set is a refusal, not a pass",
			addr: "172.17.0.1:45999",
			set:  nil,
			want: false,
		},
		{
			name: "a wildcard, which names no address at all",
			addr: "0.0.0.0:45999",
			set:  gateways,
			want: false,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := Managed(row.addr, subject, row.set)

			if row.want && err != nil {
				t.Fatalf("%s was refused: %v", row.addr, err)
			}

			if row.want {
				return
			}

			if err == nil {
				t.Fatalf("%s was accepted", row.addr)
			}

			if !errors.Is(err, ErrUnsafeBind) {
				t.Fatalf("%s: err = %v, want ErrUnsafeBind", row.addr, err)
			}
		})
	}
}
