// ©AngelaMos | 2026
// dnsfault_test.go

package inject

import (
	"slices"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
)

// daemonKinds is the CLOSED set of mutations `khaos inject` may offer: the ones
// whose whole subject is a container the daemon can be told about.
//
// It is pinned by NAME on purpose, and the reason is a defect. Deriving the
// exclusion from the registry is necessary but not sufficient: a sixth tier that
// forgets to declare itself per-run is simply absent from the derived prefix
// list, the IFF assertion still holds, and `khaos inject` quietly advertises a
// command that cannot succeed. That is exactly how thirty-six `pki-*` kinds
// shipped. A literal allowlist fails loudly and names them, and this set is
// closed by its own definition rather than by convention.
var daemonKinds = []string{KindPause, KindDisconnect}

func TestDirectKindsIsExactlyTheDaemonKinds(t *testing.T) {
	direct := DirectKinds()

	for _, kind := range direct {
		if !slices.Contains(daemonKinds, kind) {
			t.Errorf(
				"`khaos inject` offers %s, which is not a mutation the daemon "+
					"can be told about; either it belongs in daemonKinds or its "+
					"tier never declared Prefix()",
				kind,
			)
		}
	}

	for _, kind := range daemonKinds {
		if !slices.Contains(direct, kind) {
			t.Errorf("`khaos inject` no longer offers %s", kind)
		}
	}
}

// TestEveryDNSFaultIsRegistered is the census. A fault in the resolver's
// catalogue with no mutation is one `khaos catalog` could advertise and the
// engine could not apply, and the masked faults are included deliberately: they
// have to be reachable in order to be refused by name.
func TestEveryDNSFaultIsRegistered(t *testing.T) {
	for _, name := range dnsrv.Kinds() {
		kind := DNSKind(dnsrv.Kind(name))

		// Lookup must RESOLVE it: the engine gets its mutator from there for
		// every tier. Only Lookup's error message is restricted to the direct
		// kinds, so that a typo is answered with the kinds an operator can
		// actually ask for.
		if _, err := Lookup(kind); err != nil {
			t.Errorf("the engine cannot resolve %s: %v", kind, err)
		}

		if _, ok := registry[kind]; !ok {
			t.Errorf("no mutation is registered for DNS fault %s", name)
		}

		if !NeedsResolver(kind) {
			t.Errorf("%s does not ask the run for a resolver", kind)
		}

		if IsDirect(kind) {
			t.Errorf("`khaos inject` offers %s, which needs a resolver it "+
				"never starts", kind)
		}
	}
}

// TestNeedsResolverIsDerivedFromTheRegistry guards against the shape that gave
// the proxy and identity tiers their own bugs: a predicate that keys off the
// kind's spelling agrees with itself about a kind that does not exist.
func TestNeedsResolverIsDerivedFromTheRegistry(t *testing.T) {
	if NeedsResolver(KindDNSPrefix + "not-a-real-fault") {
		t.Error("NeedsResolver answered yes for a kind no mutation is " +
			"registered under, so it is reading the name rather than the registry")
	}

	for _, kind := range Kinds() {
		if strings.HasPrefix(kind, KindDNSPrefix) != NeedsResolver(kind) {
			t.Errorf("%s: NeedsResolver reports %v", kind, NeedsResolver(kind))
		}
	}
}
