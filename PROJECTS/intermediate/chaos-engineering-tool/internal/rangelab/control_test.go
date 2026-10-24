// ©AngelaMos | 2026
// control_test.go

package rangelab

import (
	"errors"
	"strings"
	"testing"
)

// controlPort is the only address parser in the project that accepts two
// shapes: the limiter's datastore is a bare host:port and the other two
// controls are URLs. Neither its success paths nor its three refusals had a
// test, and a port it misreads is a proxy khaos binds where nothing dials.
func TestControlPortReadsBothAddressShapes(t *testing.T) {
	for _, row := range []struct {
		name    string
		address string
		want    int
	}{
		{"a bare host and port", "host.docker.internal:34567", 34567},
		{"a URL", "http://host.docker.internal:34567", 34567},
		{"a loopback URL", "http://127.0.0.1:1", 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			port, err := controlPort(row.address)
			if err != nil {
				t.Fatalf("controlPort(%q): %v", row.address, err)
			}

			if port != row.want {
				t.Fatalf("port = %d, want %d", port, row.want)
			}
		})
	}
}

// Each refusal names the address it could not read, because an operator
// seeing "khaos cannot read that" needs to know which of three it meant.
func TestControlPortRefusesWhatItCannotRead(t *testing.T) {
	for _, row := range []struct{ name, address string }{
		{"no port at all", "host.docker.internal"},
		{"port zero", "host.docker.internal:0"},
		{"a non-numeric port", "host.docker.internal:redis"},
		{"a URL with no port", "http://host.docker.internal"},
		{"an empty address", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			port, err := controlPort(row.address)
			if err == nil {
				t.Fatalf(
					"controlPort(%q) returned %d rather than refusing",
					row.address,
					port,
				)
			}

			if !errors.Is(err, ErrRangeIncomplete) {
				t.Fatalf("the refusal is not a range-incomplete: %v", err)
			}
		})
	}
}

// The two ways this tier can be missing need different fixes, so they are
// different refusals: no gateway means bring the range up, and a gateway
// carrying no dependency address means that container predates the variable.
func TestRequireControlTierSeparatesTheTwoWaysItIsMissing(t *testing.T) {
	absent := Lab{}

	err := absent.RequireControlTier(ControlPolicy)
	if err == nil {
		t.Fatal("a range with no control gateway was not refused")
	}

	if !strings.Contains(err.Error(), ControlGatewayName) {
		t.Fatalf("the refusal does not name the missing gateway: %v", err)
	}

	// The gateway is there and carries no address for THIS control, which is
	// a different fix: the container has to be recreated.
	partial := Lab{
		ControlPort:      30015,
		ControlStoreAddr: "host.docker.internal:30016",
	}

	err = partial.RequireControlTier(ControlPolicy)
	if err == nil {
		t.Fatal(
			"a gateway carrying no policy-store address was not refused",
		)
	}

	if !strings.Contains(err.Error(), EnvPolicyStore) {
		t.Fatalf(
			"the refusal does not name the variable that is missing: %v",
			err,
		)
	}

	// And the control that IS wired must not be refused, or one missing
	// address would take the other two experiments down with it.
	if err := partial.RequireControlTier(ControlLimiter); err != nil {
		t.Fatalf(
			"the limiter was refused although its address is present: %v",
			err,
		)
	}
}

// Each control resolves to its OWN address and variable. Collapsing any two
// would make khaos sever one dependency while reporting another.
func TestEachControlResolvesItsOwnDependency(t *testing.T) {
	lab := Lab{
		ControlPort:       30015,
		ControlStoreAddr:  "host.docker.internal:30016",
		ControlPolicyAddr: "http://host.docker.internal:30017",
		ControlRulesAddr:  "http://host.docker.internal:30018",
	}

	seen := map[string]Control{}

	for _, at := range []Control{
		ControlLimiter,
		ControlPolicy,
		ControlRules,
	} {
		address, variable := lab.controlDependency(at)

		if address == "" || variable == "" {
			t.Fatalf("%s resolved to %q / %q", at, address, variable)
		}

		if other, clash := seen[address]; clash {
			t.Fatalf(
				"%s and %s both resolve to %s, so one fault would sever both",
				at,
				other,
				address,
			)
		}

		seen[address] = at
	}
}
