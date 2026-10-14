// ©AngelaMos | 2026
// tlstier_test.go

package experiment

import (
	"strconv"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/pki"
)

// The CLI's advertised default and the authority's own fallback are two copies
// of the same magnitude, and only one of them is validated at arm time. Two of
// the three are derived from the pki constant; cert-window cannot be, because a
// time.Duration renders as "24h0m0s" and the help text should read "24h". This
// asserts the invariant instead, so a drift fails here rather than in front of
// an operator.
func TestCertDefaultsSurviveTheAuthoritysOwnValidation(t *testing.T) {
	cases := []struct {
		param Param
		trap  pki.Trap
	}{
		{
			param: certBitsParam,
			trap:  pki.Trap{Kind: pki.WeakKey, Host: pki.DefaultHost},
		},
		{
			param: certDaysParam,
			trap: pki.Trap{
				Kind: pki.ExcessiveLifetime,
				Host: pki.DefaultHost,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.param.Name, func(t *testing.T) {
			magnitude, err := strconv.Atoi(c.param.Default)
			if err != nil {
				t.Fatalf(
					"%s default %q is not a number: %v",
					c.param.Name,
					c.param.Default,
					err,
				)
			}

			trap := c.trap
			switch trap.Kind {
			case pki.WeakKey:
				trap.Bits = magnitude
			case pki.ExcessiveLifetime:
				trap.Days = magnitude
			default:
				t.Fatalf("no magnitude field for %s", trap.Kind)
			}

			if err := trap.Validate(); err != nil {
				t.Fatalf(
					"the advertised default for %s cannot be armed: %v",
					c.param.Name,
					err,
				)
			}
		})
	}
}

func TestCertWindowDefaultMatchesTheAuthoritysFallback(t *testing.T) {
	parsed, err := time.ParseDuration(certWindowParam.Default)
	if err != nil {
		t.Fatalf(
			"cert-window default %q does not parse: %v",
			certWindowParam.Default,
			err,
		)
	}

	if parsed != pki.DefaultWindow {
		t.Fatalf(
			"cert-window advertises %s where the authority falls back to %s",
			parsed,
			pki.DefaultWindow,
		)
	}

	trap := pki.Trap{
		Kind:   pki.LeafExpired,
		Host:   pki.DefaultHost,
		Window: parsed,
	}

	if err := trap.Validate(); err != nil {
		t.Fatalf("the advertised cert-window cannot be armed: %v", err)
	}
}
