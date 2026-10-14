// ©AngelaMos | 2026
// tlstier.go

package experiment

import (
	"fmt"
	"strconv"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/pki"
)

const (
	// Two parameters, not one: khaos binds the bridge gateway's address while the
	// target addresses `host.docker.internal`, so a URL derived from khaos's own
	// listener is unreachable from the target's network namespace.
	ParamAuthorityListen = "authority-listen"
	ParamAuthorityTLS    = "authority-tls"
	ParamAuthorityBase   = "authority-base"
	ParamCertHost        = "cert-host"

	usageAuthorityListen = "the host address khaos binds its CRL and OCSP endpoints on; it has to be a Docker bridge address, because a container cannot reach loopback and khaos will not bind a wildcard"
	usageAuthorityTLS    = "the host address khaos binds the faulted dependency's TLS listener on, which must be the address your target already dials for this dependency"
	usageAuthorityBase   = "the URL the TARGET uses to reach khaos's CRL and OCSP endpoints, which is not necessarily the address khaos binds"
	usageCertHost        = "the name khaos mints its certificates for, which must be the name the target asks for"

	usageCertWindow = "how far to move the boundary a time-based certificate fault corrupts: how long ago the leaf expired, how stale the revocation answer is"
	usageCertBits   = "the RSA modulus size the weak-key fault mints, which has to be below whatever floor the target imposes for the fault to be expressible"
	usageCertDays   = "the leaf lifetime the excessive-lifetime fault mints, in days"

	ParamCertWindow = "cert-window"
	ParamCertBits   = "cert-bits"
	ParamCertDays   = "cert-days"

	defaultCertWindow = "24h"

	tlsCondition = "%s reaching a dependency whose certificate khaos has made wrong: %s"

	tlsResponse = "declining to use a dependency whose identity it cannot verify, rather than talking to it anyway"

	ConsultsCRL  = "khaos's CRL distribution point"
	ConsultsOCSP = "khaos's OCSP responder"

	// A property of the CHECK, not of any one language: no mainstream TLS stack
	// checks revocation by default and Go's does not check it at all.
	unsupportableRevocation = "revocation checking"
)

// tlsPolarity is the one polarity where HELD is a defect: carrying on unchanged
// means the target ACCEPTED a certificate khaos broke. DENIED is the pass here.
var tlsPolarity = Polarity{
	Defects:   []Direction{Held, Permitted},
	Rationale: "a target that carries on unchanged has accepted a certificate khaos deliberately broke, which means it will talk to anything presenting one; refusing the dependency and declining to serve is the correct outcome, and refusing it and then letting invalid credentials through is the worst",
}

var policyPolarity = Polarity{
	Defects:   []Direction{Held, Permitted},
	Rationale: "crypto/x509 accepts this certificate, so a target that carries on unchanged has no policy of its own rather than a bypassed check; the finding is the absence of the floor, not a skipped verification",
}

func tlsParams(extra ...Param) []Param {
	return append([]Param{
		{Name: ParamTarget, Usage: usageTarget, Required: true},
		{Name: ParamURL, Usage: usageURL, Required: true},
		{Name: ParamToken, Usage: usageToken, Required: true},
		{
			Name:     ParamAuthorityListen,
			Usage:    usageAuthorityListen,
			Required: true,
		},
		{Name: ParamAuthorityTLS, Usage: usageAuthorityTLS, Required: true},
		{Name: ParamAuthorityBase, Usage: usageAuthorityBase, Required: true},
		{Name: ParamCertHost, Usage: usageCertHost, Required: true},
		{
			Name:    ParamInvalidToken,
			Usage:   usageInvalidToken,
			Default: DefaultInvalidToken,
		},
	}, extra...)
}

var certWindowParam = Param{
	Name:    ParamCertWindow,
	Usage:   usageCertWindow,
	Default: defaultCertWindow,
}

// Derived, not restated: the authority falls back to these same constants when
// a trap carries no magnitude, and a default that drifts below pki.MinimumBits
// would make every weak-key run fail validation instead of serving a fault.
var certBitsParam = Param{
	Name:    ParamCertBits,
	Usage:   usageCertBits,
	Default: strconv.Itoa(pki.DefaultWeakBits),
}

var certDaysParam = Param{
	Name:    ParamCertDays,
	Usage:   usageCertDays,
	Default: strconv.Itoa(pki.DefaultExcessiveDays),
}

type tlsSpec struct {
	name    string
	summary string
	trap    pki.Kind

	polarity Polarity

	// consults turns on the UNSUPPORTED reading: a target that never asked has no
	// revocation check that could have failed.
	consults string

	extra []Param
}

func tlsDefinition(spec tlsSpec) Definition {
	polarity := spec.polarity
	if len(polarity.Defects) == 0 {
		polarity = tlsPolarity
		if pki.GoAccepts(spec.trap) {
			polarity = policyPolarity
		}
	}

	return Definition{
		Name:       spec.name,
		Family:     FamilyTLS,
		Summary:    spec.summary,
		Hypothesis: Hypothesis{Condition: outageGeneric, Response: tlsResponse},
		Polarity:   polarity,
		FaultKind:  inject.PKIKind(spec.trap),
		Params:     tlsParams(spec.extra...),
		Build:      buildTLS(spec),
	}
}

func buildTLS(spec tlsSpec) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)
		host := params.Get(ParamCertHost)

		authority, err := pki.New(pki.Config{Host: host})
		if err != nil {
			return Shape{}, err
		}

		// Pinned BEFORE anything binds, so the certificates khaos mints name a
		// URL the target can actually reach.
		authority.SetBase(params.Get(ParamAuthorityBase))

		trap := pki.Trap{Kind: spec.trap, Host: host}

		if err := readMagnitude(params, spec, &trap); err != nil {
			return Shape{}, err
		}

		if err := trap.Validate(); err != nil {
			return Shape{}, err
		}

		shape := Shape{
			Condition: fmt.Sprintf(
				tlsCondition,
				target,
				trap.Describe(target),
			),
			Target:          target,
			Probes:          probePair(params),
			Authority:       authority,
			PKITrap:         &trap,
			AuthorityBase:   params.Get(ParamAuthorityBase),
			AuthorityListen: params.Get(ParamAuthorityListen),
			AuthorityTLS:    params.Get(ParamAuthorityTLS),
			Defect:          spec.summary,
		}

		if spec.consults != "" {
			shape.ConsultedWhat = spec.consults
			shape.Consulted = revocationCounter(authority, spec.consults)

			shape.Unsupportable = unsupportableRevocation
		}

		return shape, nil
	}
}

// readMagnitude reads whichever parameter this experiment declared, since Params
// refuses a read of a name it never declared.
func readMagnitude(
	params *Params,
	spec tlsSpec,
	trap *pki.Trap,
) error {
	for _, param := range spec.extra {
		switch param.Name {
		case ParamCertWindow:
			window, err := params.Duration(ParamCertWindow)
			if err != nil {
				return err
			}

			trap.Window = window

		case ParamCertBits:
			bits, err := params.Count(ParamCertBits)
			if err != nil {
				return err
			}

			trap.Bits = bits

		case ParamCertDays:
			days, err := params.Count(ParamCertDays)
			if err != nil {
				return err
			}

			trap.Days = days

		default:
			// A parameter this tier does not read, which is legal: the shared
			// set carries several.
		}
	}

	return nil
}

// revocationCounter counts the TARGET's fetches only; khaos's own confirmation
// probes are subtracted by the authority, or every run would look like a check.
func revocationCounter(
	authority *pki.Authority,
	endpoint string,
) func() (int64, error) {
	read := authority.CRLFetches
	if endpoint == ConsultsOCSP {
		read = authority.OCSPQueries
	}

	return func() (int64, error) { return read(), nil }
}
