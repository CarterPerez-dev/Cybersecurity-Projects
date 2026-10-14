// ©AngelaMos | 2026
// tlstier.go

package experiment

import (
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/pki"
)

const (
	// Where khaos binds its certificate authority, and the URL the TARGET
	// reaches it by.
	//
	// They are two parameters and not one, and that is the identity provider's
	// most expensive bug stated as a design rule. khaos binds the Docker bridge
	// gateway's numeric address while the target addresses
	// `host.docker.internal`, so a URL derived from khaos's own listener is
	// unreachable from inside the target's network namespace. Every revocation
	// fetch would then fail for a reason that has nothing to do with the trap,
	// and the run would report the target as fail-closed when khaos had simply
	// pointed it at nowhere.
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

	// ConsultsCRL and ConsultsOCSP are the revocation endpoints, as they read
	// in the verdict an operator sees.
	ConsultsCRL  = "khaos's CRL distribution point"
	ConsultsOCSP = "khaos's OCSP responder"

	// unsupportableRevocation is what the UNSUPPORTED verdict names. It is a
	// property of the CHECK, not of any one language: no mainstream TLS stack
	// checks revocation by default and Go's does not check it at all.
	unsupportableRevocation = "revocation checking"
)

// tlsPolarity is the first polarity in khaos where HELD is a defect, and the
// reasoning is worth stating because it reads backwards at first glance.
//
// khaos presents a certificate that is wrong in one specific way. A target that
// carries on exactly as before has ACCEPTED it: valid traffic served, invalid
// traffic refused, nothing disturbed. That is HELD, and it means the target
// talked to a dependency whose identity it could not verify. On the other side
// of a certificate it should have refused there could be anything.
//
// A target that refuses the certificate cannot reach its dependency, and then
// the ordinary question applies: if it keeps enforcing but stops serving, that
// is DENIED, and for a certificate fault that is the CORRECT outcome with an
// availability cost. If it stops enforcing, that is PERMITTED and it is the
// worst of the three.
//
// So two directions are defects here and the pass is DENIED.
var tlsPolarity = Polarity{
	Defects:   []Direction{Held, Permitted},
	Rationale: "a target that carries on unchanged has accepted a certificate khaos deliberately broke, which means it will talk to anything presenting one; refusing the dependency and declining to serve is the correct outcome, and refusing it and then letting invalid credentials through is the worst",
}

// policyPolarity is for the faults crypto/x509 ACCEPTS. The target is not being
// caught out by its TLS library, because the library never objected: it either
// imposed a policy of its own or it did not.
//
// PERMITTED is still a defect, because dropping enforcement is always one.
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

var certBitsParam = Param{
	Name:    ParamCertBits,
	Usage:   usageCertBits,
	Default: "1024",
}

var certDaysParam = Param{
	Name:    ParamCertDays,
	Usage:   usageCertDays,
	Default: "2000",
}

// tlsSpec is one certificate experiment's declaration. Everything that is not
// derived from a parameter lives here, so a builder cannot restate its own name
// or forget its polarity.
type tlsSpec struct {
	name    string
	summary string
	trap    pki.Kind

	// polarity defaults to tlsPolarity, or policyPolarity for the faults Go
	// accepts, which is derived rather than restated per experiment.
	polarity Polarity

	// consults names the revocation endpoint this fault acts on. Setting it
	// turns on the UNSUPPORTED reading, which is the whole point of the
	// revocation group: a target that never asked has no check that failed.
	consults string

	extra []Param
}

// tlsDefinition turns one declaration into a catalogue entry. Every certificate
// experiment goes through here, so none of them can forget to build an
// authority, pin its base URL, or carry its polarity through.
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

		// Both halves together. A declared endpoint with no counter is a guard
		// that can never fire, and a counter with no name is a verdict that
		// cannot say what to check.
		if spec.consults != "" {
			shape.ConsultedWhat = spec.consults
			shape.Consulted = revocationCounter(authority, spec.consults)

			// The same observation that would void an endpoint-aimed fault is
			// the ANSWER here, so this experiment asks for the second reading.
			shape.Unsupportable = unsupportableRevocation
		}

		return shape, nil
	}
}

// readMagnitude reads whichever parameter this experiment declared. Only the
// traps that carry a magnitude declare one, and Params refuses a read of a name
// the experiment never declared, so this cannot read a flag that is not there.
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

// revocationCounter reads how many times the TARGET reached the endpoint this
// experiment faults. khaos's own confirmation probes are already subtracted by
// the authority, because a count that included them would make "the target
// checked revocation" true for every run and the UNSUPPORTED verdict would
// never fire.
// The error is always nil, and that is the point of the wrapper rather than a
// shortcut. This counter lives in khaos's own process, so there is no read that
// can fail; the DNS tier's counter lives in another container and can, which is
// why the signature carries one at all.
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
