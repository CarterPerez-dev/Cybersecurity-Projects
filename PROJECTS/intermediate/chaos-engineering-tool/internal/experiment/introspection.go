// ©AngelaMos | 2026
// introspection.go

package experiment

import (
	"github.com/CarterPerez-dev/khaos/internal/idp"
)

// The introspection experiments. All four leave khaos's provider REACHABLE and
// ANSWERING, which is what separates them from `identity.idp_outage` and from
// every `network.` experiment.
//
// That distinction is the point, not a detail. A caller's `err != nil` branch is
// never taken here, so only its status handling, its decoder's error branch or
// its timeout decides what happens. Those are different lines of code from the
// outage path, reached by different bugs, and taxonomy row F20 is explicit that
// collapsing a denial into an unknown is its own fail-open: returning 401 in one
// phase and 503 in another and getting identical caller behaviour IS the
// finding.
//
// None of the four needs a forged stream. The generic invalid control already
// carries a credential no provider would call active, so a target that accepts
// it while introspection is useless has invented a value RFC 7662 never gave it.
const (
	NameIntrospectionError     = "identity.introspection_error"
	NameIntrospectionMalformed = "identity.malformed_response"
	NameIntrospectionSlow      = "identity.idp_latency"
	NameRevokedToken           = "identity.revoked_token"
)

const (
	summaryIntrospectionError = "make the identity provider answer introspection with a 503 while staying reachable, which asks whether the target treats a refusal it cannot parse as permission"

	summaryIntrospectionMalformed = "answer introspection with a 200 and a body that is not JSON, which asks what the target's decode-error branch decided to do"

	summaryIntrospectionSlow = "hold introspection past the target's own timeout while answering everything else promptly, which asks whether a slow authority and an absent one are the same thing to it"

	summaryRevokedToken = "revoke a credential at a provider the target can still reach, and measure how long it keeps honouring it; this is the exposure window every revocation actually has"
)

const (
	conditionIntrospectionError     = "%s receiving a 503 from an identity provider it can still reach"
	conditionIntrospectionMalformed = "%s receiving an unparseable introspection response"
	conditionIntrospectionSlow      = "%s waiting longer than its own timeout for an introspection answer"
	conditionRevokedToken           = "%s holding a credential its provider has revoked and can be asked about"
)

// The provider is reachable and will answer `active: false` on request. That
// contrast with the outage experiment is the finding's whole point, so the
// phrase has to carry it.
const caveatHoldAbsorbed = "khaos held introspection for %s; a target whose own timeout is longer than that saw a slow success rather than a failure, so this run does not rule out a fail-open on a longer hold"

const defectRevokedToken = "revoking it at a provider the target can still reach and ask"

// The idleness discriminator applies here too, and this is where the contrast
// with `identity.idp_outage` becomes a teaching point rather than a nuance. There
// the authority is unreachable, so a stale decision is at least explicable. Here
// the authority is answering `active: false` and the target is simply not
// asking, and the pause tells a cache being re-armed from one with no expiry at
// all.
const defaultRevokeIdleFor = "6s"

func init() {
	for _, spec := range []idpSpec{
		{
			name:      NameIntrospectionError,
			summary:   summaryIntrospectionError,
			condition: conditionIntrospectionError,
			trap:      idp.IntrospectionError,
			consults:  ConsultsIntrospection,
			wiring:    streams{validOpaque: true},
		},
		{
			name:      NameIntrospectionMalformed,
			summary:   summaryIntrospectionMalformed,
			condition: conditionIntrospectionMalformed,
			trap:      idp.IntrospectionMalformed,
			consults:  ConsultsIntrospection,
			wiring:    streams{validOpaque: true},
		},
		{
			name:      NameIntrospectionSlow,
			summary:   summaryIntrospectionSlow,
			condition: conditionIntrospectionSlow,
			trap:      idp.IntrospectionSlow,
			consults:  ConsultsIntrospection,
			wiring:    streams{validOpaque: true},
			magnitude: holdMagnitude,
			extra:     []Param{idpDelayParam},
			// A hold the target's timeout absorbs is a slow SUCCESS, which is
			// correct behaviour. khaos cannot discover a timeout it is probing
			// from outside, so a HELD here has to say which hold it used.
			heldCaveat: func(params *Params) string {
				return sprintf(caveatHoldAbsorbed, params.Get(ParamDelay))
			},
		},
		{
			name:      NameRevokedToken,
			summary:   summaryRevokedToken,
			condition: conditionRevokedToken,
			defect:    defectRevokedToken,
			trap:      idp.Revoke,
			// The revoked stream carries an OPAQUE credential, because a locally
			// validated JWT cannot be revoked at all: research 07's asymmetry is
			// that local validation does not fail open during a provider outage,
			// it fails INVISIBLE, and revocation is a no-op until `exp`. Asking
			// this question of a JWT would measure nothing.
			// The valid control is opaque too. This experiment revokes an opaque
			// credential and asks whether the target re-checks it, so the target
			// must be one that introspects at all — and a JWT control would be
			// validated locally, prove the target is serving, and prove nothing
			// about the path under test.
			wiring: streams{revoked: revocableCredential, validOpaque: true},
			extra:  []Param{{Name: ParamIdleFor, Usage: usageIdleFor, Default: defaultRevokeIdleFor}},
		},
	} {
		definition := idpDefinition(spec)
		catalog[definition.Name] = definition
	}
}

// revocableCredential issues the opaque grant this run will revoke and records
// it on the provider as such. The mutator reads it back at inject time, because
// the trap cannot carry a credential that does not exist when the experiment is
// built.
func revocableCredential(provider *idp.Provider) (string, error) {
	return provider.Revocable(), nil
}
