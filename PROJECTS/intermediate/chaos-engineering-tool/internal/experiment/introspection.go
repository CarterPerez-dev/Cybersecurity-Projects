// ©AngelaMos | 2026
// introspection.go

package experiment

import (
	"github.com/CarterPerez-dev/khaos/internal/idp"
)

// These leave khaos's provider REACHABLE and ANSWERING, so a caller's
// `err != nil` branch is never taken: only its status handling, its decoder's
// error branch or its timeout decides what happens.
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

const caveatHoldAbsorbed = "khaos held introspection for %s; a target whose own timeout is longer than that saw a slow success rather than a failure, so this run does not rule out a fail-open on a longer hold"

const defectRevokedToken = "revoking it at a provider the target can still reach and ask"

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
			// khaos cannot discover a timeout it is probing from outside, so a
			// HELD here has to say which hold it used.
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
			// Both streams are OPAQUE, because revocation is a no-op on a locally
			// validated JWT until `exp`.
			wiring: streams{revoked: revocableCredential, validOpaque: true},
			extra:  []Param{{Name: ParamIdleFor, Usage: usageIdleFor, Default: defaultRevokeIdleFor}},
		},
	} {
		definition := idpDefinition(spec)
		catalog[definition.Name] = definition
	}
}

// revocableCredential is read back by the mutator at inject time, because the
// trap cannot carry a credential that does not exist when the experiment builds.
func revocableCredential(provider *idp.Provider) (string, error) {
	return provider.Revocable(), nil
}
