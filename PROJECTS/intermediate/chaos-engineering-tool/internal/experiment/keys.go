// ©AngelaMos | 2026
// keys.go

package experiment

import (
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

// The key experiments change what khaos's provider SERVES rather than what it
// mints.
const (
	NameJWKSUnreachable = "identity.jwks_unreachable"
	NameKidRollover     = "identity.kid_rollover"
	NameKeyRotation     = "identity.key_rotation"
)

const (
	summaryJWKSUnreachable = "take away the key set while leaving everything else up, then present a token whose signature cannot verify; a 2xx means the target stops checking signatures exactly when it cannot check them"

	summaryKidRollover = "rotate the signing key and withdraw the retired one, then replay a token signed by it; a 2xx means rotation is not a revocation mechanism for this target and a leaked key stays usable"

	summaryKeyRotation = "rotate the signing key with BOTH keys published, which is the rotation every provider is supposed to be able to perform, and find out whether the target picks the new one up or turns a routine rotation into an outage"
)

const (
	conditionJWKSUnreachable = "%s being unable to fetch its issuer's key set while the issuer is otherwise up"
	conditionKidRollover     = "%s losing the key that signed a token it had been honouring"
	conditionKeyRotation     = "%s being offered a token under its issuer's newly rotated key"
)

const (
	defectJWKSUnreachable = "a signature that does not verify under any published key"
	// A withdrawal, not a revocation call: the provider stays reachable.
	defectKidRollover = "withdrawing the key that signed it from a key set the target can still fetch"
)

// A target still honouring a withdrawn key either re-arms its key cache on every
// failed refetch or never expires it, and those are two different fixes.
const defaultKeyIdleFor = "6s"

func init() {
	for _, spec := range []idpSpec{
		{
			name:      NameJWKSUnreachable,
			summary:   summaryJWKSUnreachable,
			condition: conditionJWKSUnreachable,
			defect:    defectJWKSUnreachable,
			trap:      idp.JWKSUnreachable,
			consults:  ConsultsJWKS,
			wiring: streams{
				// REJECTED, the opposite of every forgery experiment: this
				// credential is malformed from the moment it is minted.
				forged:      probe.ExpectRejected,
				forgedFixed: corruptedToken,
			},
		},
		{
			name:      NameKidRollover,
			summary:   summaryKidRollover,
			condition: conditionKidRollover,
			defect:    defectKidRollover,
			trap:      idp.KidRollover,
			// The valid stream must use a key that is never rotated: one under the
			// current signing key would supply the new-key traffic that evicts
			// the retired one, so khaos would cause the recovery it reports.
			wiring: streams{revoked: honestToken, validStable: true},
			extra:  []Param{{Name: ParamIdleFor, Usage: usageIdleFor, Default: defaultKeyIdleFor}},
		},
		{
			name:      NameKeyRotation,
			summary:   summaryKeyRotation,
			condition: conditionKeyRotation,
			trap:      idp.KeyRotation,
			polarity:  rotationPolarity,
			// The VALID stream mints under the armed trap, so a target that
			// refuses the new key's token registers as DENIED. Nothing is forged.
			wiring: streams{validTrapped: true},
		},
	} {
		definition := idpDefinition(spec)
		catalog[definition.Name] = definition
	}
}

// honestToken mints the credential the rollover will orphan, at BUILD time, so
// it is signed by the key the rotation is about to withdraw.
func honestToken(provider *idp.Provider) (string, error) {
	return provider.HonestToken()
}

// corruptedToken breaks one bit of a correct credential's signature and leaves
// everything else right, so only the signature can be refused: a garbage string
// would be refused even by a verifier that never checks one.
func corruptedToken(provider *idp.Provider) (string, error) {
	honest, err := provider.HonestToken()
	if err != nil {
		return "", err
	}

	return idp.CorruptSignature(honest)
}
