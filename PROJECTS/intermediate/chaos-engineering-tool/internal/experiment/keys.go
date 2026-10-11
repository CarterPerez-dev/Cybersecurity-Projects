// ©AngelaMos | 2026
// keys.go

package experiment

import (
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

// The key experiments. These three change what khaos's provider SERVES rather
// than what it mints, and between them they cover the two halves of key rotation
// plus the trap research 07 calls the highest-value one in its archive.
//
// They need almost no new machinery, and that is a result rather than a
// coincidence: `kid_rollover` is a credential that was legitimately accepted and
// then taken away, which is exactly what the revoked stream already means, and
// `key_rotation` is a correctly signed credential the target may refuse, which
// is exactly what the directional axis already measures.
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
	// A withdrawal, not a revocation call, and the provider stays reachable
	// throughout. Saying "while the authority was unreachable" here would be
	// false.
	defectKidRollover = "withdrawing the key that signed it from a key set the target can still fetch"
)

// The idleness discriminator applies to the rollover, and it is the same
// question in a different place: a target still honouring a withdrawn key either
// re-arms its key cache on every failed refetch, or never expires it at all.
// Those are two different fixes.
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
				// REJECTED, the opposite of every forgery experiment, and the
				// reason the expectation is declared rather than derived. This
				// credential is malformed from the moment it is minted, so a
				// target that did not refuse it while the key set was reachable
				// was never checking signatures and its acceptance during the
				// fault proves nothing changed.
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
			// The revoked stream, not the forged one. This credential was
			// LEGITIMATE when it was issued and the rotation is what took it
			// away, which is the revoked stream's exact meaning, and it brings
			// the idleness discriminator with it for free.
			//
			// The valid stream is a JWT under a key that is NEVER rotated, and
			// this experiment is not correct without that. A valid stream under
			// the current signing key supplies the new-key traffic that evicts
			// the retired one, so khaos caused the recovery it then reported:
			// measured with the verifier's key cache set to an hour, the run
			// still returned `passed / HELD` against a target with an unbounded
			// stale window.
			//
			// An opaque credential also avoids that and was the first fix, but it
			// demands the target support introspection — a JWT-only verifier
			// cannot establish a baseline at all, which trades one blind spot for
			// another.
			wiring: streams{revoked: honestToken, validStable: true},
			extra:  []Param{{Name: ParamIdleFor, Usage: usageIdleFor, Default: defaultKeyIdleFor}},
		},
		{
			name:      NameKeyRotation,
			summary:   summaryKeyRotation,
			condition: conditionKeyRotation,
			trap:      idp.KeyRotation,
			polarity:  rotationPolarity,
			// No forged stream and no revoked one. The VALID stream mints under
			// the armed trap, so it carries the new key's token during the fault,
			// and a target that refuses it registers on the directional axis as
			// DENIED. There is nothing forged anywhere in this experiment.
			wiring: streams{validTrapped: true},
		},
	} {
		definition := idpDefinition(spec)
		catalog[definition.Name] = definition
	}
}

// honestToken mints the credential the rollover will orphan. It is minted at
// BUILD time, which is before the fault by construction, so it is signed by the
// key the rotation is about to withdraw. A credential minted after the rotation
// would be signed by the new key and would prove nothing.
func honestToken(provider *idp.Provider) (string, error) {
	return provider.HonestToken()
}

// corruptedToken mints a correct credential and then breaks one bit of its
// signature. Everything else about it is right: the header, the kid, the claims
// and the signature's length, so the only thing a verifier can refuse it for is
// the signature itself.
//
// That precision is the whole experiment. A garbage string would be refused by
// anything, including a verifier that skipped signature verification entirely,
// so it could never distinguish the two.
func corruptedToken(provider *idp.Provider) (string, error) {
	honest, err := provider.HonestToken()
	if err != nil {
		return "", err
	}

	return idp.CorruptSignature(honest)
}
