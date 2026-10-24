// ©AngelaMos | 2026
// forgery.go

package experiment

import (
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const caveatOneKeyForm = "this run keyed the forged MAC on the %s serialization only, and the same bug is unreachable under the wrong one; a target that loaded its key differently is not ruled out until each of %s has been tried"

// Each forgery experiment mints a credential wrong in EXACTLY ONE named way and
// leaves everything else correct. The forged stream's baseline expectation is
// ACCEPTED for all ten, because khaos's provider mints correctly until the trap
// is armed: a target refusing even those is not pointed at khaos's provider.
const (
	NameAlgNone            = "identity.alg_none"
	NameAlgConfusion       = "identity.alg_confusion"
	NameEmbeddedJWK        = "identity.embedded_jwk"
	NameClaimExpired       = "identity.claim_expired"
	NameClaimNotYetValid   = "identity.claim_not_yet_valid"
	NameClaimWrongAudience = "identity.claim_wrong_audience"
	NameClaimForeignIssuer = "identity.claim_foreign_issuer"
	NameSignatureTruncated = "identity.signature_truncated"
	NameSignatureZero      = "identity.signature_zero"
	NameSignatureWeakKey   = "identity.signature_weak_key"
)

const (
	summaryAlgNone = "mint an unsigned token that declares `alg: none` and find out whether the target believes it, which is the cheapest high-signal probe in the whole tool because it needs no cooperation from anything"

	summaryAlgConfusion = "sign a token with HMAC keyed on the issuer's PUBLIC key and find out whether the target verifies it, which works because the attacker has the secret by definition"

	summaryEmbeddedJWK = "mint a token carrying its own signing key in the header and find out whether the target resolves keys from the token instead of from the key set it trusts"

	summaryClaimExpired = "mint a correctly signed token that has already expired, which asks whether the target still has the only revocation mechanism a stateless verifier gets"

	summaryClaimNotYetValid = "mint a correctly signed token that is not valid yet, which asks whether staged issuance means anything to the target"

	summaryClaimWrongAudience = "mint a correctly signed token addressed to a different service, which asks whether a token minted for anything in the estate works everywhere in it"

	summaryClaimForeignIssuer = "mint a correctly signed token from a second issuer whose keys the provider also publishes, which asks whether the key set is being mistaken for the trust boundary"

	summarySignatureTruncated = "cut a valid signature down to one byte and find out whether the target checks its length before believing it"

	summarySignatureZero = "mint an ES256 token whose signature is entirely zero bytes, which is the shape of the psychic-signatures bug and costs one request to rule out"

	summarySignatureWeakKey = "sign with a modulus smaller than any correct verifier should accept, and find out whether the target checks key size or only that the arithmetic worked"
)

const (
	conditionAlgNone            = "%s being offered an unsigned token by its own identity provider"
	conditionAlgConfusion       = "%s being offered a token signed with its issuer's public key as an HMAC secret"
	conditionEmbeddedJWK        = "%s being offered a token that brings its own signing key"
	conditionClaimExpired       = "%s being offered an expired token with a correct signature"
	conditionClaimNotYetValid   = "%s being offered a not-yet-valid token with a correct signature"
	conditionClaimWrongAudience = "%s being offered a correctly signed token meant for another service"
	conditionClaimForeignIssuer = "%s being offered a correctly signed token from another issuer"
	conditionSignatureTruncated = "%s being offered a token whose signature is one byte long"
	conditionSignatureZero      = "%s being offered a token whose signature is all zeroes"
	conditionSignatureWeakKey   = "%s being offered a token signed under an undersized key"
)

const (
	defectAlgNone            = "no signature at all and a header saying so"
	defectAlgConfusion       = "an HMAC keyed on its issuer's own public key"
	defectEmbeddedJWK        = "a signing key the issuer never published, carried in the token's own header"
	defectClaimExpired       = "an expiry already in the past"
	defectClaimNotYetValid   = "a validity window that has not started"
	defectClaimWrongAudience = "an audience belonging to another service"
	defectClaimForeignIssuer = "an issuer the target was not configured to trust"
	defectSignatureTruncated = "a signature cut to a single byte"
	defectSignatureZero      = "a signature of nothing but zero bytes"
	defectSignatureWeakKey   = "a modulus below the size any correct verifier accepts"
)

// forged declares a forgery experiment. The wiring is identical across all ten
// because the shape is.
func forged(
	name, summary, condition, defect string,
	trap idp.Kind,
	extra ...Param,
) idpSpec {
	spec := idpSpec{
		name:      name,
		summary:   summary,
		condition: condition,
		defect:    defect,
		trap:      trap,
		wiring:    streams{forged: probe.ExpectAccepted},
		extra:     extra,
	}

	switch trap {
	case idp.ClaimExpired, idp.ClaimNotYetValid:
		spec.magnitude = claimShiftMagnitude
	case idp.AlgConfusion:
		spec.magnitude = keyFormMagnitude
		// This bug is unreachable under the wrong key serialization and khaos
		// tries one per run, so a HELD rules out one expression, not the bug.
		spec.heldCaveat = func(params *Params) string {
			return sprintf(
				caveatOneKeyForm,
				params.Get(ParamKeyForm),
				strings.Join(idp.KeyForms(), nameSep),
			)
		}

	default:
		// Every other trap keeps the magnitude and caveat the caller declared.
	}

	return spec
}

func init() {
	for _, spec := range []idpSpec{
		forged(NameAlgNone, summaryAlgNone, conditionAlgNone, defectAlgNone, idp.AlgNone),
		forged(NameAlgConfusion, summaryAlgConfusion, conditionAlgConfusion, defectAlgConfusion, idp.AlgConfusion, keyFormParam),
		forged(NameEmbeddedJWK, summaryEmbeddedJWK, conditionEmbeddedJWK, defectEmbeddedJWK, idp.EmbeddedJWK),
		forged(NameClaimExpired, summaryClaimExpired, conditionClaimExpired, defectClaimExpired, idp.ClaimExpired, claimShiftParam),
		forged(NameClaimNotYetValid, summaryClaimNotYetValid, conditionClaimNotYetValid, defectClaimNotYetValid, idp.ClaimNotYetValid, claimShiftParam),
		forged(NameClaimWrongAudience, summaryClaimWrongAudience, conditionClaimWrongAudience, defectClaimWrongAudience, idp.ClaimWrongAudience),
		forged(NameClaimForeignIssuer, summaryClaimForeignIssuer, conditionClaimForeignIssuer, defectClaimForeignIssuer, idp.ClaimForeignIssuer),
		forged(NameSignatureTruncated, summarySignatureTruncated, conditionSignatureTruncated, defectSignatureTruncated, idp.SignatureTruncated),
		forged(NameSignatureZero, summarySignatureZero, conditionSignatureZero, defectSignatureZero, idp.SignatureZero),
		forged(NameSignatureWeakKey, summarySignatureWeakKey, conditionSignatureWeakKey, defectSignatureWeakKey, idp.SignatureWeakKey),
	} {
		definition := idpDefinition(spec)
		catalog[definition.Name] = definition
	}
}
