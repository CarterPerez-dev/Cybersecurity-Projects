// ©AngelaMos | 2026
// secret.go

package experiment

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/probe"
	"github.com/CarterPerez-dev/khaos/internal/secretfile"
)

const (
	ParamSecretPath  = "secret-path"
	ParamSecretBytes = "secret-bytes"

	NameSecretEmpty      = "credential.secret_file_empty"
	NameSecretTruncated  = "credential.secret_file_truncated"
	NameSecretMissing    = "credential.secret_file_missing"
	NameSecretUnreadable = "credential.secret_file_unreadable"

	usageSecretPath = "the secret file's path INSIDE the target, which khaos breaks in place through a helper container that mounts only the mount containing it"

	usageSecretBytes = "how many bytes of the secret survive a truncation"

	summarySecretEmpty = "truncate a service's secret to zero bytes and see whether it still verifies credentials, because an empty secret is not no secret"

	summarySecretTruncated = "cut a service's secret down to a few bytes, which leaves a silently wrong key rather than a missing one"

	summarySecretMissing = "take a service's secret away entirely, which is the one shape of the four that an application usually handles"

	summarySecretUnreadable = "make a service's secret unreadable, which is the only one of the four that errors on the read itself"

	conditionSecret = "%s's secret file being %s"

	responseSecretEmpty = "refusing every credential, because HMAC computes happily with a zero-length key and a token signed with one verifies against a verifier that did not check the length"

	responseSecretOther = "refusing every credential rather than verifying against a key it cannot have read correctly"

	defectSecretEmpty = "truncating its secret to zero bytes, which os.ReadFile reports as success with an empty slice"

	defectSecretTruncated = "cutting its secret down to a few bytes"

	defectSecretMissing = "taking its secret away"

	defectSecretUnreadable = "making its secret unreadable"

	probeEmptyKeyName = "credential-signed-with-the-empty-key"

	describeEmptyKey = "%s carrying a credential signed with a ZERO-LENGTH key, which is what a verifier that read an empty secret and did not check its length will accept"

	caveatSecretHeld = "the target kept verifying credentials throughout; khaos broke the secret through a helper that writes IN PLACE, so a target holding an open file descriptor would still be reading the original and this says nothing about one that does"

	stateEmpty      = "emptied"
	stateTruncated  = "cut down to a few bytes"
	stateMissing    = "taken away"
	stateUnreadable = "made unreadable"
)

// secretPolarity is PERMITTED: a target that verifies a credential signed with
// a key it could not have read is not verifying anything. Every one of the four
// faults is expected to make a correct target refuse, and three of them cannot
// do anything else - which is what makes them the controls for the one that
// can.
var secretPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a service that keeps accepting credentials after its signing secret was destroyed is verifying them against something it should not have accepted as a key",
}

var secretParams = []Param{
	{Name: ParamTarget, Usage: usageTargetSecret, Required: true},
	{Name: ParamURL, Usage: usageURL, Required: true},
	{Name: ParamToken, Usage: usageTokenSecret, Required: true},
	{Name: ParamSecretPath, Usage: usageSecretPath, Required: true},
}

const (
	usageTargetSecret = "the consenting container whose secret file you want to break"

	usageTokenSecret = "a credential the target currently accepts, which the range asks the target itself to issue because khaos never reads the secret"
)

func buildSecret(
	kind secretfile.Kind,
	state, defect string,
) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)
		url := params.Get(ParamURL)
		path := params.Get(ParamSecretPath)

		mutation := secretfile.Mutation{
			Kind:  kind,
			Path:  path,
			Aside: secretfile.AsideFor(path),
		}

		if kind == secretfile.Truncated {
			bytes, err := params.Count(ParamSecretBytes)
			if err != nil {
				return Shape{}, err
			}
			mutation.Bytes = bytes
		}

		if err := mutation.Validate(); err != nil {
			return Shape{}, err
		}

		return Shape{
			Condition: fmt.Sprintf(conditionSecret, target, state),
			Target:    target,
			Probes: probe.Pair{
				Valid: probe.NewHTTP(probe.HTTPOptions{
					Name:       probeValidName,
					URL:        url,
					Credential: probe.Valid,
					Token:      params.Get(ParamToken),
				}),
				// The negative control is signed with the EMPTY key, which is
				// the one thing about it that must not vary, and freshly
				// minted per request, which is what keeps a cached refusal
				// from answering every repeat. The nonce rides inside the
				// signed message, so both hold at once.
				Invalid: probe.NewHTTP(probe.HTTPOptions{
					Name:       probeEmptyKeyName,
					Describe:   fmt.Sprintf(describeEmptyKey, url),
					URL:        url,
					Credential: probe.Invalid,
					Mint: func(context.Context) (string, error) {
						return secretfile.Token(nil, rand.Text()), nil
					},
				}),
			},
			Secret: &inject.SecretPlan{
				Mutation: mutation,
			},
			Defect:     defect,
			HeldCaveat: caveatSecretHeld,

			// A service that cannot read its secret answers 503 rather than
			// refusing a credential, and for this control that IS failing
			// closed.
			ClosedWhen: []probe.Disposition{probe.Unavailable},
		}, nil
	}
}

func secretDefinition(
	name string,
	kind secretfile.Kind,
	summary, state, defect, response string,
	extra ...Param,
) Definition {
	return Definition{
		Name:    name,
		Family:  FamilyCredential,
		Summary: summary,
		Hypothesis: Hypothesis{
			Condition: "a service's signing secret being " + state,
			Response:  response,
		},
		Polarity:  secretPolarity,
		FaultKind: inject.SecretKind(kind),
		Params:    append(secretParams, extra...),
		Build:     buildSecret(kind, state, defect),
	}
}

func init() {
	for _, definition := range []Definition{
		secretDefinition(
			NameSecretEmpty,
			secretfile.Empty,
			summarySecretEmpty,
			stateEmpty,
			defectSecretEmpty,
			responseSecretEmpty,
		),
		secretDefinition(
			NameSecretTruncated,
			secretfile.Truncated,
			summarySecretTruncated,
			stateTruncated,
			defectSecretTruncated,
			responseSecretOther,
			Param{
				Name:    ParamSecretBytes,
				Usage:   usageSecretBytes,
				Default: defaultSecretBytes,
			},
		),
		secretDefinition(
			NameSecretMissing,
			secretfile.Missing,
			summarySecretMissing,
			stateMissing,
			defectSecretMissing,
			responseSecretOther,
		),
		secretDefinition(
			NameSecretUnreadable,
			secretfile.Unreadable,
			summarySecretUnreadable,
			stateUnreadable,
			defectSecretUnreadable,
			responseSecretOther,
		),
	} {
		catalogAdd(definition)
	}
}

const defaultSecretBytes = "4"

// SecretNames is the family in catalogue order, for the one census that has to
// know which experiments reach a file rather than a credential.
func SecretNames() []string {
	return []string{
		NameSecretEmpty,
		NameSecretTruncated,
		NameSecretMissing,
		NameSecretUnreadable,
	}
}
