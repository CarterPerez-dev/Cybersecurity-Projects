// ©AngelaMos | 2026
// env.go

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
	ParamEnvVar = "variable"

	NameEnvUnset = "credential.env_unset"
	NameEnvEmpty = "credential.env_empty"

	usageEnvVar = "the environment variable holding the secret, which khaos takes away by replacing the container; the original is kept inside the replacement so khaos never writes it anywhere"

	usageTargetEnv = "the consenting container whose environment you want to break; khaos keeps the original container aside and renames it back on the way out"

	summaryEnvUnset = "replace a service with one that does not carry its secret at all, which is what a deploy with a missing variable does"

	summaryEnvEmpty = "replace a service with one whose secret is present and EMPTY, which os.Getenv cannot distinguish from absent"

	conditionEnvUnset = "%s being restarted without %s in its environment"

	conditionEnvEmpty = "%s being restarted with %s present and empty"

	responseEnvUnset = "refusing to serve at all rather than starting healthy and verifying credentials against a secret it never read"

	responseEnvEmpty = "refusing every credential, because an empty secret is a secret equal to the empty string and HMAC computes happily with one"

	defectEnvUnset = "replacing it with a container that does not carry that variable"

	defectEnvEmpty = "replacing it with a container whose variable is present and empty"

	caveatEnvHeld = "the replacement kept verifying credentials; khaos replaced the container, so this is the service's behaviour on a FRESH start with that environment rather than anything it did while running"
)

// envPolarity matches the secret family's: a service that verifies a credential
// against a secret it could not have read is not verifying anything.
var envPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a service that starts healthy and keeps accepting credentials without the secret it needs to check them has stopped being a check",
}

var envParams = []Param{
	{Name: ParamTarget, Usage: usageTargetEnv, Required: true},
	{Name: ParamURL, Usage: usageURL, Required: true},
	{Name: ParamToken, Usage: usageTokenSecret, Required: true},
	{Name: ParamEnvVar, Usage: usageEnvVar, Required: true},
}

func buildEnv(
	kind inject.EnvKind,
	condition, defect string,
) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		if err := inject.ValidEnvKind(kind); err != nil {
			return Shape{}, err
		}

		target := params.Get(ParamTarget)
		url := params.Get(ParamURL)
		variable := params.Get(ParamEnvVar)

		return Shape{
			Condition: fmt.Sprintf(condition, target, variable),
			Target:    target,
			Probes: probe.Pair{
				Valid: probe.NewHTTP(probe.HTTPOptions{
					Name:       probeValidName,
					URL:        url,
					Credential: probe.Valid,
					Token:      params.Get(ParamToken),
				}),
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
			Env: &inject.EnvPlan{Kind: kind, Variable: variable},

			Defect:     defect,
			HeldCaveat: caveatEnvHeld,

			// A service that cannot read its secret answers 503 rather than
			// refusing a credential, and for this control that IS failing
			// closed.
			ClosedWhen: []probe.Disposition{probe.Unavailable},
		}, nil
	}
}

func init() {
	catalogAdd(Definition{
		Name:    NameEnvUnset,
		Family:  FamilyCredential,
		Summary: summaryEnvUnset,
		Hypothesis: Hypothesis{
			Condition: "a service being restarted without the variable holding its secret",
			Response:  responseEnvUnset,
		},
		Polarity:  envPolarity,
		FaultKind: inject.EnvFaultKind(inject.EnvUnset),
		Params:    envParams,
		Build: buildEnv(
			inject.EnvUnset,
			conditionEnvUnset,
			defectEnvUnset,
		),
	})

	catalogAdd(Definition{
		Name:    NameEnvEmpty,
		Family:  FamilyCredential,
		Summary: summaryEnvEmpty,
		Hypothesis: Hypothesis{
			Condition: "a service being restarted with that variable present and empty",
			Response:  responseEnvEmpty,
		},
		Polarity:  envPolarity,
		FaultKind: inject.EnvFaultKind(inject.EnvEmpty),
		Params:    envParams,
		Build: buildEnv(
			inject.EnvEmpty,
			conditionEnvEmpty,
			defectEnvEmpty,
		),
	})
}
