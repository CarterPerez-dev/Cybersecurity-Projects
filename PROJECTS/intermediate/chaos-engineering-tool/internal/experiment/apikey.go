// ©AngelaMos | 2026
// apikey.go

package experiment

import (
	"context"
	"errors"
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/authz"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	ParamAuthzListen = "authz-listen"

	NameAPIKeyRevoked = "credential.apikey_revoked"

	usageAuthzListen = "where khaos binds the authorization dependency it plays, which has to be the address the target's own authorization check already calls; khaos answers that call for the length of the run"

	usageAuthzToken = "a credential the target accepts, which khaos's authorization dependency keeps allowing; it is the stream that proves the target is still serving"

	usageAuthzRevocable = "a SECOND credential the target accepts, which khaos's authorization dependency answers a definitive 403 for once the baseline is established. It must NOT be one your live traffic is using: khaos denies it for the length of the run, so anything else presenting it is denied too, and the retry count khaos reports is the number of times THIS credential was asked about, which other clients presenting it would inflate"

	summaryAPIKeyRevoked = "have a service's authorization dependency answer a definitive deny, then answer nothing at all, and see whether the service can tell those apart"

	conditionAPIKeyRevoked = "%s's authorization dependency refusing one credential outright, and then becoming unable to answer at all"

	responseAPIKeyRevoked = "refusing the credential its dependency denied, continuing to serve every other credential, and refusing again once the dependency can no longer answer -- three outcomes, not two"

	// It names khaos's own posture as well as the fault, because this string is
	// what a LEAKING run prints and the HeldCaveat below is not: an operator
	// acting on a finding has to know khaos was answering their authorization
	// calls and allowing everything it was not told to deny.
	defectAPIKeyRevoked = "answering a definitive 403 for that credential at the authorization dependency khaos is playing, which stayed reachable throughout and kept allowing every other credential"

	consultsAuthz = "khaos's authorization dependency"

	deliversAuthz = "ask khaos's authorization dependency for a decision"

	hintAuthz = "A target that caches authorization decisions produces this shape: it asked once before the fault and answered every probe from that cached allow. What to check, in that order: the lifetime of the target's own decision cache, whether it caches a negative answer at all, and whether its authorization check runs per request or per session. Re-run with --fault-for longer than that lifetime"

	shiftAuthzWhat = "khaos's authorization dependency answered 503 to everything"

	shiftAuthzDetail = "making khaos's authorization dependency unable to answer at all, which is the only outcome a fallback policy may act on"

	caveatAuthzHeld = "khaos stood in for the authorization dependency for the length of this run and allowed every credential it was not told to deny, so this says nothing about the decisions that dependency normally makes; what was measured is how the target reads the three answers it can give"

	errShiftUnconfirmed = "%w: khaos armed the second phase and its own dependency did not answer 503 when read back, so the window would have measured the first fault twice"

	probeDeniedName = "denied-credential"

	describeAuthzValid = "%s with a credential khaos's authorization dependency keeps allowing"

	describeAuthzDenied = "%s with the credential khaos's authorization dependency denies"
)

var ErrShiftUnconfirmed = errors.New(
	"the second phase of this fault could not be confirmed",
)

// authzPolarity has TWO defects, and the second one is not symmetry for its own
// sake. khaos's dependency denies exactly one credential and keeps allowing
// every other, so a target that stops serving the valid one has turned a single
// revocation into an outage of everything, which is a real failure mode of a
// shared authorization client rather than an over-cautious success.
var authzPolarity = Polarity{
	Defects:   []Direction{Permitted, Denied},
	Rationale: "an authorization dependency has three outcomes, allow, deny and unknown, and only unknown is eligible for a fallback policy: serving a credential it was told to refuse is a bypass, and refusing every other credential because one was denied is an outage the deny never called for",
}

const usageAuthzTarget = "the consenting container whose authorization dependency khaos answers; nothing of the target's is taken away and no dependency of its is paused, so this is the service being measured rather than the thing being broken"

var authzParams = []Param{
	{Name: ParamTarget, Usage: usageAuthzTarget, Required: true},
	{Name: ParamURL, Usage: usageURL, Required: true},
	{Name: ParamToken, Usage: usageAuthzToken, Required: true},
	{Name: ParamRevocable, Usage: usageAuthzRevocable, Required: true},
	{Name: ParamAuthzListen, Usage: usageAuthzListen, Required: true},
	{
		Name:    ParamInvalidToken,
		Usage:   usageInvalidToken,
		Default: DefaultInvalidToken,
	},
}

func buildAPIKeyRevoked(params *Params) (Shape, error) {
	target := params.Get(ParamTarget)
	url := params.Get(ParamURL)
	revocable := params.Get(ParamRevocable)

	dependency := authz.New()

	trap := authz.Trap{Kind: authz.Deny, Credential: revocable}
	if err := trap.Validate(); err != nil {
		return Shape{}, err
	}

	return Shape{
		Condition: fmt.Sprintf(conditionAPIKeyRevoked, target),
		Target:    target,

		Probes: probe.Pair{
			Valid: probe.NewHTTP(probe.HTTPOptions{
				Name:       probeValidName,
				Describe:   fmt.Sprintf(describeAuthzValid, url),
				URL:        url,
				Token:      params.Get(ParamToken),
				Credential: probe.Valid,
			}),
			Invalid: probe.NewHTTP(probe.HTTPOptions{
				Name:       probeInvalidName,
				URL:        url,
				Token:      params.Get(ParamInvalidToken),
				Credential: probe.Invalid,
				Unique:     true,
			}),
			Revoked: probe.NewHTTP(probe.HTTPOptions{
				Name:       probeDeniedName,
				Describe:   fmt.Sprintf(describeAuthzDenied, url),
				URL:        url,
				Token:      revocable,
				Credential: probe.Revoked,
			}),
		},

		Authz:       dependency,
		AuthzTrap:   &trap,
		AuthzListen: params.Get(ParamAuthzListen),

		Defect:     defectAPIKeyRevoked,
		HeldCaveat: caveatAuthzHeld,

		// A caller that answers 503 to a request whose authorization was
		// refused has not served it, and for this control that IS failing
		// closed. It is a worse answer than a 403 and not a defect.
		ClosedWhen: []probe.Disposition{probe.Unavailable},

		Consulted:     dependency.Asked,
		ConsultedWhat: consultsAuthz,
		Refusals:      refusalsOf(dependency),
		DeliveredWhat: deliversAuthz,
		DeliveredHint: hintAuthz,

		Shift:       shiftToOutage(dependency),
		ShiftDetail: shiftAuthzDetail,
		ShiftWhat:   shiftAuthzWhat,
	}, nil
}

// refusalsOf is the retry-storm instrument. Only the credential under test is
// ever answered with a definitive refusal, so this count IS the number of times
// the target asked about a credential it had already been refused for.
func refusalsOf(dependency *authz.Dependency) func() (int64, error) {
	return func() (int64, error) {
		return dependency.Refused(), nil
	}
}

// shiftToOutage is the second phase. It confirms before returning, because an
// unconfirmed shift would leave the deny in place and khaos would measure the
// FIRST fault twice and then compare a window with itself.
func shiftToOutage(
	dependency *authz.Dependency,
) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := dependency.Arm(
			authz.Trap{Kind: authz.Outage},
		); err != nil {
			return err
		}

		_, confirmed, err := dependency.Observe(ctx)
		if err != nil {
			return err
		}

		if !confirmed {
			return fmt.Errorf(errShiftUnconfirmed, ErrShiftUnconfirmed)
		}

		return nil
	}
}

func init() {
	catalogAdd(Definition{
		Name:    NameAPIKeyRevoked,
		Family:  FamilyCredential,
		Summary: summaryAPIKeyRevoked,
		Hypothesis: Hypothesis{
			Condition: "a service's authorization dependency refusing one credential outright, and then becoming unable to answer at all",
			Response:  responseAPIKeyRevoked,
		},
		Polarity:  authzPolarity,
		FaultKind: inject.AuthzKind(authz.Deny),
		Params:    authzParams,
		Build:     buildAPIKeyRevoked,
	})
}
