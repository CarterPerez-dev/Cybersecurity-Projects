// ©AngelaMos | 2026
// call.go

package probe

import (
	"context"
	"time"
)

// CallOptions is a probe whose transport is not HTTP. The caller supplies the
// one function that asks a question and says what the answer was, which keeps
// this package free of every protocol khaos learns to speak.
type CallOptions struct {
	Name       string
	Describe   string
	Credential Credential
	Call       func(context.Context) (Disposition, string)
}

type CallProbe struct {
	options CallOptions
}

func NewCall(options CallOptions) *CallProbe {
	return &CallProbe{options: options}
}

func (p *CallProbe) Name() string {
	return p.options.Name
}

func (p *CallProbe) Credential() Credential {
	return p.options.Credential
}

func (p *CallProbe) Describe() string {
	return p.options.Describe
}

func (p *CallProbe) Run(ctx context.Context) Outcome {
	started := time.Now().UTC()

	outcome := Outcome{
		At:          started,
		Credential:  p.options.Credential,
		Disposition: Unknown,
	}

	if p.options.Call == nil {
		outcome.Disposition = ProbeFailed
		outcome.Detail = detailNoCall
		return outcome
	}

	disposition, detail := p.options.Call(ctx)

	outcome.SetLatency(time.Since(started))
	outcome.Disposition = disposition
	outcome.Detail = detail

	return outcome
}

const detailNoCall = "this probe was built with nothing to call, which is khaos's own fault and not a target behaviour"
