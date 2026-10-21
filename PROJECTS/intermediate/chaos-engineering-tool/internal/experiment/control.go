// ©AngelaMos | 2026
// control.go

package experiment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	FamilyControl = "control"

	NameRatelimitStoreDown   = "control.ratelimit_store_down"
	NamePolicyStoreDown      = "control.policy_store_down"
	NamePolicyStoreColdStart = "control.policy_store_cold_start"
	NameWAFRulesBackendDown  = "control.waf_rules_backend_down"

	// An ENDPOINT rather than a value, and that is forced rather than chosen.
	// This family's negative control has to be authentic and still refused by
	// the control, so it is signed -- and a signed credential cannot carry an
	// appended nonce without becoming a different fault. Fetching a fresh one
	// per probe is the only way to vary it, and vary it khaos must: a control
	// with a decision cache answers a repeated input from one cached refusal,
	// so a fixed one makes the fail-closed direction unmeasurable.
	//
	// Its own parameter rather than --invalid-token for the same reason: the
	// range can only answer it for this family, and a name the range claims
	// to answer everywhere and answers in one place sends an operator looking
	// for a flag that does nothing.
	ParamRefusedFrom = "refused-from"
)

// ControlSubject is which of a gateway's controls an experiment severs. The
// experiment declares it because the mechanism cannot be read off the fault:
// all four sever with the same proxy and differ only in what they sever.
type ControlSubject string

const (
	SubjectLimiter ControlSubject = "limiter"
	SubjectPolicy  ControlSubject = "policy"
	SubjectRules   ControlSubject = "rules"
)

const (
	usageControlURL = "the endpoint the control you are testing guards, which is the only endpoint whose answer that control decides"

	usageControlRefused = "an endpoint that issues an input this control should refuse: for a rate limiter a credential whose budget is already exhausted, for a policy engine a subject the policy denies, for a rule matcher a request a rule matches. khaos fetches a fresh one for every probe, because a control holding a decision cache answers a repeated input from one cached refusal. This is the negative control, and a run in which khaos never sees it refused is voided rather than concluded"

	conditionRatelimit = "%s losing the datastore its rate limiter counts in"
	conditionPolicy    = "%s losing the store its authorization policy is loaded from"
	conditionColdStart = "%s starting up with the store its authorization policy is loaded from already unreachable"
	conditionRules     = "%s losing the backend its rule set is loaded from"

	summaryRatelimit = "take away the datastore a rate limiter counts in, which is the one control in the taxonomy whose best-known implementation disables itself by default when it cannot count"

	summaryPolicy = "take away the store an authorization policy is loaded from while the target is running, which finds a service that drops the policy it already had"

	summaryColdStart = "start the target with its policy store already unreachable, which finds a service whose empty policy set denies nothing -- a different bug from losing a policy it had loaded, and one that reports the same verdict"

	summaryRules = "take away the backend a rule set is loaded from, which finds the operator's own fallback rather than a vendor default: of the vendors that document one, both deny"

	responseRatelimit = "continuing to refuse requests over the budget, rather than serving them because it cannot count them"

	responsePolicy = "continuing to refuse the subjects its policy denies, rather than serving them because it cannot re-read the policy"

	responseColdStart = "refusing to serve requests it cannot evaluate, rather than treating an empty policy set as a policy that denies nothing"

	responseRules = "continuing to refuse the requests its rules match, rather than passing traffic it cannot inspect"

	defectRatelimit = "a rate limiter that disables itself when its datastore is unreachable"

	defectPolicy = "an authorization policy that stops being enforced when its store is unreachable"

	defectColdStart = "an empty policy set read as a policy that denies nothing"

	defectRules = "a rule set that stops being matched when its backend is unreachable"

	caveatControlHeld = "khaos severed the dependency and confirmed it, and this control kept refusing what it refused before; that is the correct outcome and it carries an availability cost khaos did not measure"

	probeRefusedName = "input-this-control-refuses"

	describeRefused = "an input this control refused while its dependency was reachable, fetched fresh per probe and presented again once it was not"

	errRefusedStatus = "%s answered %d rather than issuing an input this control should refuse"

	errRefusedEmpty = "%s issued an empty input, so this run has no negative control"

	// Short: a negative control khaos cannot fetch inside one sample interval
	// is a probe failure rather than target behaviour, and the run says so.
	refusedTimeout = 3 * time.Second
)

var refusedClient = &http.Client{Timeout: refusedTimeout}

// controlPolarity declares PERMITTED alone. DENIED is this control refusing
// to act on information it does not have, which is correct with an
// availability cost rather than a defect.
//
// The rationale states the counter-argument out loud for the limiter: a
// limiter that disables itself when its datastore is gone is a defensible
// trade when it is deliberate, Kong ships exactly that, and khaos still
// reports it because the operator ran an experiment named after a control.
var controlPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a control that stops refusing what it refused a moment ago has stopped being a control; refusing to serve while it cannot consult its dependency is the correct outcome with an availability cost, not a defect",
}

func controlParams() []Param {
	return []Param{
		{Name: ParamTarget, Usage: usageTarget, Required: true},
		{Name: ParamURL, Usage: usageControlURL, Required: true},
		{Name: ParamToken, Usage: usageToken, Required: true},
		{
			Name:     ParamRefusedFrom,
			Usage:    usageControlRefused,
			Required: true,
		},
		{Name: ParamProxyListen, Usage: usageProxyListen, Required: true},
		{
			Name:     ParamProxyUpstream,
			Usage:    usageProxyUpstream,
			Required: true,
		},
	}
}

// controlProbes drives the guarded endpoint with an input the control allows
// and one it must refuse. Both are credentials the service AUTHENTICATES, so
// a 401 is never what either stream measures.
func controlProbes(params *Params) probe.Pair {
	url := params.Get(ParamURL)

	return probe.Pair{
		Valid: probe.NewHTTP(probe.HTTPOptions{
			Name:       probeValidName,
			URL:        url,
			Token:      params.Get(ParamToken),
			Credential: probe.Valid,
		}),
		Invalid: probe.NewHTTP(probe.HTTPOptions{
			Name:       probeRefusedName,
			Describe:   describeRefused,
			URL:        url,
			Credential: probe.Invalid,
			Mint:       mintRefused(params.Get(ParamRefusedFrom)),
		}),
	}
}

// mintRefused fetches one refused input per probe. A signed credential cannot
// carry an appended nonce without becoming a different fault, so this is how
// the negative control varies.
func mintRefused(from string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		request, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			from,
			nil,
		)
		if err != nil {
			return "", err
		}

		response, err := refusedClient.Do(request)
		if err != nil {
			return "", err
		}
		defer func() { _ = response.Body.Close() }()

		if response.StatusCode != http.StatusOK {
			return "", fmt.Errorf(errRefusedStatus, from, response.StatusCode)
		}

		var body struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			return "", err
		}

		if body.Token == "" {
			return "", fmt.Errorf(errRefusedEmpty, from)
		}

		return body.Token, nil
	}
}

// buildControl severs one dependency with the proxy tier. closed is what this
// control's refusal looks like beyond a Rejected: a limiter answers 429,
// which says nothing about a credential and is still a refusal.
func buildControl(
	condition, defect, probePayload string,
	closed []probe.Disposition,
	cold bool,
) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)
		listen, upstream := proxyEndpoint(params)

		shape := Shape{
			Condition:     fmt.Sprintf(condition, target),
			Target:        target,
			Probes:        controlProbes(params),
			ProxyFault:    &proxy.Fault{Kind: proxy.Reset},
			ProxyListen:   listen,
			ProxyUpstream: upstream,
			ProxyProbe:    probePayload,
			Defect:        defect,
			HeldCaveat:    caveatControlHeld,
			ClosedWhen:    closed,
		}

		if cold {
			shape.ColdStart = true
		}

		return shape, nil
	}
}

func controlDefinition(
	name string,
	subject ControlSubject,
	summary, condition, response, defect, probePayload string,
	closed []probe.Disposition,
	cold bool,
) Definition {
	return Definition{
		Name:    name,
		Family:  FamilyControl,
		Summary: summary,
		Hypothesis: Hypothesis{
			Condition: fmt.Sprintf(condition, "the target"),
			Response:  response,
		},
		Polarity:  controlPolarity,
		FaultKind: inject.ProxyKind(proxy.Reset),
		Control:   subject,
		Params:    controlParams(),
		Build:     buildControl(condition, defect, probePayload, closed, cold),
	}
}

func init() {
	catalogAdd(controlDefinition(
		NameRatelimitStoreDown,
		SubjectLimiter,
		summaryRatelimit,
		conditionRatelimit,
		responseRatelimit,
		defectRatelimit,
		// The only dependency in the catalogue that does not speak HTTP, and
		// the oracle needs it to ANSWER on the direct path.
		proxy.ProbeRESP,
		// A limiter's refusal is a 429, on both streams: the over-budget
		// request it must keep refusing, and the request it refuses because
		// it can no longer count at all.
		[]probe.Disposition{probe.Throttled},
		false,
	))

	catalogAdd(controlDefinition(
		NamePolicyStoreDown,
		SubjectPolicy,
		summaryPolicy,
		conditionPolicy,
		responsePolicy,
		defectPolicy,
		"",
		nil,
		false,
	))

	catalogAdd(controlDefinition(
		NamePolicyStoreColdStart,
		SubjectPolicy,
		summaryColdStart,
		conditionColdStart,
		responseColdStart,
		defectColdStart,
		"",
		nil,
		true,
	))

	catalogAdd(controlDefinition(
		NameWAFRulesBackendDown,
		SubjectRules,
		summaryRules,
		conditionRules,
		responseRules,
		defectRules,
		"",
		nil,
		false,
	))
}
