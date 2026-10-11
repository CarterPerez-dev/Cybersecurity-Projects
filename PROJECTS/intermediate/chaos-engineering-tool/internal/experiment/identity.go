// ©AngelaMos | 2026
// identity.go

package experiment

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	FamilyIdentity = "identity"

	NameIDPOutage = "identity.idp_outage"

	ParamIdleFor   = "idle-for"
	ParamAuthority = "authority"
	ParamRevocable = "revocable-token"

	usageIdleFor   = "how long to pause traffic, with the fault still applied, to see whether the target's decision cache is being re-armed; it has to outlast the target's own cache lifetime"
	usageAuthority = "khaos's OWN address for the identity provider, which it keeps while the target loses its path to it; this is what makes the revocation real and unreachable at the same time"
	usageRevocable = "a credential the target is honouring and that khaos revokes once the target can no longer reach the authority"

	// Six seconds outlasts the range's own two second decision cache by a wide
	// margin. Against anything else the operator sets it, because khaos cannot
	// discover a cache lifetime it is probing from outside.
	defaultIdleFor = "6s"

	revokePath   = "/revoke"
	revokeParam  = "token"
	revokeMethod = http.MethodPost

	revokeTimeout = 5 * time.Second

	errRevoke       = "khaos could not revoke the credential at %s: %w"
	errRevokeStatus = "the authority at %s answered %d when khaos asked it to revoke a credential, so the revocation did not happen"

	actDetail = "revoking a credential at the authority, which the target can no longer reach"

	// The phrase the verdict uses to say what khaos did. It is per experiment
	// because the three experiments with a revoked stream invalidate their
	// credential three different ways, and only this one does it at an authority
	// the target cannot see.
	defectIDPOutage = "revoking it at an authority the target could no longer reach"

	idpOutageSummary = "sever the target from its identity provider, revoke a credential there, and find out WHY the target still honours it: a decision cache being re-armed by every failed check, or one that never expires at all"

	idpOutageCondition = "%s becoming unreachable to the target while khaos revokes a credential there"

	idpOutageResponse = "refusing the credential khaos revoked, and letting any cached decision lapse on schedule rather than on idleness"
)

// The research calls this the highest-value single experiment in its archive, and
// the reason is the extra phases rather than the fault. Severing a target from its
// identity provider is something several tools can do. Making a change at that
// provider which the target cannot see, and then telling a cache that is being
// RE-ARMED from one that has NO EXPIRY, from outside, with no access to the
// target's source, is what no other tool does. The two have different fixes.
var idpOutagePolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a control that keeps honouring a credential while the authority that could revoke it is unreachable has stopped being a control, and the longer it does so the wider the exposure",
}

// The fault is a PROXY fault and not a pause, and that is forced. A paused
// provider is unreachable by khaos too, so the revocation could not be made at
// all. khaos severs the target's path with its own in-process proxy and keeps its
// own direct path to the authority.
func buildIDPOutage(params *Params) (Shape, error) {
	target := params.Get(ParamTarget)
	probeURL := params.Get(ParamURL)
	authority := params.Get(ParamAuthority)
	revocable := params.Get(ParamRevocable)

	idle, err := params.Duration(ParamIdleFor)
	if err != nil {
		return Shape{}, err
	}

	pair := probePair(params)

	// The third stream. It carries a credential the target is honouring, and its
	// acceptance AFTER khaos revokes it is the finding. It is deliberately not
	// unique per request: the whole question is whether the target's cached
	// decision for THIS credential outlives the authority, and a fresh identity
	// every time would never reach that cache.
	pair.Revoked = probe.NewHTTP(probe.HTTPOptions{
		Name:       probeRevokedName,
		URL:        probeURL,
		Token:      revocable,
		Credential: probe.Revoked,
	})

	listen, upstream := proxyEndpoint(params)

	return Shape{
		Condition:     fmt.Sprintf(idpOutageCondition, target),
		Target:        target,
		Probes:        pair,
		ProxyFault:    &proxy.Fault{Kind: proxy.Hang},
		ProxyListen:   listen,
		ProxyUpstream: upstream,
		IdleFor:       idle,
		Act:           revokeAt(authority, revocable),
		ActDetail:     actDetail,
		Defect:        defectIDPOutage,
	}, nil
}

// revokeAt asks the authority to revoke one credential. A non-2xx answer is a
// FAILED revocation, not a quiet success: the engine voids the run on it, because
// a credential nobody revoked is one the target is correct to keep honouring.
func revokeAt(authority, credential string) func(context.Context) error {
	return func(ctx context.Context) error {
		endpoint, err := url.Parse(authority + revokePath)
		if err != nil {
			return fmt.Errorf(errRevoke, authority, err)
		}

		query := endpoint.Query()
		query.Set(revokeParam, credential)
		endpoint.RawQuery = query.Encode()

		request, err := http.NewRequestWithContext(ctx, revokeMethod, endpoint.String(), nil)
		if err != nil {
			return fmt.Errorf(errRevoke, authority, err)
		}

		client := &http.Client{Timeout: revokeTimeout}

		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf(errRevoke, authority, err)
		}
		defer func() { _ = response.Body.Close() }()

		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf(errRevokeStatus, authority, response.StatusCode)
		}

		return nil
	}
}

func init() {
	catalog[NameIDPOutage] = Definition{
		Name:       NameIDPOutage,
		Family:     FamilyIdentity,
		Summary:    idpOutageSummary,
		Hypothesis: Hypothesis{Condition: outageGeneric, Response: idpOutageResponse},
		Polarity:   idpOutagePolarity,
		FaultKind:  inject.ProxyKind(proxy.Hang),
		Params: append(proxyParams(),
			Param{Name: ParamAuthority, Usage: usageAuthority, Required: true},
			Param{Name: ParamRevocable, Usage: usageRevocable, Required: true},
			Param{Name: ParamIdleFor, Usage: usageIdleFor, Default: defaultIdleFor},
		),
		Build: buildIDPOutage,
	}
}
