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

	// Clears the range's own decision cache; against anything else the operator
	// sets it, because khaos cannot discover a cache lifetime from outside.
	defaultIdleFor = "6s"

	revokePath   = "/revoke"
	revokeParam  = "token"
	revokeMethod = http.MethodPost

	revokeTimeout = 5 * time.Second

	errRevoke       = "khaos could not revoke the credential at %s: %w"
	errRevokeStatus = "the authority at %s answered %d when khaos asked it to revoke a credential, so the revocation did not happen"

	actDetail = "revoking a credential at the authority, which the target can no longer reach"

	defectIDPOutage = "revoking it at an authority the target could no longer reach"

	idpOutageSummary = "sever the target from its identity provider, revoke a credential there, and find out WHY the target still honours it: a decision cache being re-armed by every failed check, or one that never expires at all"

	idpOutageCondition = "%s becoming unreachable to the target while khaos revokes a credential there"

	idpOutageResponse = "refusing the credential khaos revoked, and letting any cached decision lapse on schedule rather than on idleness"
)

var idpOutagePolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a control that keeps honouring a credential while the authority that could revoke it is unreachable has stopped being a control, and the longer it does so the wider the exposure",
}

// A PROXY fault and not a pause, which is forced: a paused provider would be
// unreachable by khaos too, so the revocation could not be made at all.
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

	// NOT unique per request: the question is whether the target's cached
	// decision for THIS credential outlives the authority.
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

// revokeAt treats a non-2xx as a FAILED revocation and voids the run, because a
// credential nobody revoked is one the target is correct to keep honouring.
func revokeAt(authority, credential string) func(context.Context) error {
	return func(ctx context.Context) error {
		endpoint, err := url.Parse(authority + revokePath)
		if err != nil {
			return fmt.Errorf(errRevoke, authority, err)
		}

		query := endpoint.Query()
		query.Set(revokeParam, credential)
		endpoint.RawQuery = query.Encode()

		request, err := http.NewRequestWithContext(
			ctx,
			revokeMethod,
			endpoint.String(),
			nil,
		)
		if err != nil {
			return fmt.Errorf(errRevoke, authority, err)
		}

		client := &http.Client{Timeout: revokeTimeout}

		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf(errRevoke, authority, err)
		}
		defer func() { _ = response.Body.Close() }()

		if response.StatusCode < http.StatusOK ||
			response.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf(errRevokeStatus, authority, response.StatusCode)
		}

		return nil
	}
}

func init() {
	catalog[NameIDPOutage] = Definition{
		Name:    NameIDPOutage,
		Family:  FamilyIdentity,
		Summary: idpOutageSummary,
		Hypothesis: Hypothesis{
			Condition: outageGeneric,
			Response:  idpOutageResponse,
		},
		Polarity:  idpOutagePolarity,
		FaultKind: inject.ProxyKind(proxy.Hang),
		Params: append(
			proxyParams(),
			Param{Name: ParamAuthority, Usage: usageAuthority, Required: true},
			Param{Name: ParamRevocable, Usage: usageRevocable, Required: true},
			Param{
				Name:    ParamIdleFor,
				Usage:   usageIdleFor,
				Default: defaultIdleFor,
			},
		),
		Build: buildIDPOutage,
	}
}
