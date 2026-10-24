// ©AngelaMos | 2026
// network.go

package experiment

import (
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
)

const (
	NameDependencyHang      = "network.dependency_hang"
	NameDependencyReset     = "network.dependency_reset"
	NameDependencyEOF       = "network.dependency_eof"
	NameDependencyLatency   = "network.dependency_latency"
	NameDependencyPartial   = "network.dependency_partial"
	NameDependencySlowClose = "network.dependency_slow_close"

	ParamDelay = "delay"
	ParamBytes = "bytes"

	// Declared PARAMETERS rather than something startProxy discovers, because
	// discovery made every proxy experiment require the bundled range.
	ParamProxyListen   = "proxy-listen"
	ParamProxyUpstream = "proxy-upstream"

	usageProxyListen   = "the host address khaos binds its fault proxy on, which must be the address your target already dials for this dependency; it has to be a Docker bridge address, because a container cannot reach loopback and khaos will not bind a wildcard"
	usageProxyUpstream = "the real dependency khaos's proxy forwards to, as host:port"

	usageDelay = "how long khaos's proxy holds each exchange with the dependency"
	usageBytes = "how many bytes of the dependency's answer to deliver before closing"

	// Past the range gateway's own upstream timeout, so the default reaches the
	// branch the experiment exists to test rather than producing a slow success.
	defaultDelay = "2s"

	// Enough for a status line and the start of a body, so the target receives a
	// well-formed beginning and a truncated end.
	defaultBytes = "16"

	hangCondition      = "%s accepting connections and never answering them"
	resetCondition     = "%s resetting the connections its caller opens"
	eofCondition       = "%s closing the connections its caller opens without answering"
	latencyCondition   = "every exchange with %s taking %s longer"
	partialCondition   = "%s answering with only the first %d bytes and then closing"
	slowCloseCondition = "%s answering in full but holding the connection open %s longer"

	hangSummary      = "accept the target's connections to its dependency and never answer, which is the failure shape that finds a missing timeout"
	resetSummary     = "reset the target's connections to its dependency, which is the failure shape that finds a swallowed error in the deny path"
	eofSummary       = "close the target's connections to its dependency cleanly, which is what a stopped dependency looks like to its peer"
	latencySummary   = "slow every exchange with the dependency, which finds a timeout that is too generous rather than missing"
	partialSummary   = "truncate the dependency's answer, which finds a parser treating a short read as an empty success"
	slowCloseSummary = "answer in full but never close, which stalls a caller that waits for the close rather than for a length"

	proxyResponse = "refusing credentials it would have refused anyway, rather than letting them through"
)

var proxyPolarity = Polarity{
	Defects:   []Direction{Permitted},
	Rationale: "a control that stops rejecting invalid credentials when its dependency misbehaves has stopped being a control",
}

func proxyParams(extra ...Param) []Param {
	return append([]Param{
		{Name: ParamTarget, Usage: usageTarget, Required: true},
		{Name: ParamURL, Usage: usageURL, Required: true},
		{Name: ParamToken, Usage: usageToken, Required: true},
		{Name: ParamProxyListen, Usage: usageProxyListen, Required: true},
		{Name: ParamProxyUpstream, Usage: usageProxyUpstream, Required: true},
		{
			Name:    ParamInvalidToken,
			Usage:   usageInvalidToken,
			Default: DefaultInvalidToken,
		},
	}, extra...)
}

func proxyEndpoint(params *Params) (string, string) {
	return params.Get(ParamProxyListen), params.Get(ParamProxyUpstream)
}

var delayParam = Param{
	Name:    ParamDelay,
	Usage:   usageDelay,
	Default: defaultDelay,
}

var bytesParam = Param{
	Name:    ParamBytes,
	Usage:   usageBytes,
	Default: defaultBytes,
}

// plainProxyShape covers the three faults that carry no magnitude.
func plainProxyShape(
	kind proxy.Kind,
	condition string,
) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)

		listen, upstream := proxyEndpoint(params)

		return Shape{
			Condition:     fmt.Sprintf(condition, target),
			Target:        target,
			Probes:        probePair(params),
			ProxyFault:    &proxy.Fault{Kind: kind},
			ProxyListen:   listen,
			ProxyUpstream: upstream,
		}, nil
	}
}

func delayedProxyShape(
	kind proxy.Kind,
	condition string,
) func(*Params) (Shape, error) {
	return func(params *Params) (Shape, error) {
		target := params.Get(ParamTarget)

		delay, err := params.Duration(ParamDelay)
		if err != nil {
			return Shape{}, err
		}

		listen, upstream := proxyEndpoint(params)

		return Shape{
			Condition:     fmt.Sprintf(condition, target, delay),
			Target:        target,
			Probes:        probePair(params),
			ProxyFault:    &proxy.Fault{Kind: kind, Delay: delay},
			ProxyListen:   listen,
			ProxyUpstream: upstream,
		}, nil
	}
}

func buildDependencyPartial(params *Params) (Shape, error) {
	target := params.Get(ParamTarget)

	budget, err := params.Count(ParamBytes)
	if err != nil {
		return Shape{}, err
	}

	listen, upstream := proxyEndpoint(params)

	return Shape{
		Condition:     fmt.Sprintf(partialCondition, target, budget),
		Target:        target,
		Probes:        probePair(params),
		ProxyFault:    &proxy.Fault{Kind: proxy.Partial, Bytes: budget},
		ProxyListen:   listen,
		ProxyUpstream: upstream,
	}, nil
}

func proxyDefinition(
	name, summary, condition string,
	kind proxy.Kind,
	extra ...Param,
) Definition {
	build := plainProxyShape(kind, condition)

	switch kind {
	case proxy.Latency, proxy.SlowClose:
		build = delayedProxyShape(kind, condition)
	case proxy.Partial:
		build = buildDependencyPartial
	default:
		// Hang, Reset and EOF take no parameters, so the plain shape stands.
	}

	return Definition{
		Name:    name,
		Family:  FamilyNetwork,
		Summary: summary,
		Hypothesis: Hypothesis{
			Condition: outageGeneric,
			Response:  proxyResponse,
		},
		Polarity:  proxyPolarity,
		FaultKind: inject.ProxyKind(kind),
		Params:    proxyParams(extra...),
		Build:     build,
	}
}

func init() {
	for _, definition := range []Definition{
		proxyDefinition(NameDependencyHang, hangSummary, hangCondition, proxy.Hang),
		proxyDefinition(NameDependencyReset, resetSummary, resetCondition, proxy.Reset),
		proxyDefinition(NameDependencyEOF, eofSummary, eofCondition, proxy.EOF),
		proxyDefinition(NameDependencyLatency, latencySummary, latencyCondition, proxy.Latency, delayParam),
		proxyDefinition(NameDependencySlowClose, slowCloseSummary, slowCloseCondition, proxy.SlowClose, delayParam),
		proxyDefinition(NameDependencyPartial, partialSummary, partialCondition, proxy.Partial, bytesParam),
	} {
		catalog[definition.Name] = definition
	}
}
