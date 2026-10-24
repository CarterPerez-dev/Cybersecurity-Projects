// ©AngelaMos | 2026
// experiment_test.go

package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/rangelab"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const bogusExperiment = "network.no_such_experiment"

var testAnswers = rangeAnswers{
	Token:         "a-token",
	Revocable:     "a-revocable-token",
	Authority:     "http://127.0.0.1:30009",
	ProxyListen:   "10.0.0.1:30003",
	ProxyUpstream: "172.20.0.5:8080",

	// The base URL is NOT the listen address, deliberately. khaos binds a
	// bridge address and the container addresses host.docker.internal, so a
	// fixture that made them equal would agree with a bug.
	AuthorityListen: "10.0.0.1:30006",
	AuthorityTLS:    "10.0.0.1:30007",
	AuthorityBase:   "http://host.docker.internal:30006",
	CertHost:        "dependency.khaos.invalid",
	AuthzListen:     "10.0.0.1:30013",
}

// refuser fails the test if khaos goes looking for a range it was never meant to
// need. A reader that merely returns nothing cannot tell "khaos did not look"
// from "khaos looked and found none", and those are different behaviours.
type refuser struct{ t *testing.T }

func (r refuser) Targets(
	context.Context,
	dockerx.Filter,
) ([]dockerx.Target, error) {
	r.t.Fatal(
		"khaos went looking for a range although the operator supplied every parameter " +
			"a range could have answered; an operator pointed at their own stack must not need one running",
	)
	return nil, nil
}

func (r refuser) PublishedPort(context.Context, string, int) (int, error) {
	r.t.Fatal(
		"khaos read a published port although it needed nothing from a range",
	)
	return 0, nil
}

func (r refuser) ContainerEnv(
	context.Context,
	string,
) (map[string]string, error) {
	r.t.Fatal(
		"khaos read a container environment although it needed nothing from a range",
	)
	return nil, nil
}

func (r refuser) NetworkAddress(
	context.Context,
	string,
	string,
) (string, error) {
	r.t.Fatal(
		"khaos read a network address although it needed nothing from a range",
	)
	return "", nil
}

func (r refuser) BridgeGateway(context.Context) (string, error) {
	r.t.Fatal(
		"khaos read the bridge gateway although it needed nothing from a range",
	)
	return "", nil
}

// absent is a daemon with no range on it at all.
type absent struct{}

func (absent) Targets(
	context.Context,
	dockerx.Filter,
) ([]dockerx.Target, error) {
	return nil, nil
}

func (absent) PublishedPort(context.Context, string, int) (int, error) {
	return 0, nil
}

func (absent) ContainerEnv(context.Context, string) (map[string]string, error) {
	return nil, nil
}

func (absent) NetworkAddress(context.Context, string, string) (string, error) {
	return "", nil
}

func (absent) BridgeGateway(context.Context) (string, error) {
	return "", nil
}

func outage(t *testing.T) experiment.Definition {
	t.Helper()

	definition, err := experiment.Lookup(experiment.NameDependencyOutage)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	return definition
}

// The key set has to be knowable without starting anything, because it is what
// decides whether khaos looks for a range at all. Keeping it in a second place
// is only safe if the two cannot drift.
func TestRangeSuppliesIsExactlyTheKeySetOfRangeDefaults(t *testing.T) {
	union := map[string]bool{}

	for _, at := range allTiers() {
		t.Run(tierName(at), func(t *testing.T) {
			for name := range assertKeySet(
				t,
				rangeDefaults(fullLab(), testAnswers, at),
			) {
				union[name] = true
			}
		})
	}

	// Per tier the answers are a SUBSET, because two of them are
	// tier-conditional: the credential tier has no url and no other tier has an
	// engine. Across every tier the union has to be exact, or khaos would
	// refuse a parameter it can fill or try to fill one it cannot.
	supplies := slices.Clone(rangeSupplies())
	slices.Sort(supplies)

	answered := make([]string, 0, len(union))
	for name := range union {
		answered = append(answered, name)
	}
	slices.Sort(answered)

	if !slices.Equal(supplies, answered) {
		t.Fatalf(
			"rangeSupplies() = %v but no tier answers %v",
			supplies,
			answered,
		)
	}
}

// allTiers is every tier the range serves. A test that iterated only the two it
// knew about would go on passing while a whole gateway's answers drifted.
func allTiers() []tier {
	return []tier{
		tierDirect,
		tierProxy,
		tierIdP,
		tierTLS,
		tierDNS,
		tierCred,
		tierPool,
		tierSecret,
		tierEnv,
		tierAuthz,
		tierControlLimiter,
		tierControlPolicy,
		tierControlRules,
	}
}

func tierName(at tier) string {
	switch at {
	case tierProxy:
		return "through the proxy"
	case tierIdP:
		return "against khaos's own provider"
	case tierTLS:
		return "against khaos's own certificate authority"
	case tierDNS:
		return "through khaos's own chaos resolver"
	case tierCred:
		return "over the engine's own administrative protocol"
	case tierPool:
		return "at the service whose pool holds the credential"
	case tierSecret:
		return "at the file the service verifies with"
	case tierEnv:
		return "at the variable the service verifies with"
	case tierAuthz:
		return "at the service whose authorization dependency khaos answers"
	case tierControlLimiter:
		return "at the rate limiter's datastore"
	case tierControlPolicy:
		return "at the policy engine's policy store"
	case tierControlRules:
		return "at the rule matcher's rules backend"
	default:
		return "direct"
	}
}

// fullLab is a range with every gateway present. Each field has to be distinct
// and non-zero or the assertions below cannot tell the gateways apart.
func fullLab() rangelab.Lab {
	return rangelab.Lab{
		Port:         30001,
		ProxiedPort:  30002,
		ProxyPort:    30003,
		VerifierPort: 30004,
		IdPPort:      30005,
		Issuer:       "http://host.docker.internal:30005",

		TLSPort:       30008,
		Dependency:    "https://host.docker.internal:30007",
		AuthorityBase: "http://host.docker.internal:30006",
		CertHost:      "dependency.khaos.invalid",

		DNSPort: 30009,

		// The stateful tier, which `range up --with-db` creates, plus the
		// secret fixture, which the default range does.
		Stateful:      true,
		DBGatewayPort: 30010,
		SecretPort:    30011,
		EnvPort:       30012,

		// The caller whose authorization dependency khaos plays. Its base URL
		// is what khaos reads the port to bind out of, so it is NOT the port
		// the caller itself publishes.
		AuthzPort: 30014,
		AuthzBase: "http://host.docker.internal:30013",

		// The control gateway, and the three addresses it was told to find
		// its three dependencies on. Distinct from each other because the
		// whole point of the tier is that khaos severs exactly one.
		ControlPort:       30015,
		ControlStoreAddr:  "host.docker.internal:30016",
		ControlPolicyAddr: "http://host.docker.internal:30017",
		ControlRulesAddr:  "http://host.docker.internal:30018",
	}
}

// assertKeySet checks one tier and returns the names it answered, so the caller
// can require the union across tiers to be exact.
func assertKeySet(t *testing.T, defaults map[string]string) map[string]bool {
	t.Helper()

	supplies := rangeSupplies()
	answered := map[string]bool{}

	for name, value := range defaults {
		if value == "" {
			t.Fatalf(
				"the range claims to answer %q but answers it with an empty string",
				name,
			)
		}

		if !slices.Contains(supplies, name) {
			t.Fatalf(
				"rangeDefaults answers %q, which rangeSupplies() does not list, so khaos would try to fill a parameter it does not believe it can",
				name,
			)
		}

		answered[name] = true
	}

	return answered
}

func TestAPartlySuppliedInvocationIsRefusedRatherThanFused(t *testing.T) {
	definition := outage(t)

	answerable := answerableFor(definition)

	if len(answerable) < 2 {
		t.Fatalf(
			"%s declares %d range-answerable parameters; with fewer than two there is no "+
				"mixing to refuse and this test cannot fail",
			definition.Name,
			len(answerable),
		)
	}

	for _, given := range answerable {
		t.Run(given, func(t *testing.T) {
			// absent, not refuser: gutting the mixing check must fail this test on
			// the MESSAGE, not on a fake that trips the moment khaos looks for a
			// range. A refuser here would alibi the assertions below.
			_, err := fillFromRange(context.Background(), io.Discard, absent{},
				definition, map[string]string{given: "something"})

			if err == nil {
				t.Fatalf(
					"supplying only --%s was silently completed from the range",
					given,
				)
			}

			if !strings.Contains(err.Error(), "will not fill one half") {
				t.Fatalf("the refusal did not name the cause: %v", err)
			}

			if !strings.Contains(err.Error(), flagPrefix+given) {
				t.Fatalf("the refusal did not name what was given: %v", err)
			}

			for _, other := range answerable {
				if other == given {
					continue
				}
				if !strings.Contains(err.Error(), flagPrefix+other) {
					t.Fatalf(
						"the refusal did not name the missing --%s, so the operator "+
							"cannot tell what to add: %v",
						other,
						err,
					)
				}
			}
		})
	}
}

// Supplying everything a range could answer means the operator is pointing khaos
// at their own stack. khaos must not require a range to be running for that, and
// must not overwrite a single value they gave.
func TestAFullySuppliedInvocationNeverTouchesTheRange(t *testing.T) {
	definition := outage(t)

	supplied := map[string]string{}
	for _, name := range answerableFor(definition) {
		supplied[name] = "operator-" + name
	}

	filled, err := fillFromRange(
		context.Background(),
		io.Discard,
		refuser{t: t},
		definition,
		supplied,
	)
	if err != nil {
		t.Fatalf("fill: %v", err)
	}

	for name, want := range supplied {
		if filled[name] != want {
			t.Fatalf(
				"khaos replaced the operator's --%s %q with %q",
				name,
				want,
				filled[name],
			)
		}
	}
}

func TestAnInvocationWithNoFlagsAtAllLooksForARange(t *testing.T) {
	definition := outage(t)

	_, err := fillFromRange(
		context.Background(),
		io.Discard,
		absent{},
		definition,
		map[string]string{},
	)

	if !errors.Is(err, rangelab.ErrNoRange) {
		t.Fatalf(
			"err = %v, want ErrNoRange; with nothing supplied khaos must go looking for a "+
				"range, and say so when there is none",
			err,
		)
	}

	// The fix has to be the whole fix. Naming a subset sends the operator straight
	// into the half-specified refusal instead.
	for _, name := range answerableFor(definition) {
		if !strings.Contains(err.Error(), flagPrefix+name) {
			t.Fatalf(
				"the refusal does not name --%s, so following it lands the operator in the "+
					"half-specified refusal: %v",
				name,
				err,
			)
		}
	}
}

// A parameter an experiment does not declare must not be settable on it, and one
// it does declare must be. Registering the union of every experiment's parameters
// on one command is what this forbids.
func TestEveryExperimentRegistersExactlyItsDeclaredParameters(t *testing.T) {
	for _, verb := range []string{"run", "plan"} {
		t.Run(verb, func(t *testing.T) {
			parent := find(t, NewRoot(), verb)

			subcommands := parent.Commands()
			if len(subcommands) != len(experiment.Catalog()) {
				t.Fatalf("%s has %d subcommands for %d experiments",
					verb, len(subcommands), len(experiment.Catalog()))
			}

			for _, cmd := range subcommands {
				definition, err := experiment.Lookup(cmd.Name())
				if err != nil {
					t.Fatalf(
						"%s %s is not an experiment: %v",
						verb,
						cmd.Name(),
						err,
					)
				}

				registered := stringFlags(cmd)

				// These three belong to `run` alone: `plan` executes
				// nothing, so it has no outcome to gate and no record to
				// write, and a flag there would do nothing.
				extra := []string{flagProject}
				if verb == "run" {
					extra = append(
						extra,
						flagFailOn,
						flagRecord,
						flagOutput,
						flagJUnit,
						flagMetricsOut,
					)
				}

				want := slices.Concat(extra, names(definition.Params))
				slices.Sort(registered)
				slices.Sort(want)

				if !slices.Equal(registered, want) {
					t.Fatalf(
						"%s %s registers %v, want %v",
						verb,
						cmd.Name(),
						registered,
						want,
					)
				}

				for _, param := range definition.Params {
					flag := cmd.Flags().Lookup(param.Name)
					if !strings.Contains(flag.Usage, param.Usage) {
						t.Fatalf(
							"--%s on %s does not carry the usage the experiment declared",
							param.Name,
							cmd.Name(),
						)
					}
					if flag.DefValue != "" {
						t.Fatalf(
							"--%s on %s registers a non-empty default %q, so khaos can no "+
								"longer tell an operator who set it from one who did not",
							param.Name,
							cmd.Name(),
							flag.DefValue,
						)
					}
				}
			}
		})
	}
}

func TestAFlagTheExperimentNeverDeclaredIsRejected(t *testing.T) {
	root := NewRoot()
	silence(root)
	root.SetArgs(
		[]string{
			"run",
			experiment.NameDependencyOutage,
			"--not-a-parameter-of-anything",
			"x",
		},
	)

	if err := root.Execute(); err == nil {
		t.Fatal(
			"an undeclared flag was accepted, so an operator cannot tell a typo from a parameter",
		)
	}
}

func TestAnUnknownExperimentNamesTheOnesThatExist(t *testing.T) {
	for _, verb := range []string{"run", "plan"} {
		t.Run(verb, func(t *testing.T) {
			root := NewRoot()
			out := &strings.Builder{}
			root.SetOut(out)
			root.SetErr(out)
			root.SetArgs([]string{verb, bogusExperiment})

			err := root.Execute()
			if err == nil {
				t.Fatalf(
					"%s accepted %q as an experiment",
					verb,
					bogusExperiment,
				)
			}

			if !errors.Is(err, experiment.ErrUnknownExperiment) {
				t.Fatalf("err = %v, want ErrUnknownExperiment", err)
			}

			if !strings.Contains(err.Error(), experiment.NameDependencyOutage) {
				t.Fatalf(
					"the refusal did not name an experiment that does exist: %v",
					err,
				)
			}
		})
	}
}

// A typo'd experiment carrying flags must still report the experiment, not the
// flag. The flag is only unknown because the experiment is.
func TestAnUnknownExperimentIsReportedAheadOfItsFlags(t *testing.T) {
	root := NewRoot()
	silence(root)
	root.SetArgs(
		[]string{
			"run",
			bogusExperiment,
			"--" + experiment.ParamURL,
			"http://127.0.0.1:1",
		},
	)

	err := root.Execute()
	if !errors.Is(err, experiment.ErrUnknownExperiment) {
		t.Fatalf(
			"err = %v, want ErrUnknownExperiment; reporting the unknown flag instead buries "+
				"the only thing actually wrong with the line",
			err,
		)
	}
}

func TestNamingNoExperimentAtAllListsThem(t *testing.T) {
	root := NewRoot()
	silence(root)
	root.SetArgs([]string{"run"})

	err := root.Execute()
	if err == nil {
		t.Fatal(
			"`khaos run` with no experiment exited cleanly without running anything",
		)
	}

	if !strings.Contains(err.Error(), experiment.NameDependencyOutage) {
		t.Fatalf("the refusal did not list the experiments: %v", err)
	}
}

func find(t *testing.T, root *cobra.Command, name string) *cobra.Command {
	t.Helper()

	for _, cmd := range root.Commands() {
		if cmd.Name() == name {
			return cmd
		}
	}

	t.Fatalf("no %q command is registered", name)
	return nil
}

func stringFlags(cmd *cobra.Command) []string {
	out := []string{}
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Value.Type() == "string" {
			out = append(out, flag.Name)
		}
	})
	return out
}

func names(params []experiment.Param) []string {
	out := make([]string, 0, len(params))
	for _, param := range params {
		out = append(out, param.Name)
	}
	return out
}

// present is a daemon with a running range on it. Without it nothing executed
// fillFromRange's SUCCESS path at all: refuser fatals the moment khaos looks for
// a range and absent returns nothing, so Discover never succeeded in any test and
// the values the range answers with were unpinned. Deleting the fillFromRange call
// from runPlan entirely, and answering --url with the gateway root instead of
// /protected, both left the Go suite green.
type present struct {
	gateway *httptest.Server
	port    int
}

func (p present) Targets(
	context.Context,
	dockerx.Filter,
) ([]dockerx.Target, error) {
	return []dockerx.Target{{
		ID:        "range-gateway",
		Name:      rangelab.GatewayName,
		Project:   rangelab.ProjectName,
		Running:   true,
		Inspected: true,
	}}, nil
}

func (p present) PublishedPort(context.Context, string, int) (int, error) {
	return p.port, nil
}

func (p present) ContainerEnv(
	context.Context,
	string,
) (map[string]string, error) {
	return map[string]string{}, nil
}

func (p present) NetworkAddress(
	context.Context,
	string,
	string,
) (string, error) {
	return "127.0.0.1", nil
}

func (p present) BridgeGateway(context.Context) (string, error) {
	return "127.0.0.1", nil
}

func rangeOnLoopback(t *testing.T) present {
	t.Helper()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"`+rangeIssuedToken+`"}`)
		}),
	)
	t.Cleanup(server.Close)

	port, err := strconv.Atoi(
		strings.TrimPrefix(server.URL, "http://127.0.0.1:"),
	)
	if err != nil {
		t.Fatalf("the test server is not on loopback: %v", err)
	}

	return present{gateway: server, port: port}
}

const rangeIssuedToken = "a-credential-the-range-issued"

func TestARunningRangeAnswersEveryParameterItClaimsTo(t *testing.T) {
	reader := rangeOnLoopback(t)
	definition := outage(t)

	filled, err := fillFromRange(
		context.Background(),
		io.Discard,
		reader,
		definition,
		map[string]string{},
	)
	if err != nil {
		t.Fatalf("fill: %v", err)
	}

	for _, name := range answerableFor(definition) {
		if filled[name] == "" {
			t.Fatalf("the range claims to answer --%s and left it empty", name)
		}
	}

	// The VALUES matter, not just the keys. Answering --url with the gateway root
	// instead of the protected endpoint probes a path that needs no credential, so
	// the baseline never observes enforcement and every verdict is baseline-not-met.
	if filled[experiment.ParamURL] != reader.gateway.URL+"/protected" {
		t.Fatalf(
			"--url answered as %q, want the protected endpoint; probing the gateway root "+
				"measures a path that needs no credential",
			filled[experiment.ParamURL],
		)
	}

	// The target is the DEPENDENCY, not the gateway. Pausing the gateway pauses the
	// thing being measured rather than the thing being taken away.
	if filled[experiment.ParamTarget] != rangelab.IDPName {
		t.Fatalf("--target answered as %q, want the identity provider %q",
			filled[experiment.ParamTarget], rangelab.IDPName)
	}

	if filled[experiment.ParamToken] != rangeIssuedToken {
		t.Fatalf("--token was not the credential the range issued, got %q",
			filled[experiment.ParamToken])
	}
}

// The note is the only thing telling an operator which stack khaos just chose for
// them, and it must never print the credential.
func TestTheRangeNoteNamesWhatWasChosenAndNeverTheCredential(t *testing.T) {
	out := &strings.Builder{}

	if _, err := fillFromRange(
		context.Background(),
		out,
		rangeOnLoopback(t),
		outage(t),
		map[string]string{},
	); err != nil {
		t.Fatalf("fill: %v", err)
	}

	printed := out.String()

	if !strings.Contains(printed, "using the running range") {
		t.Fatalf(
			"khaos filled an invocation from the range without saying so: %q",
			printed,
		)
	}

	if !strings.Contains(printed, rangelab.IDPName) {
		t.Fatalf("the note does not name the target it chose: %q", printed)
	}

	if strings.Contains(printed, rangeIssuedToken) {
		t.Fatalf("the note printed the credential: %q", printed)
	}
}

// Required bits on the shipped catalogue were asserted by nothing. Every CLI path
// reaches Build through fillFromRange, so if the range cannot answer an
// experiment's required parameters the zero-flag commitment is broken for it.
func TestTheRangeCanSatisfyEveryExperimentsRequiredParameters(t *testing.T) {
	lab := fullLab()

	for _, definition := range experiment.Catalog() {
		t.Run(definition.Name, func(t *testing.T) {
			defaults := rangeDefaults(
				lab,
				testAnswers,
				tierOf(definition),
			)

			supplied := map[string]string{}
			for _, param := range definition.Params {
				if value, answerable := defaults[param.Name]; answerable {
					supplied[param.Name] = value
				}
			}

			// Every catalogue entry BUILDS, including the two DNS faults khaos
			// refuses to deliver. They are catalogued in order to be explained,
			// and the refusal arrives when khaos is asked to arm one, which is
			// what keeps this census able to walk the whole catalogue.
			_, err := experiment.Build(
				definition.Name,
				supplied,
				experiment.Timing{},
			)
			if err != nil {
				t.Fatalf(
					"the range cannot satisfy %s, so it cannot run with zero flags: %v",
					definition.Name,
					err,
				)
			}
		})
	}
}

// The range carries FIVE gateways and they are not interchangeable. Each one
// exists so one injection tier is measured on a path nothing else contaminates:
// a proxy-tier experiment arms a fault on the path only the proxied gateway
// uses, an identity-tier one arms a provider only the verifier gateway resolves
// keys from, and a certificate-tier one arms an authority only the TLS gateway
// dials. Pointing any of them at the wrong gateway measures a service with no
// causal connection to the fault and reports a clean survival over an armed
// fault.
func TestEveryExperimentIsPointedAtTheGatewayItsFaultActuallyAffects(
	t *testing.T,
) {
	lab := fullLab()

	// The credential tier has NO url, and that is a property rather than an
	// omission: its probe streams are database connections, so there is no
	// gateway in front of the dependency and nothing to address over HTTP. A
	// url filled in here would be a flag the operator can set to no effect.
	want := map[tier]string{
		tierDirect: lab.ProtectedURL(),
		tierProxy:  lab.ProxiedProtectedURL(),
		tierIdP:    lab.VerifierProtectedURL(),
		tierTLS:    lab.TLSProtectedURL(),
		tierDNS:    lab.DNSProtectedURL(),
		tierCred:   "",
		tierPool:   lab.DBProtectedURL(),
		tierSecret: lab.SecretProtectedURL(),
		tierEnv:    lab.EnvProtectedURL(),
		tierAuthz:  lab.AuthzProtectedURL(),

		tierControlLimiter: lab.ControlGatewayURL() + rangelab.LimitedPath,
		tierControlPolicy:  lab.ControlGatewayURL() + rangelab.GovernedPath,
		tierControlRules:   lab.ControlGatewayURL() + rangelab.FilteredPath,
	}

	seen := map[string]tier{}
	for at, url := range want {
		if other, clash := seen[url]; clash {
			t.Fatalf(
				"%s and %s resolve to the same URL, so this test cannot tell them apart",
				tierName(at),
				tierName(other),
			)
		}
		seen[url] = at
	}

	exercised := map[tier]bool{}

	for _, definition := range experiment.Catalog() {
		t.Run(definition.Name, func(t *testing.T) {
			at := tierOf(definition)
			exercised[at] = true

			defaults := rangeDefaults(lab, testAnswers, at)

			if answered := defaults[experiment.ParamURL]; answered != want[at] {
				t.Fatalf("%s injects %s and is probed at %q, want %q",
					definition.Name, definition.FaultKind, answered, want[at])
			}

			// The three per-run tiers name their GATEWAY rather than the
			// dependency, because that is the container khaos needs consent for
			// and the one it actually measures. The fault lands on khaos's own
			// provider, authority or resolver, which is not the dependency at
			// all, so naming the dependency would ask consent for something
			// this experiment never touches and leave the measured service
			// unchecked.
			//
			// The DNS tier is the clearest case of it: the dependency stays
			// healthy and reachable throughout, and what changes is only whether
			// the gateway can find it.
			wantTarget := rangelab.IDPName

			switch at {
			case tierProxy:
				wantTarget = rangelab.ProxiedGatewayName
			case tierIdP:
				wantTarget = rangelab.VerifierGatewayName
			case tierTLS:
				wantTarget = rangelab.TLSGatewayName
			case tierDNS:
				wantTarget = rangelab.DNSGatewayName

			// The one tier whose target IS the dependency, because khaos does
			// not replace this authority: the fault is performed on the engine
			// itself, on a role khaos mints there for the run.
			case tierCred:
				wantTarget = rangelab.PostgresName

			// The pooled faults measure the SERVICE and rotate at the engine,
			// so the consent they ask for is the service's.
			case tierPool:
				wantTarget = rangelab.DBGatewayName

			case tierSecret:
				wantTarget = rangelab.SecretGatewayName

			// A SECOND secret fixture, whose secret is in its environment.
			// These faults REPLACE the container, and doing that to the file
			// fixture would take the volume's experiments with it.
			case tierEnv:
				wantTarget = rangelab.EnvGatewayName

			// The CALLER, which is the only container in this tier: khaos
			// replaces the dependency it asks, and that dependency is a
			// listener in khaos's own process rather than a container at all.
			case tierAuthz:
				wantTarget = rangelab.AuthzGatewayName

			// One gateway for all three, because the fault lands on khaos's
			// proxy in front of a dependency rather than on the dependency.
			// The three tiers differ in which of its controls is measured,
			// never in whose consent is needed.
			case tierControlLimiter, tierControlPolicy, tierControlRules:
				wantTarget = rangelab.ControlGatewayName

			default:
				// The direct and proxy tiers fault the dependency itself.
			}

			if answered := defaults[experiment.ParamTarget]; answered != wantTarget {
				t.Fatalf("%s asks consent for %q, want %q",
					definition.Name, answered, wantTarget)
			}
		})
	}

	for _, at := range allTiers() {
		if !exercised[at] {
			t.Errorf(
				"the catalogue exercises no experiment %s, so this test cannot fail for that tier",
				tierName(at),
			)
		}
	}
}

// answerableFor is the intersection khaos actually acts on: the parameters this
// experiment declares AND the range can answer. Iterating the global list
// instead made these tests demand flags the experiment under test does not take.
func answerableFor(definition experiment.Definition) []string {
	out := []string{}

	for _, param := range definition.Params {
		if slices.Contains(rangeSupplies(), param.Name) {
			out = append(out, param.Name)
		}
	}

	return out
}

// A credential supplied as a FLAG is in /proc/<pid>/cmdline, which is
// world-readable (mode 444, measured), while /proc/<pid>/environ is 400. That
// is why the chaos resolver's nonce has always been an environment variable
// rather than an argument, and `credential.apikey_revoked` is the first
// experiment to require TWO live credentials, so argv-only put both of an
// operator's secrets in the process table and in shell history.
func TestAParameterCanArriveInTheEnvironmentInsteadOfArgv(t *testing.T) {
	definition := outage(t)

	t.Setenv("KHAOS_TOKEN", "a-credential-from-the-environment")

	cmd := newRunCmd()
	cmd.SetArgs([]string{definition.Name})

	in, err := experimentInputs(
		experimentCmdFor(t, cmd, definition),
		definition,
	)
	if err != nil {
		t.Fatalf("inputs: %v", err)
	}

	if in.Supplied[experiment.ParamToken] != "a-credential-from-the-environment" {
		t.Fatalf(
			"the environment channel was ignored: %q; a credential has no other way in that keeps it out of the process table",
			in.Supplied[experiment.ParamToken],
		)
	}
}

// The FLAG still wins, because an operator who typed one meant it, and the
// environment must not silently override what they just said.
func TestAFlagBeatsTheEnvironment(t *testing.T) {
	definition := outage(t)

	t.Setenv("KHAOS_TOKEN", "from-the-environment")

	cmd := newRunCmd()
	sub := experimentCmdFor(t, cmd, definition)

	if err := sub.Flags().
		Set(experiment.ParamToken, "from-the-flag"); err != nil {
		t.Fatalf("set the flag: %v", err)
	}

	in, err := experimentInputs(sub, definition)
	if err != nil {
		t.Fatalf("inputs: %v", err)
	}

	if in.Supplied[experiment.ParamToken] != "from-the-flag" {
		t.Fatalf(
			"the environment overrode a flag the operator typed: %q",
			in.Supplied[experiment.ParamToken],
		)
	}
}

// And the mapping is DERIVED from the parameter's name, so a new parameter gets
// the channel without anyone remembering to add it.
func TestTheEnvironmentNameIsDerivedFromTheParameter(t *testing.T) {
	for param, want := range map[string]string{
		experiment.ParamToken:        "KHAOS_TOKEN",
		experiment.ParamRevocable:    "KHAOS_REVOCABLE_TOKEN",
		experiment.ParamAuthzListen:  "KHAOS_AUTHZ_LISTEN",
		experiment.ParamInvalidToken: "KHAOS_INVALID_TOKEN",
	} {
		if got := envFor(param); got != want {
			t.Fatalf("envFor(%q) = %q, want %q", param, got, want)
		}
	}
}

// experimentCmdFor finds the per-experiment subcommand, which is where the
// parameters are declared as flags.
func experimentCmdFor(
	t *testing.T,
	root *cobra.Command,
	definition experiment.Definition,
) *cobra.Command {
	t.Helper()

	for _, sub := range root.Commands() {
		if sub.Name() == definition.Name {
			return sub
		}
	}

	t.Fatalf("no subcommand for %s", definition.Name)

	return nil
}
