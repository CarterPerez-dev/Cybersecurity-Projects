// ©AngelaMos | 2026
// params_test.go

package experiment

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	sentinelPrefix = "sentinel-"
	strayName      = "a-name-nobody-declared"
)

// fill supplies a distinguishable value for every declared parameter. A parameter
// that declares a default takes it, because a typed parameter such as a duration
// or a byte count cannot accept an arbitrary sentinel and a build that refuses the
// value never reaches the assertion under test.
func fill(declared []Param) map[string]string {
	supplied := map[string]string{}

	for _, param := range declared {
		if param.Default != "" {
			supplied[param.Name] = param.Default
			continue
		}
		supplied[param.Name] = sentinelPrefix + param.Name
	}

	return supplied
}

func TestBindRejectsAParameterTheExperimentDoesNotDeclare(t *testing.T) {
	declared := []Param{{Name: ParamURL, Usage: usageURL, Required: true}}

	_, err := Bind(declared, map[string]string{ParamURL: "u", strayName: "v"})
	if !errors.Is(err, ErrUndeclaredParam) {
		t.Fatalf(
			"err = %v, want ErrUndeclaredParam; an input nothing will read must not be silently accepted",
			err,
		)
	}

	if !strings.Contains(err.Error(), ParamURL) {
		t.Fatalf(
			"the refusal did not name what this experiment does accept: %v",
			err,
		)
	}
}

func TestBindRejectsAMissingRequiredParameterAndNamesTheFix(t *testing.T) {
	declared := []Param{{Name: ParamTarget, Usage: usageTarget, Required: true}}

	_, err := Bind(declared, nil)
	if err == nil {
		t.Fatal(
			"a missing required parameter was accepted, so the experiment would run against nothing",
		)
	}

	for _, want := range []string{flagSpelling(ParamTarget), usageTarget} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf(
				"the refusal did not name %q, so it does not reach the operator as a fix: %v",
				want,
				err,
			)
		}
	}
}

func TestBindAppliesADeclaredDefaultAndAnOperatorValueOverridesIt(
	t *testing.T,
) {
	declared := []Param{
		{
			Name:    ParamInvalidToken,
			Usage:   usageInvalidToken,
			Default: DefaultInvalidToken,
		},
	}

	bound, err := Bind(declared, nil)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	if got := bound.Get(ParamInvalidToken); got != DefaultInvalidToken {
		t.Fatalf(
			"default not applied: got %q, want %q",
			got,
			DefaultInvalidToken,
		)
	}

	bound, err = Bind(declared, map[string]string{ParamInvalidToken: "mine"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	if got := bound.Get(ParamInvalidToken); got != "mine" {
		t.Fatalf("the declared default overrode the operator: got %q", got)
	}
}

// A parameter with a default is never missing, so declaring it Required as well
// would make the Required check untestable for it. This pins the distinction.
func TestADefaultSatisfiesARequiredParameter(t *testing.T) {
	declared := []Param{
		{Name: ParamToken, Usage: usageToken, Required: true, Default: "d"},
	}

	if _, err := Bind(declared, nil); err != nil {
		t.Fatalf(
			"a required parameter with a default was reported missing: %v",
			err,
		)
	}
}

// The negative control for the stray-read rejection: a definition whose builder
// reaches for a name it never declared. Without this check that read returns an
// empty string with no symptom anywhere.
func TestBuildRejectsABuilderThatReadsAnUndeclaredParameter(t *testing.T) {
	const name = "test.stray_read"

	catalog[name] = Definition{
		Name:      name,
		Family:    FamilyNetwork,
		FaultKind: "test-kind",
		Params: []Param{
			{Name: ParamTarget, Usage: usageTarget, Required: true},
		},
		Build: func(params *Params) (Shape, error) {
			return Shape{
				Target: params.Get(ParamTarget) + params.Get(strayName),
			}, nil
		},
	}
	t.Cleanup(func() { delete(catalog, name) })

	_, err := Build(name, map[string]string{ParamTarget: "t"}, Timing{})
	if !errors.Is(err, ErrStrayParam) {
		t.Fatalf("err = %v, want ErrStrayParam", err)
	}

	if !strings.Contains(err.Error(), strayName) {
		t.Fatalf("the refusal did not name the stray parameter: %v", err)
	}
}

// A declared parameter its builder never reads is a flag the operator can set to
// no effect. This is the check that catches one the moment it is added.
func TestEveryDeclaredParameterIsReadByItsBuilder(t *testing.T) {
	definitions := Catalog()
	if len(definitions) == 0 {
		t.Fatal("the catalogue is empty, so this test proves nothing")
	}

	for _, definition := range definitions {
		t.Run(definition.Name, func(t *testing.T) {
			if len(definition.Params) == 0 {
				t.Fatalf("%s declares no parameters at all", definition.Name)
			}

			bound, err := Bind(definition.Params, fill(definition.Params))
			if err != nil {
				t.Fatalf("bind: %v", err)
			}

			if _, err := definition.Build(bound); err != nil {
				t.Fatalf("build: %v", err)
			}

			if unread := bound.unread(); len(unread) > 0 {
				t.Fatalf(
					"%s declares %v but never reads them, so those flags do nothing",
					definition.Name,
					unread,
				)
			}

			if stray := bound.strayReads(); len(stray) > 0 {
				t.Fatalf(
					"%s reads %v without declaring them",
					definition.Name,
					stray,
				)
			}
		})
	}
}

// catalog and run must not be able to disagree about what an experiment is. The
// builder returns a Shape precisely so it cannot restate any of this and get it
// wrong, and this is the assertion that proves Build carries all of it across.
func TestBuildTakesEveryIdentityFieldFromTheDeclaration(t *testing.T) {
	timing := Timing{
		SampleInterval: time.Millisecond,
		BaselineFor:    2 * time.Millisecond,
		FaultFor:       3 * time.Millisecond,
		RecoveryFor:    4 * time.Millisecond,
	}

	for _, definition := range Catalog() {
		t.Run(definition.Name, func(t *testing.T) {
			spec, err := Build(definition.Name, fill(definition.Params), timing)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			if spec.Name != definition.Name {
				t.Fatalf("name = %q, want %q", spec.Name, definition.Name)
			}
			if spec.Family != definition.Family {
				t.Fatalf("family = %q, want %q", spec.Family, definition.Family)
			}
			if spec.Summary != definition.Summary {
				t.Fatalf(
					"summary = %q, want %q",
					spec.Summary,
					definition.Summary,
				)
			}
			if !slices.Equal(
				spec.Polarity.Defects,
				definition.Polarity.Defects,
			) ||
				spec.Polarity.Rationale != definition.Polarity.Rationale {
				t.Fatalf(
					"polarity = %+v, want %+v",
					spec.Polarity,
					definition.Polarity,
				)
			}
			if spec.Fault.Target != sentinelPrefix+ParamTarget {
				t.Fatalf(
					"fault target = %q, want %q; this is the one value that decides WHICH "+
						"container gets faulted and nothing else asserted it",
					spec.Fault.Target,
					sentinelPrefix+ParamTarget,
				)
			}
			if spec.Fault.Kind != definition.FaultKind {
				t.Fatalf(
					"fault kind = %q, want %q; `khaos catalog` would be advertising a "+
						"different fault than `khaos run` applies",
					spec.Fault.Kind,
					definition.FaultKind,
				)
			}
			if spec.Hypothesis.Response != definition.Hypothesis.Response {
				t.Fatalf(
					"response = %q, want %q",
					spec.Hypothesis.Response,
					definition.Hypothesis.Response,
				)
			}
			if spec.Timing != timing {
				t.Fatalf(
					"timing = %+v, want %+v; a builder that forgets to carry timing "+
						"silently ignores every timing flag",
					spec.Timing,
					timing,
				)
			}
			if !spec.Probes.Complete() {
				t.Fatal("the built experiment has no probe pair")
			}
		})
	}
}

// The condition is the one hypothesis field a build may resolve, because it names
// the actual target. The generic form belongs to the catalogue.
func TestBuildResolvesTheHypothesisConditionAgainstTheTarget(t *testing.T) {
	const target = "a-very-specific-container"

	spec, err := Build(NameDependencyOutage, map[string]string{
		ParamTarget: target,
		ParamURL:    "http://127.0.0.1:1",
		ParamToken:  "t",
	}, Timing{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if !strings.Contains(spec.Hypothesis.Condition, target) {
		t.Fatalf(
			"the hypothesis still reads %q and never names the target",
			spec.Hypothesis.Condition,
		)
	}

	generic := catalog[NameDependencyOutage].Hypothesis.Condition
	if spec.Hypothesis.Condition == generic {
		t.Fatal(
			"the built hypothesis is the catalogue's generic form, so a run reports a " +
				"hypothesis that never mentions what it actually broke",
		)
	}
}

func TestTheNegativeControlCredentialIsNotAcceptableToAnyVerifier(
	t *testing.T,
) {
	spec, err := Build(NameDependencyOutage, map[string]string{
		ParamTarget: "t",
		ParamURL:    "http://127.0.0.1:1",
		ParamToken:  "t",
	}, Timing{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if spec.Probes.Invalid.Credential() != probe.Invalid {
		t.Fatal(
			"the second probe does not carry an invalid credential, so the run has no negative control",
		)
	}
}

func flagSpelling(name string) string {
	return "--" + name
}

// Control at the other end. The probe package proves a Unique probe varies its
// credential; this proves the CATALOGUE asks for one. Deleting `Unique: true`
// from the builder left every probe-level assertion green, which is the whole
// reason both ends need a control.
func TestTheCatalogueAsksForAFreshNegativeControlCredential(t *testing.T) {
	for _, definition := range Catalog() {
		t.Run(definition.Name, func(t *testing.T) {
			var mu sync.Mutex
			seen := map[string]bool{}

			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					seen[r.Header.Get("Authorization")] = true
					mu.Unlock()
					w.WriteHeader(http.StatusUnauthorized)
				}),
			)
			defer server.Close()

			supplied := fill(definition.Params)
			supplied[ParamURL] = server.URL

			spec, err := Build(definition.Name, supplied, fastTiming)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			const rounds = 4
			for range rounds {
				spec.Probes.Invalid.Run(context.Background())
			}

			mu.Lock()
			distinct := len(seen)
			mu.Unlock()

			if distinct != rounds {
				t.Fatalf(
					"%s sent %d distinct invalid credentials across %d probes; a "+
						"credential-keyed decision cache answers every repeat from one cached "+
						"refusal, and a control that stops enforcing during the fault is never "+
						"exercised. Measured against the range: a gateway configured to fail open "+
						"with a cache TTL longer than the fault window reported passed / HELD, "+
						"conclusive, exit 0",
					definition.Name,
					distinct,
					rounds,
				)
			}
		})
	}
}

// An explicitly empty value is a real request, not an absent one. An empty
// credential is sent as no Authorization header at all, which is the canonical
// unauthenticated negative control, so replacing it with the default makes that
// control inexpressible for a tool whose whole thesis is the negative control.
func TestAnExplicitlyEmptyValueIsNotReplacedByTheDefault(t *testing.T) {
	declared := []Param{
		{
			Name:    ParamInvalidToken,
			Usage:   usageInvalidToken,
			Default: DefaultInvalidToken,
		},
	}

	bound, err := Bind(declared, map[string]string{ParamInvalidToken: ""})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	if got := bound.Get(ParamInvalidToken); got != "" {
		t.Fatalf(
			"an explicit empty value became %q, so the unauthenticated negative control "+
				"cannot be asked for",
			got,
		)
	}

	absent, err := Bind(declared, map[string]string{})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	if got := absent.Get(ParamInvalidToken); got != DefaultInvalidToken {
		t.Fatalf(
			"an absent value did not take the declared default, got %q",
			got,
		)
	}
}

func TestAnExplicitlyEmptyRequiredValueIsStillRefused(t *testing.T) {
	declared := []Param{{Name: ParamToken, Usage: usageToken, Required: true}}

	if _, err := Bind(declared, map[string]string{ParamToken: ""}); err == nil {
		t.Fatal(
			"an empty required credential was accepted; the valid probe would carry no " +
				"credential and the baseline would blame the target for not serving",
		)
	}
}
