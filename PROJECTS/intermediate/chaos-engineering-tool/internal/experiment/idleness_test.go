// ©AngelaMos | 2026
// idleness_test.go

package experiment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	cacheTTL    = 60 * time.Millisecond
	leakedToken = "a-credential-the-target-cached-an-allow-for"
	idleName    = "test.idleness"
)

type cachingService struct {
	up       atomic.Bool
	reArm    bool
	noExpiry bool

	mu    sync.Mutex
	cache map[string]time.Time
}

func newCachingService(reArm, noExpiry bool) *cachingService {
	s := &cachingService{
		reArm:    reArm,
		noExpiry: noExpiry,
		cache:    map[string]time.Time{},
	}
	s.up.Store(true)
	s.cache[leakedToken] = time.Now().Add(cacheTTL)
	return s
}

func (s *cachingService) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), bearer)

		if s.up.Load() {
			// While the dependency answers, the control enforces correctly: only
			// the genuinely valid credential is accepted. This is what makes the
			// baseline a steady state and the leaked credential a rejection.
			if token != goodToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		expires, known := s.cache[token]
		if known && (s.noExpiry || time.Now().Before(expires)) {
			if s.reArm {
				s.cache[token] = time.Now().Add(cacheTTL)
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		if token == goodToken {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusForbidden)
	})
}

type cachingInjector struct{ svc *cachingService }

func (i *cachingInjector) Inject(context.Context, string, string) error {
	i.svc.up.Store(false)
	return nil
}

func (i *cachingInjector) Confirm(context.Context) (string, error) {
	if i.svc.up.Load() {
		return "", nil
	}
	return "the dependency reads as down", nil
}

func (i *cachingInjector) Revert(context.Context) error {
	i.svc.up.Store(true)
	return nil
}

func (i *cachingInjector) Restart(context.Context) error {
	return nil
}

// The negative control here is deliberately NOT unique, and that is the opposite
// of what network.dependency_outage needs. There, the control is a credential no
// verifier could ever accept, so a FIXED one lets a cached refusal answer every
// probe and the control is never exercised. Here the control is a credential the
// target has cached an ALLOW for, so it has to be the same credential every time
// or the cached allow is never reached at all.
func registerIdlenessExperiment(t *testing.T) {
	t.Helper()

	catalog[idleName] = Definition{
		Name:    idleName,
		Family:  FamilyNetwork,
		Summary: "a cached allow outliving the authority that could revoke it",
		Hypothesis: Hypothesis{
			Condition: outageGeneric,
			Response:  outageResponse,
		},
		Polarity:  outagePolarity,
		FaultKind: "test-kind",
		Params: []Param{
			{Name: ParamTarget, Usage: usageTarget, Required: true},
			{Name: ParamURL, Usage: usageURL, Required: true},
			{Name: ParamToken, Usage: usageToken, Required: true},
		},
		Build: func(params *Params) (Shape, error) {
			url := params.Get(ParamURL)

			return Shape{
				Target: params.Get(ParamTarget),
				Probes: probe.Pair{
					Valid: probe.NewHTTP(probe.HTTPOptions{
						Name:       probeValidName,
						URL:        url,
						Token:      params.Get(ParamToken),
						Credential: probe.Valid,
					}),
					Invalid: probe.NewHTTP(probe.HTTPOptions{
						Name:       probeInvalidName,
						URL:        url,
						Token:      leakedToken,
						Credential: probe.Invalid,
					}),
				},
			}, nil
		},
	}

	t.Cleanup(func() { delete(catalog, idleName) })
}

func runIdleness(t *testing.T, svc *cachingService, idle time.Duration) Result {
	t.Helper()

	registerIdlenessExperiment(t)

	server := httptest.NewServer(svc.handler())
	t.Cleanup(server.Close)

	spec, err := Build(idleName, map[string]string{
		ParamTarget: "the-identity-provider",
		ParamURL:    server.URL,
		ParamToken:  goodToken,
	}, Timing{
		SampleInterval: time.Millisecond,
		BaselineFor:    20 * time.Millisecond,
		// At least as long as the pause. The TTL-extension diagnosis is only
		// sound when steady traffic kept the credential alive for at least the
		// duration of the pause that then killed it: a fixed lifetime sitting
		// between a short fault window and a longer pause produces the same
		// observation. These tests used a 20ms window against a 600ms pause and
		// asserted a causal claim khaos could not make from it.
		FaultFor:    maxDuration(20*time.Millisecond, idle),
		RecoveryFor: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	spec.IdleFor = idle

	engine := Engine{Injector: &cachingInjector{svc: svc}}

	result, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	return result
}

func TestTheIdlenessDiscriminatorSeparatesTwoCausesOfOneLeak(t *testing.T) {
	const pause = 10 * cacheTTL

	cases := []struct {
		name  string
		svc   *cachingService
		cause Cause
	}{
		{
			"a cache re-armed on every failed check",
			newCachingService(true, false),
			LapsedOnPause,
		},
		{
			"a cache that outlasts the pause",
			newCachingService(false, true),
			StalePastPause,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := runIdleness(t, tc.svc, pause)

			if result.Verdict.Direction != Permitted {
				t.Fatalf(
					"direction = %s, want %s (%s)",
					result.Verdict.Direction,
					Permitted,
					strings.Join(result.Verdict.Reasons, "; "),
				)
			}

			if result.Verdict.Cause != tc.cause {
				t.Fatalf(
					"cause = %s, want %s. These two targets are identical under steady "+
						"traffic and need different fixes, so a verdict that cannot tell them apart "+
						"sends the operator after the wrong bug (%s)",
					result.Verdict.Cause,
					tc.cause,
					strings.Join(result.Verdict.Reasons, "; "),
				)
			}

			if result.Observation.IdleFor != pause {
				t.Fatalf(
					"the run recorded a pause of %s, want %s; a finding whose pause is not "+
						"reported cannot be checked",
					result.Observation.IdleFor,
					pause,
				)
			}
		})
	}
}

// The discriminator costs a pause and a second measurement window. On a target
// that never leaked there is nothing to diagnose, so spending them would be the
// tool deciding to learn nothing slowly.
func TestTheDiscriminatorDoesNotRunOnATargetThatHeld(t *testing.T) {
	registerIdlenessExperiment(t)

	// A target whose cache holds nothing never leaks.
	svc := &cachingService{cache: map[string]time.Time{}}
	svc.up.Store(true)

	server := httptest.NewServer(svc.handler())
	defer server.Close()

	spec, err := Build(idleName, map[string]string{
		ParamTarget: "dep",
		ParamURL:    server.URL,
		ParamToken:  goodToken,
	}, Timing{
		SampleInterval: time.Millisecond,
		BaselineFor:    20 * time.Millisecond,
		FaultFor:       20 * time.Millisecond,
		RecoveryFor:    10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	spec.IdleFor = 10 * time.Second

	started := time.Now()
	result, err := Engine{
		Injector: &cachingInjector{svc: svc},
	}.Run(
		context.Background(),
		spec,
	)
	took := time.Since(started)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if took >= spec.IdleFor {
		t.Fatalf(
			"the run took %s against a %s pause, so it paused traffic on a target with "+
				"nothing to diagnose",
			took,
			spec.IdleFor,
		)
	}

	if result.Verdict.Cause != Undiagnosed {
		t.Fatalf(
			"cause = %s, want %s on a run where the discriminator never ran",
			result.Verdict.Cause,
			Undiagnosed,
		)
	}

	if result.Observation.Resumed.Paired() != 0 {
		t.Fatal(
			"a resumed window was measured although the discriminator did not run",
		)
	}
}

// An experiment that does not ask for the discriminator must never get it, and
// must report its absence rather than a cause it did not establish.
func TestWithoutAPauseTheCauseIsUndiagnosedRatherThanGuessed(t *testing.T) {
	result := runIdleness(t, newCachingService(true, false), 0)

	if result.Verdict.Direction != Permitted {
		t.Fatalf("direction = %s, want %s", result.Verdict.Direction, Permitted)
	}

	if result.Verdict.Cause != Undiagnosed {
		t.Fatalf(
			"cause = %s, want %s. Nothing ran that could tell the causes apart, and naming "+
				"one anyway is a finding khaos did not measure",
			result.Verdict.Cause,
			Undiagnosed,
		)
	}
}

// maxDuration keeps the steady-traffic window at least as long as the pause, so
// the discriminator's causal claim is falsifiable rather than asserted.
func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// The soundness condition itself. A fixed, never-re-armed cache whose lifetime
// sits between the steady-traffic window and the pause produces exactly the
// observation TTL-EXTENSION is built on, so khaos must refuse the causal claim
// when its own window was too short to exclude that.
//
// The gate shipped with `--fault-for 8s --idle-for 14s`, which is that case.
func TestTTLExtensionIsRefusedWhenTheSteadyWindowIsShorterThanThePause(
	t *testing.T,
) {
	lapsed := probe.Window{}
	for range MinimumPaired {
		lapsed.Record(
			probe.Outcome{
				Credential:  probe.Revoked,
				Disposition: probe.Rejected,
			},
		)
	}

	leaked := window(
		probe.Accepted,
		probe.Rejected,
		"",
		probe.Accepted,
		MinimumPaired,
	)

	base := Observation{
		Baseline: window(
			probe.Accepted,
			probe.Rejected,
			"",
			probe.Accepted,
			MinimumPaired,
		),
		Fault: leaked,
		Recovery: window(
			probe.Accepted,
			probe.Rejected,
			"",
			"",
			MinimumPaired,
		),
		Resumed:        lapsed,
		FaultConfirmed: true,
		IdleFor:        14 * time.Second,
		Defect:         "revoking it at the authority",
	}

	unsound := base
	unsound.FaultFor = 8 * time.Second

	if verdict := Judge(unsound, idpPolarity); verdict.Cause != LapsedOnPause {
		t.Fatalf(
			"an 8s steady window against a 14s pause produced %s; a fixed lifetime between "+
				"those two durations explains it just as well (%s)",
			verdict.Cause,
			strings.Join(verdict.Reasons, "; "),
		)
	}

	sound := base
	sound.FaultFor = 14 * time.Second

	verdict := Judge(sound, idpPolarity)

	if verdict.Cause != LapsedOnPause {
		t.Fatalf(
			"a 14s steady window against a 14s pause produced %s, want %s (%s)",
			verdict.Cause,
			LapsedOnPause,
			strings.Join(verdict.Reasons, "; "),
		)
	}

	if !strings.Contains(
		strings.Join(verdict.Reasons, "; "),
		"cannot distinguish an ordinary expiry",
	) {
		t.Fatalf(
			"the diagnosis does not state the fixed-expiry ambiguity: %s",
			strings.Join(verdict.Reasons, "; "),
		)
	}
}
