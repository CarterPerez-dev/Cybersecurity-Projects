// ©AngelaMos | 2026
// revocation_test.go

package experiment

import (
	"context"
	"errors"
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
	revokedName  = "test.revocation"
	stillValid   = "a-credential-that-stays-valid"
	toBeRevoked  = "a-credential-khaos-revokes-mid-run"
	corruptToken = "a-token-with-a-corrupted-signature"
)

// authority is the identity provider. khaos can reach it throughout; the TARGET
// loses its path to it when the fault lands, which is what makes a revocation
// real and unreachable at the same time. A paused provider cannot express this,
// because then khaos cannot reach it either.
type authority struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func (a *authority) revoke(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revoked == nil {
		a.revoked = map[string]bool{}
	}
	a.revoked[token] = true
}

func (a *authority) active(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return token != corruptToken && !a.revoked[token]
}

// cachingGateway serves a cached decision when it cannot reach the authority, and
// reArm decides whether serving one also re-arms it.
type cachingGateway struct {
	authority *authority
	reachable atomic.Bool
	reArm     bool
	noExpiry  bool
	ttl       time.Duration

	mu    sync.Mutex
	cache map[string]time.Time
}

func newCachingGateway(
	a *authority,
	reArm, noExpiry bool,
	ttl time.Duration,
) *cachingGateway {
	g := &cachingGateway{
		authority: a, reArm: reArm, noExpiry: noExpiry, ttl: ttl,
		cache: map[string]time.Time{},
	}
	g.reachable.Store(true)
	return g
}

func (g *cachingGateway) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), bearer)

		g.mu.Lock()
		defer g.mu.Unlock()

		expires, known := g.cache[token]
		if known && (g.noExpiry || time.Now().Before(expires)) {
			if !g.reachable.Load() && g.reArm {
				g.cache[token] = time.Now().Add(g.ttl)
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		if !g.reachable.Load() {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if !g.authority.active(token) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		g.cache[token] = time.Now().Add(g.ttl)
		w.WriteHeader(http.StatusOK)
	})
}

type severingInjector struct{ gw *cachingGateway }

func (i *severingInjector) Inject(context.Context, string, string) error {
	i.gw.reachable.Store(false)
	return nil
}

func (i *severingInjector) Confirm(context.Context) (string, error) {
	if i.gw.reachable.Load() {
		return "", nil
	}
	return "the path to the authority reads as severed", nil
}

func (i *severingInjector) Revert(context.Context) error {
	i.gw.reachable.Store(true)
	return nil
}

func (i *severingInjector) Restart(context.Context) error {
	return nil
}

func registerRevocationExperiment(
	t *testing.T,
	url string,
	act func(context.Context) error,
) {
	t.Helper()

	catalog[revokedName] = Definition{
		Name:    revokedName,
		Family:  FamilyNetwork,
		Summary: "a credential revoked at an authority the target can no longer reach",
		Hypothesis: Hypothesis{
			Condition: outageGeneric,
			Response:  outageResponse,
		},
		Polarity:  outagePolarity,
		FaultKind: "test-kind",
		Params: []Param{
			{Name: ParamTarget, Usage: usageTarget, Required: true},
		},
		Build: func(params *Params) (Shape, error) {
			return Shape{
				Target: params.Get(ParamTarget),
				Probes: probe.Pair{
					Valid: probe.NewHTTP(probe.HTTPOptions{
						Name:       "valid",
						URL:        url,
						Token:      stillValid,
						Credential: probe.Valid,
					}),
					Invalid: probe.NewHTTP(probe.HTTPOptions{
						Name:       "control",
						URL:        url,
						Token:      corruptToken,
						Credential: probe.Invalid,
					}),
					Revoked: probe.NewHTTP(probe.HTTPOptions{
						Name:       "revoked",
						URL:        url,
						Token:      toBeRevoked,
						Credential: probe.Revoked,
					}),
				},
				Act:       act,
				ActDetail: "revoking a credential at the authority the target can no longer reach",
				Defect:    testDefectPhrase,
			}, nil
		},
	}

	t.Cleanup(func() { delete(catalog, revokedName) })
}

func runRevocation(
	t *testing.T,
	gw *cachingGateway,
	act func(context.Context) error,
	idle time.Duration,
) Result {
	t.Helper()

	server := httptest.NewServer(gw.handler())
	t.Cleanup(server.Close)

	registerRevocationExperiment(t, server.URL, act)

	spec, err := Build(
		revokedName,
		map[string]string{ParamTarget: "the-authority"},
		Timing{
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
		},
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	spec.IdleFor = idle

	result, err := Engine{
		Injector: &severingInjector{gw: gw},
	}.Run(
		context.Background(),
		spec,
	)
	if err != nil && !errors.Is(err, errActRefused) {
		t.Fatalf("run: %v", err)
	}

	return result
}

var errActRefused = errors.New("the authority refused khaos's change")

// The phrase this experiment supplies for the verdict. It is asserted verbatim
// below rather than loosely matched, because the whole point of the field is
// that each experiment says what IT did: one shared constant previously claimed
// every revocation happened "while that authority was unreachable", which was
// false for two of the three experiments that have a revoked stream.
const testDefectPhrase = "revoking it at an authority the target could no longer reach"

// The finding this whole shape exists to produce, with its own claim. "A
// credential khaos invalidated at the authority was still accepted" is not the
// same statement as "a credential the target had already rejected was
// accepted", and the verdict must make the one that actually happened.
//
// It must also say HOW khaos invalidated it, in this experiment's own words. A
// verdict that falls back to the generic phrase is one that would describe a key
// withdrawal and an unreachable-authority revocation identically.
func TestARevokedCredentialStillHonouredIsItsOwnFinding(t *testing.T) {
	auth := &authority{}
	gw := newCachingGateway(auth, true, false, 60*time.Millisecond)

	result := runRevocation(t, gw, func(context.Context) error {
		auth.revoke(toBeRevoked)
		return nil
	}, 0)

	if result.Verdict.Direction != Permitted {
		t.Fatalf(
			"direction = %s, want %s (%s)",
			result.Verdict.Direction,
			Permitted,
			strings.Join(result.Verdict.Reasons, "; "),
		)
	}

	joined := strings.Join(result.Verdict.Reasons, "; ")

	if !strings.Contains(joined, "invalidated at the authority") {
		t.Fatalf(
			"the verdict does not state what khaos actually observed: %s",
			joined,
		)
	}

	if !strings.Contains(joined, testDefectPhrase) {
		t.Fatalf(
			"the verdict does not say HOW khaos invalidated the credential, so it would read "+
				"identically for every experiment that has a revoked stream: %s",
			joined,
		)
	}

	if strings.Contains(joined, "had already rejected") {
		t.Fatalf(
			"the verdict claims the target honoured something it had already rejected, "+
				"which is not what happened: %s",
			joined,
		)
	}

	if !result.Observation.Acted {
		t.Fatal(
			"the run did not record that khaos made its change at the authority",
		)
	}
}

// A failed action means the credential khaos went on to measure was never
// revoked, so every acceptance of it was correct and the run proves nothing.
func TestAFailedMidRunActionVoidsTheRunRatherThanClearingTheTarget(
	t *testing.T,
) {
	auth := &authority{}
	gw := newCachingGateway(auth, true, false, 60*time.Millisecond)

	result := runRevocation(t, gw, func(context.Context) error {
		return errActRefused
	}, 0)

	if result.Verdict.Epistemic != Aborted {
		t.Fatalf(
			"epistemic = %s, want %s. khaos measured a credential nobody revoked, so a "+
				"clean verdict would be khaos clearing a target it never tested (%s)",
			result.Verdict.Epistemic,
			Aborted,
			strings.Join(result.Verdict.Reasons, "; "),
		)
	}

	if !result.Observation.ActFailed {
		t.Fatal("the run did not record that the action failed")
	}

	if result.Verdict.Direction == Permitted {
		t.Fatal("a run whose action failed reported a bypass")
	}
}

// Revoking a credential the target was never honouring takes nothing away, so
// every later rejection is the target being correct.
func TestTheBaselineRefusesWhenThereIsNothingToRevoke(t *testing.T) {
	auth := &authority{}
	auth.revoke(toBeRevoked)

	gw := newCachingGateway(auth, true, false, 60*time.Millisecond)

	result := runRevocation(
		t,
		gw,
		func(context.Context) error { return nil },
		0,
	)

	if result.Verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s (%s)",
			result.Verdict.Epistemic,
			BaselineNotMet,
			strings.Join(result.Verdict.Reasons, "; "),
		)
	}

	if !strings.Contains(
		strings.Join(result.Verdict.Reasons, "; "),
		"revoking it takes nothing away",
	) {
		t.Fatalf(
			"the refusal does not name the cause: %s",
			strings.Join(result.Verdict.Reasons, "; "),
		)
	}
}

// The discriminator has to read the stream that actually leaked. Reading the
// never-valid control instead would report the pause's effect on something that
// was rejected throughout.
func TestTheDiscriminatorReadsTheStreamThatLeaked(t *testing.T) {
	const ttl = 50 * time.Millisecond

	cases := []struct {
		name  string
		reArm bool
		none  bool
		cause Cause
	}{
		{"re-armed on every failed check", true, false, LapsedOnPause},
		{"stale past the pause", false, true, StalePastPause},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := &authority{}
			gw := newCachingGateway(auth, tc.reArm, tc.none, ttl)

			result := runRevocation(t, gw, func(context.Context) error {
				auth.revoke(toBeRevoked)
				return nil
			}, 10*ttl)

			if result.Verdict.Cause != tc.cause {
				t.Fatalf(
					"cause = %s, want %s (%s)",
					result.Verdict.Cause,
					tc.cause,
					strings.Join(result.Verdict.Reasons, "; "),
				)
			}

			if result.Observation.Resumed.Revoked.Countable() == 0 {
				t.Fatal(
					"the resumed window carries no revoked samples, so the diagnosis read " +
						"a stream the fault never touched",
				)
			}
		})
	}
}
