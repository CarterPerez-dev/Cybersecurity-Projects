// ©AngelaMos | 2026
// integration_test.go

package experiment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	goodToken  = "a-credential-the-service-accepts"
	bearer     = "Bearer "
	gatewayURL = "/protected"
)

var fastTiming = Timing{
	SampleInterval: time.Millisecond,
	BaselineFor:    20 * time.Millisecond,
	FaultFor:       20 * time.Millisecond,
	RecoveryFor:    10 * time.Millisecond,
}

// service models a control in front of a dependency. When the dependency is
// up it verifies credentials. When the dependency goes down it does whatever
// its policy says, which is the thing khaos exists to measure.
type service struct {
	dependencyUp atomic.Bool
	failOpen     bool
	restarts     atomic.Int64
}

func (s *service) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), bearer)

		if !s.dependencyUp.Load() {
			if s.failOpen {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if token != goodToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	})
}

type serviceInjector struct {
	svc *service
}

func (i *serviceInjector) Inject(context.Context, string, string) error {
	i.svc.dependencyUp.Store(false)
	return nil
}

func (i *serviceInjector) Confirm(context.Context) (string, error) {
	if i.svc.dependencyUp.Load() {
		return "", nil
	}
	return "the dependency reads as down", nil
}

func (i *serviceInjector) Revert(context.Context) error {
	i.svc.dependencyUp.Store(true)
	return nil
}

// Restart is the real thing for this fake: the service drops what it loaded
// from its dependency, which is what a cold start under fault looks like.
func (i *serviceInjector) Restart(context.Context) error {
	i.svc.restarts.Add(1)
	return nil
}

func runAgainst(t *testing.T, svc *service) Result {
	t.Helper()

	svc.dependencyUp.Store(true)

	server := httptest.NewServer(svc.handler())
	t.Cleanup(server.Close)

	spec, err := Build(NameDependencyOutage, map[string]string{
		ParamTarget: "the-dependency",
		ParamURL:    server.URL + gatewayURL,
		ParamToken:  goodToken,
	}, fastTiming)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	engine := Engine{Injector: &serviceInjector{svc: svc}}

	result, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	return result
}

func TestAControlThatFailsClosedIsReportedAsDenied(t *testing.T) {
	result := runAgainst(t, &service{failOpen: false})

	if result.Verdict.Direction != Denied {
		t.Fatalf(
			"direction = %s, want %s (%s)",
			result.Verdict.Direction,
			Denied,
			strings.Join(result.Verdict.Reasons, "; "),
		)
	}

	if result.Verdict.Defect {
		t.Fatal(
			"failing closed was flagged as a defect for a control whose declared defect is failing open",
		)
	}

	if result.Verdict.Epistemic != Deviated {
		t.Fatalf(
			"epistemic = %s, want %s; refusing legitimate traffic is a deviation even though "+
				"it is the safe direction",
			result.Verdict.Epistemic,
			Deviated,
		)
	}
}

func TestAControlThatFailsOpenIsCaughtAndFlaggedADefect(t *testing.T) {
	result := runAgainst(t, &service{failOpen: true})

	if result.Verdict.Direction != Permitted {
		t.Fatalf(
			"direction = %s, want %s (%s)",
			result.Verdict.Direction,
			Permitted,
			strings.Join(result.Verdict.Reasons, "; "),
		)
	}

	if !result.Verdict.Defect {
		t.Fatal(
			"a control that started honouring a credential it had been rejecting was not " +
				"flagged as a defect",
		)
	}

	if !result.Verdict.Conclusive {
		t.Fatal("the finding was not marked conclusive")
	}
}

func TestTheProbeReadsTheBodyAndClassifiesByStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusOK, "accepted"},
		{http.StatusNoContent, "accepted"},
		{http.StatusUnauthorized, "rejected"},
		{http.StatusForbidden, "rejected"},
		{http.StatusTeapot, "rejected"},
		{http.StatusBadRequest, "rejected"},
		{http.StatusNotFound, "rejected"},
		{http.StatusMethodNotAllowed, "rejected"},
		{http.StatusTooManyRequests, "throttled"},
		{http.StatusMovedPermanently, "redirected"},
		{http.StatusFound, "redirected"},
		{http.StatusSeeOther, "redirected"},
		{http.StatusTemporaryRedirect, "redirected"},
		{http.StatusInternalServerError, "unavailable"},
		{http.StatusBadGateway, "unavailable"},
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tc.status)
				}),
			)
			defer server.Close()

			spec, err := Build(NameDependencyOutage, map[string]string{
				ParamTarget: "x",
				ParamURL:    server.URL,
				ParamToken:  goodToken,
			}, fastTiming)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			outcome := spec.Probes.Valid.Run(context.Background())
			if outcome.Disposition.String() != tc.want {
				t.Fatalf(
					"status %d classified as %s, want %s",
					tc.status,
					outcome.Disposition,
					tc.want,
				)
			}

			if outcome.Status != tc.status {
				t.Fatalf(
					"recorded status %d, want %d",
					outcome.Status,
					tc.status,
				)
			}
		})
	}
}

func TestAnUnreachableEndpointIsNotMistakenForARejection(t *testing.T) {
	spec, err := Build(NameDependencyOutage, map[string]string{
		ParamTarget: "x",
		ParamURL:    "http://127.0.0.1:1/never-listening",
		ParamToken:  goodToken,
	}, fastTiming)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	outcome := spec.Probes.Invalid.Run(context.Background())

	// Unreachable rather than Unavailable since the dispositions were split:
	// nothing ANSWERED here. Reading it as a rejection would make an outage
	// look like a control doing its job, and reading it as an answered 503
	// would let a control that declares a 503 its fail-closed outcome cover a
	// target that had died.
	if outcome.Disposition != probe.Unreachable {
		t.Fatalf(
			"a connection failure was classified as %s, want %s",
			outcome.Disposition,
			probe.Unreachable,
		)
	}
}

func TestARedirectingGatewayIsNamedNotBlamed(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.TrimPrefix(
				r.Header.Get("Authorization"),
				bearer,
			) != goodToken {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer server.Close()

	spec, err := Build(NameDependencyOutage, map[string]string{
		ParamTarget: "dep",
		ParamURL:    server.URL + gatewayURL,
		ParamToken:  goodToken,
	}, fastTiming)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	svc := &service{}
	svc.dependencyUp.Store(true)

	engine := Engine{Injector: &serviceInjector{svc: svc}}

	result, err := engine.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if result.Verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s",
			result.Verdict.Epistemic,
			BaselineNotMet,
		)
	}

	joined := strings.Join(result.Verdict.Reasons, " ")
	if !strings.Contains(joined, "redirect") {
		t.Fatalf(
			"khaos refused to run against a redirecting gateway without naming the redirect "+
				"as the cause: %q",
			joined,
		)
	}

	if !strings.Contains(joined, "--url") {
		t.Fatalf("the refusal names a cause but no fix: %q", joined)
	}
}

func TestABaselineBlipDoesNotFabricateABypass(t *testing.T) {
	baseline := healthyBaseline()
	baseline.Invalid = stream(
		probe.Invalid,
		probe.Rejected,
		probe.Accepted,
		probe.Rejected,
		probe.Rejected,
		probe.Rejected,
	)

	clean := probe.Window{
		Valid: stream(probe.Valid, repeat(probe.Accepted, MinimumPaired)...),
		Invalid: stream(
			probe.Invalid,
			repeat(probe.Rejected, MinimumPaired)...),
	}

	verdict := Judge(Observation{
		FaultConfirmed: true,
		Baseline:       baseline,
		Fault:          clean,
		Recovery:       healthyRecovery(),
	}, authPolarity)

	if verdict.Direction == Permitted {
		t.Fatal(
			"one flaky acceptance during the BASELINE was reported as a credential being " +
				"honoured during the fault; the fault window was spotless",
		)
	}
}

func TestAProvenBypassIsReportedEvenOnThinEvidence(t *testing.T) {
	thinButDamning := probe.Window{
		Valid:   stream(probe.Valid, probe.Accepted, probe.Accepted),
		Invalid: stream(probe.Invalid, probe.Accepted, probe.Accepted),
	}

	verdict := Judge(Observation{
		FaultConfirmed: true,
		Baseline:       healthyBaseline(),
		Fault:          thinButDamning,
		Recovery:       healthyRecovery(),
	}, authPolarity)

	if verdict.Direction != Permitted {
		t.Fatalf(
			"direction = %s; a credential the target had already refused being honoured even "+
				"once is PROOF of a bypass, and burying it as thin evidence loses the finding "+
				"khaos exists to produce",
			verdict.Direction,
		)
	}

	if !verdict.Defect {
		t.Fatal("the proven bypass was not flagged as a defect")
	}
}

func TestACleanRunOnThinEvidenceIsNotConclusive(t *testing.T) {
	verdict := Judge(Observation{
		FaultConfirmed: true,
		Baseline:       healthyBaseline(),
		Fault: probe.Window{
			Valid: stream(
				probe.Valid,
				repeat(probe.Accepted, MinimumPaired)...),
			Invalid: stream(
				probe.Invalid,
				repeat(probe.Rejected, MinimumPaired)...),
		},
		Recovery: healthyRecovery(),
	}, authPolarity)

	if verdict.Direction != Held {
		t.Fatalf("direction = %s, want %s", verdict.Direction, Held)
	}

	if verdict.Conclusive {
		t.Fatalf(
			"a clean result on %d samples was called conclusive; the absence of a bypass "+
				"needs a sample-size argument that %d does not supply",
			MinimumPaired,
			MinimumPaired,
		)
	}
}
