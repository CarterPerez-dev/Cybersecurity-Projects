// ©AngelaMos | 2026
// authz_test.go

package authz

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/bindguard"
)

const (
	subject = "the-credential-under-test"
	other   = "a-credential-nobody-named"
	loop    = "127.0.0.1:0"
)

func serving(t *testing.T) *Dependency {
	t.Helper()

	dependency := New()

	if err := dependency.Listen(loop); err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() { _ = dependency.Close() })

	return dependency
}

// through reads the dependency the way the TARGET does, over HTTP, because
// every claim khaos makes about this tier is a claim about what the dependency
// answered rather than about what khaos set.
func through(t *testing.T, dependency *Dependency, credential string) int {
	t.Helper()

	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"http://"+dependency.Addr()+"/",
		nil,
	)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	request.Header.Set(headerAuthorization, bearerPrefix+credential)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	_, _ = io.Copy(io.Discard, response.Body)

	return response.StatusCode
}

// An authorization dependency has three outcomes and khaos's stand-in has to
// be able to give all three, because the whole tier exists for the one in the
// middle: a definitive refusal from a dependency that is perfectly reachable.
func TestTheDependencyAnswersAllowDenyAndUnknown(t *testing.T) {
	dependency := serving(t)

	if status := through(t, dependency, subject); status != http.StatusOK {
		t.Fatalf(
			"before any fault the dependency answered %d, want %d: a stand-in that refuses anything it was not told to refuse makes the baseline khaos's posture rather than the target's",
			status,
			http.StatusOK,
		)
	}

	if err := dependency.Arm(
		Trap{Kind: Deny, Credential: subject},
	); err != nil {
		t.Fatalf("arm the deny: %v", err)
	}

	if status := through(
		t,
		dependency,
		subject,
	); status != http.StatusForbidden {
		t.Fatalf("the denied credential was answered %d, want %d",
			status, http.StatusForbidden)
	}

	if err := dependency.Arm(Trap{Kind: Outage}); err != nil {
		t.Fatalf("arm the outage: %v", err)
	}

	if status := through(
		t,
		dependency,
		subject,
	); status != http.StatusServiceUnavailable {
		t.Fatalf("under the outage the dependency answered %d, want %d",
			status, http.StatusServiceUnavailable)
	}
}

// The property the confirmation's control side exists for. A dependency that
// answered 403 to everything would confirm every deny khaos ever armed, and
// the target would be refusing for a reason khaos invented.
func TestADenyIsScopedToOneCredential(t *testing.T) {
	dependency := serving(t)

	if err := dependency.Arm(
		Trap{Kind: Deny, Credential: subject},
	); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if status := through(t, dependency, other); status != http.StatusOK {
		t.Fatalf(
			"denying one credential answered %d for another, want %d: the experiment reads a target refusing every OTHER credential as a defect, so khaos must not be the cause of it",
			status,
			http.StatusOK,
		)
	}
}

// THE negative control. An inert arm prepares everything and tells the
// dependency nothing, so a confirmation that reads khaos's own armed flag
// instead of the dependency's answer says yes here and is worthless.
func TestAnInertArmIsRefusedByTheConfirmation(t *testing.T) {
	dependency := serving(t)

	if err := dependency.Arm(
		Trap{Kind: Deny, Credential: subject, Inert: true},
	); err != nil {
		t.Fatalf("arm: %v", err)
	}

	detail, confirmed, err := dependency.Observe(context.Background())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	if confirmed {
		t.Fatalf(
			"the confirmation accepted an inert arm, with %q: it is reading khaos's own state rather than what the dependency answers",
			detail,
		)
	}

	if status := through(t, dependency, subject); status != http.StatusOK {
		t.Fatalf("an inert arm changed the answer to %d", status)
	}
}

// And the same control for the second phase: the trap is still Outage after a
// disarm, so a confirmation keyed on the trap rather than the answer passes.
func TestAnOutageConfirmationNeedsThe503(t *testing.T) {
	dependency := serving(t)

	if err := dependency.Arm(Trap{Kind: Outage}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if _, confirmed, err := dependency.Observe(
		context.Background(),
	); err != nil || !confirmed {
		t.Fatalf("an armed outage did not confirm: %v, %v", confirmed, err)
	}

	dependency.Disarm()

	if _, confirmed, err := dependency.Observe(
		context.Background(),
	); err != nil || confirmed {
		t.Fatalf(
			"the outage confirmed after a disarm (%v, %v), so it is reading the trap rather than the answer",
			confirmed,
			err,
		)
	}
}

func TestTheConfirmationReportsWhatItRead(t *testing.T) {
	dependency := serving(t)

	if err := dependency.Arm(
		Trap{Kind: Deny, Credential: subject},
	); err != nil {
		t.Fatalf("arm: %v", err)
	}

	detail, confirmed, err := dependency.Observe(context.Background())
	if err != nil || !confirmed {
		t.Fatalf("an armed deny did not confirm: %v, %v", confirmed, err)
	}

	if detail == "" {
		t.Fatal(
			"the confirmation reported no observable; a constant describing the technique is not evidence",
		)
	}
}

// The control side of the two-sided confirmation, driven directly, because the
// input it exists to reject cannot be produced through the dependency's own
// API: a dependency that refused EVERYTHING would confirm the deny khaos armed
// while also refusing the valid credential, and this experiment reports that
// refusal as a defect of the target. The row that matters is the third.
func TestTheConfirmationNeedsBothSides(t *testing.T) {
	for _, row := range []struct {
		name    string
		kind    Kind
		subject int
		control int
		want    bool
	}{
		{
			name:    "the credential is refused and the control is allowed",
			kind:    Deny,
			subject: http.StatusForbidden,
			control: http.StatusOK,
			want:    true,
		},
		{
			name:    "the credential was never refused",
			kind:    Deny,
			subject: http.StatusOK,
			control: http.StatusOK,
			want:    false,
		},
		{
			name:    "the dependency refuses everything",
			kind:    Deny,
			subject: http.StatusForbidden,
			control: http.StatusForbidden,
			want:    false,
		},
		{
			name:    "the outage answers everything",
			kind:    Outage,
			subject: http.StatusServiceUnavailable,
			control: http.StatusServiceUnavailable,
			want:    true,
		},
		{
			name:    "the outage was never armed",
			kind:    Outage,
			subject: http.StatusOK,
			control: http.StatusOK,
			want:    false,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			detail, confirmed, err := confirms(
				row.kind,
				row.subject,
				row.control,
			)
			if err != nil {
				t.Fatalf("confirms: %v", err)
			}

			if confirmed != row.want {
				t.Fatalf(
					"subject %d and control %d confirmed %v, want %v",
					row.subject,
					row.control,
					confirmed,
					row.want,
				)
			}

			if confirmed && detail == "" {
				t.Fatal("confirmed with no observable to report")
			}
		})
	}
}

func TestDisarmRestoresTheAllowEverythingPosture(t *testing.T) {
	dependency := serving(t)

	if err := dependency.Arm(
		Trap{Kind: Deny, Credential: subject},
	); err != nil {
		t.Fatalf("arm: %v", err)
	}

	dependency.Disarm()

	if status := through(t, dependency, subject); status != http.StatusOK {
		t.Fatalf(
			"after the revert the dependency still answered %d for the credential it had denied, want %d: the recovery window measures the target serving again",
			status,
			http.StatusOK,
		)
	}
}

// Asked is a liveness guard three separate verdict branches read, and Refused
// is the retry-storm instrument. Only a definitive refusal increments the
// second, or a caller asking once per request would read as one asking twice.
func TestTheCountersSeparateDecisionsFromRefusals(t *testing.T) {
	dependency := serving(t)

	through(t, dependency, subject)
	through(t, dependency, other)

	asked, err := dependency.Asked()
	if err != nil {
		t.Fatalf("asked: %v", err)
	}

	if asked != 2 {
		t.Fatalf("the dependency counted %d decisions, want 2", asked)
	}

	if refused := dependency.Refused(); refused != 0 {
		t.Fatalf(
			"the dependency counted %d refusals before any fault, want 0",
			refused,
		)
	}

	if err := dependency.Arm(
		Trap{Kind: Deny, Credential: subject},
	); err != nil {
		t.Fatalf("arm: %v", err)
	}

	through(t, dependency, subject)
	through(t, dependency, subject)
	through(t, dependency, other)

	if refused := dependency.Refused(); refused != 2 {
		t.Fatalf(
			"the dependency counted %d refusals, want 2: a credential it allowed must not count, or khaos would report a retry storm on a caller that asked once",
			refused,
		)
	}
}

func TestATrapWithoutACredentialIsRefusedByName(t *testing.T) {
	dependency := serving(t)

	err := dependency.Arm(Trap{Kind: Deny})
	if err == nil {
		t.Fatal(
			"a deny with no credential was armed; it would deny nothing and the confirmation would have nothing to read",
		)
	}

	if status := through(t, dependency, ""); status != http.StatusOK {
		t.Fatalf("the refused arm still changed the answer to %d", status)
	}
}

func TestAnUnknownTrapIsRefusedByName(t *testing.T) {
	dependency := serving(t)

	if err := dependency.Arm(Trap{Kind: "not-a-real-fault"}); err == nil {
		t.Fatal("an invented authorization fault was armed")
	}
}

// Injectable is deliberately smaller than Kinds, and the gap is the whole
// design: every other tier can make a dependency unreachable, so an outage
// exists here only as the second phase of a deny.
func TestInjectableIsASubsetOfKindsAndExcludesTheOutage(t *testing.T) {
	for _, kind := range Injectable() {
		found := false
		for _, known := range Kinds() {
			if kind == known {
				found = true
			}
		}

		if !found {
			t.Fatalf(
				"%s is offered for injection and is not a known kind",
				kind,
			)
		}

		if kind == string(Outage) {
			t.Fatal(
				"the outage is offered as a fault of its own; it would duplicate every network fault khaos already has, and its value is the comparison with the deny",
			)
		}
	}
}

// This dependency ALLOWS every credential until it is told otherwise, so a
// wildcard bind would put an allow-everything authorization service on every
// interface the host has. The refusal is shared with the proxy tier because
// both listeners are things an operator would be horrified to find exposed.
func TestAnExposedBindIsRefused(t *testing.T) {
	for _, addr := range []string{
		"0.0.0.0:45999",
		":45999",
		"[::]:45999",
	} {
		dependency := New()

		err := dependency.Listen(addr)
		if err == nil {
			bound := dependency.Addr()
			_ = dependency.Close()
			t.Fatalf(
				"the dependency bound %s, which is reachable from outside this host",
				bound,
			)
		}

		if !errors.Is(err, bindguard.ErrUnsafeBind) {
			t.Fatalf("%s: err = %v, want ErrUnsafeBind", addr, err)
		}
	}

	// And loopback MUST still be accepted, or the refusal is simply a broken
	// listener rather than a guard.
	dependency := New()
	if err := dependency.Listen(loop); err != nil {
		t.Fatalf("loopback was refused: %v", err)
	}
	_ = dependency.Close()
}

func TestEveryKindDescribesItself(t *testing.T) {
	for _, name := range Kinds() {
		trap := Trap{Kind: Kind(name), Credential: subject}

		if trap.Describe() == "" {
			t.Fatalf("%s describes itself as nothing", name)
		}
	}
}
