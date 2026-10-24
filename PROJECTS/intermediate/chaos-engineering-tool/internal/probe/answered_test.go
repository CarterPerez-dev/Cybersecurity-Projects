// ©AngelaMos | 2026
// answered_test.go

package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A target ANSWERING that it cannot serve and a target not answering at all are
// different observations, and they were one disposition. Four experiments
// declare the first as their fail-closed outcome, so the conflation made a
// crashed target read as one that had correctly refused.
func TestA503AndADeadTargetAreDifferentDispositions(t *testing.T) {
	serving := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}),
	)
	defer serving.Close()

	answered := NewHTTP(HTTPOptions{
		Name:       "answered",
		URL:        serving.URL,
		Credential: Valid,
		Timeout:    time.Second,
	}).Run(context.Background())

	if answered.Disposition != Unavailable {
		t.Fatalf(
			"a target answering 503 produced %s, want %s",
			answered.Disposition,
			Unavailable,
		)
	}

	if answered.Status != http.StatusServiceUnavailable {
		t.Fatalf("the status was not recorded: %d", answered.Status)
	}

	// A listener that is closed: the connection is refused, and nothing
	// answers. This is the case a declared fail-closed set must NOT cover.
	dead := deadAddress(t)

	refused := NewHTTP(HTTPOptions{
		Name:       "refused",
		URL:        "http://" + dead,
		Credential: Valid,
		Timeout:    time.Second,
	}).Run(context.Background())

	if refused.Disposition != Unreachable {
		t.Fatalf(
			"a target that refused the connection produced %s, want %s",
			refused.Disposition,
			Unreachable,
		)
	}

	if refused.Status != 0 {
		t.Fatalf(
			"a probe that was never answered carries status %d; zero is what says nothing answered",
			refused.Status,
		)
	}
}

// Both are real evidence about the target and neither is a decision about the
// credential, so they agree on the two properties every rate is built from.
// Changing either would move the crash check for every experiment.
func TestNeitherCountsAsAnAnswerAndBothAreCountable(t *testing.T) {
	for _, disposition := range []Disposition{Unavailable, Unreachable} {
		if disposition.Answered() {
			t.Fatalf(
				"%s reads as the target having answered, which would let a target that served nothing read as HELD for every experiment that declares no closed set",
				disposition,
			)
		}

		if !disposition.Countable() {
			t.Fatalf(
				"%s is excluded from every rate, so a target in that state would be invisible rather than measured",
				disposition,
			)
		}
	}
}

// deadAddress is a port nothing is listening on, obtained by binding and
// releasing it, so the dial is REFUSED rather than timing out.
func deadAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	return addr
}
