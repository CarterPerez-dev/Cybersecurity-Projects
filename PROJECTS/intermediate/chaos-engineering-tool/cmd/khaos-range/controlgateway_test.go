// ©AngelaMos | 2026
// controlgateway_test.go

package main

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const controlTestSecret = "a-signing-key-for-this-test"

// stubStore is a datastore that speaks enough RESP to answer the two commands
// a fixed-window counter sends, and that can be taken away mid-test the way
// khaos's proxy takes the real one away.
type stubStore struct {
	listener net.Listener

	// resetting accepts the connection and then resets it, which is what
	// khaos's proxy.Reset fault does. Closing the listener instead produces a
	// refused DIAL, a different code path: the client fails before it ever
	// writes a command, so the mid-protocol failure production actually hits
	// goes unexercised.
	resetting atomic.Bool

	mu     sync.Mutex
	counts map[string]int64
}

func newStubStore(t *testing.T) *stubStore {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the stub datastore: %v", err)
	}

	store := &stubStore{listener: listener, counts: map[string]int64{}}
	t.Cleanup(store.close)

	go store.serve()

	return store
}

func (s *stubStore) address() string {
	return s.listener.Addr().String()
}

func (s *stubStore) close() {
	_ = s.listener.Close()
}

func (s *stubStore) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.handle(conn)
	}
}

func (s *stubStore) reset() {
	s.resetting.Store(true)
}

func (s *stubStore) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if s.resetting.Load() {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}

		return
	}

	reader := bufio.NewReader(conn)

	for {
		parts, err := readCommand(reader)
		if err != nil {
			return
		}

		if len(parts) == 0 {
			return
		}

		reply := ":1\r\n"

		if strings.EqualFold(parts[0], respINCR) && len(parts) > 1 {
			s.mu.Lock()
			s.counts[parts[1]]++
			reply = ":" + strconv.FormatInt(s.counts[parts[1]], 10) + "\r\n"
			s.mu.Unlock()
		}

		if _, err = conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// readCommand parses the array-of-bulk-strings encoding respEncode writes,
// which is the only shape the fixture ever sends.
func readCommand(reader *bufio.Reader) ([]string, error) {
	header, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	count, err := strconv.Atoi(strings.TrimRight(header[1:], "\r\n"))
	if err != nil {
		return nil, err
	}

	parts := make([]string, 0, count)

	for range count {
		if _, err = reader.ReadString('\n'); err != nil {
			return nil, err
		}

		value, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		parts = append(parts, strings.TrimRight(value, "\r\n"))
	}

	return parts, nil
}

// controlFixture wires the gateway to a live datastore and a live backend, so
// every test below measures the real client paths rather than a stub decision.
func controlFixture(
	t *testing.T,
	failMode string,
) (*controlGateway, *stubStore, *httptest.Server) {
	t.Helper()

	store := newStubStore(t)

	backend := httptest.NewServer(newControlBackend().routes())
	t.Cleanup(backend.Close)

	gateway := newControlGateway(
		store.address(),
		backend.URL,
		backend.URL,
		failMode,
		controlTestSecret,
		defaultLimit,
	)

	return gateway, store, backend
}

// loaded waits for the first refresh: a control holding a last-known-good
// starts without one, and that state is a different test.
func loaded(t *testing.T, gateway *controlGateway) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		gateway.mu.Lock()
		ready := gateway.loadedPolicy && gateway.loadedRules
		gateway.mu.Unlock()

		if ready {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the gateway never loaded a policy or a rule set")
}

// awaitStale waits for the gateway to NOTICE its policy store is gone. It
// fails rather than falling through: a timeout here means the state never
// arrived, and reading that as a content failure sends the reader to the
// wrong line.
func awaitStale(t *testing.T, gateway *controlGateway) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		gateway.mu.Lock()
		stale := !gateway.freshPolicy
		gateway.mu.Unlock()

		if stale {
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("the gateway never noticed its policy store was unreachable")
}

func token(t *testing.T, mux *http.ServeMux, path string) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPost, path, nil),
	)

	var body struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decode the issued credential: %v", err)
	}

	if body.Token == "" {
		t.Fatal("the fixture issued an empty credential")
	}

	return body.Token
}

func call(
	t *testing.T,
	mux *http.ServeMux,
	path, credential string,
) (int, string) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set(headerAuthorization, bearerPrefix+credential)

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)

	return recorder.Code, recorder.Header().Get(headerControlReason)
}

// Every control sits behind this service's own authentication, so a refusal
// from one is never read as the service failing to identify the caller.
func TestEveryControlAuthenticatesFirst(t *testing.T) {
	gateway, _, _ := controlFixture(t, FailClosed)
	mux := gateway.routes()

	for _, path := range []string{
		routeLimited,
		routeGoverned,
		routeFiltered,
	} {
		status, _ := call(t, mux, path, "a-credential-nobody-issued")
		if status != http.StatusUnauthorized {
			t.Errorf(
				"%s answered %d to a credential this service never issued, want 401",
				path,
				status,
			)
		}
	}
}

// While the limiter can count, the flagged credential has no budget and must
// be throttled. That refusal is this control's negative control.
func TestTheLimiterThrottlesWhatHasNoBudget(t *testing.T) {
	gateway, _, _ := controlFixture(t, FailClosed)
	mux := gateway.routes()

	status, reason := call(t, mux, routeLimited, token(t, mux, issuePath))
	if status != http.StatusOK {
		t.Errorf(
			"an ordinary credential within its budget got %d (%s), want 200",
			status,
			reason,
		)
	}

	status, reason = call(
		t,
		mux,
		routeLimited,
		token(t, mux, routeFlaggedToken),
	)
	if status != http.StatusTooManyRequests {
		t.Errorf(
			"a credential with no budget got %d (%s), want 429",
			status,
			reason,
		)
	}
}

// F8, both directions: the datastore is severed while the limit itself is
// still known, which is where Kong's fault_tolerant decides.
func TestTheLimiterSplitsOnItsFailModeWhenTheDatastoreIsGone(t *testing.T) {
	// The REASON, not only the status: a flagged credential is refused 429
	// whether the limiter is over budget or cannot count at all, so a row
	// asserting the status alone survives the severance being deleted.
	for _, row := range []struct {
		mode   string
		status int
		reason string
	}{
		{FailOpen, http.StatusOK, reasonLimiterFellOpen},
		{FailClosed, http.StatusTooManyRequests, reasonLimiterHeld},
	} {
		for _, sever := range []struct {
			name string
			how  func(*stubStore)
		}{
			// Both shapes, because they take different paths through the
			// client: a refused dial fails before a command is written, and
			// a reset fails mid-protocol. khaos's proxy applies the second.
			{"the datastore refuses the dial", (*stubStore).close},
			{"the datastore resets the connection", (*stubStore).reset},
		} {
			t.Run(row.mode+", "+sever.name, func(t *testing.T) {
				gateway, store, _ := controlFixture(t, row.mode)
				mux := gateway.routes()

				flagged := token(t, mux, routeFlaggedToken)

				if status, _ := call(
					t,
					mux,
					routeLimited,
					flagged,
				); status != http.StatusTooManyRequests {
					t.Fatalf(
						"the limiter was not enforcing before the fault, got %d",
						status,
					)
				}

				sever.how(store)

				status, reason := call(t, mux, routeLimited, flagged)
				if status != row.status {
					t.Errorf(
						"with the datastore severed, %s answered %d (%s), want %d",
						row.mode,
						status,
						reason,
						row.status,
					)
				}

				if reason != row.reason {
					t.Errorf(
						"%s refused for %q, want %q; the status alone cannot tell "+
							"'over budget' from 'cannot count'",
						row.mode,
						reason,
						row.reason,
					)
				}
			})
		}
	}
}

// F21's negative control, which had none: the rule matcher has to REFUSE a
// request a loaded rule matches. Without this the matcher can be gutted to
// always allow and the whole package stays green, because the only other
// test that calls it does so after its backend is already severed.
func TestTheRuleMatcherRefusesWhatARuleMatches(t *testing.T) {
	gateway, _, _ := controlFixture(t, FailClosed)
	mux := gateway.routes()

	loaded(t, gateway)

	status, reason := call(
		t,
		mux,
		routeFiltered,
		token(t, mux, routeFlaggedToken),
	)
	if status != http.StatusForbidden || reason != reasonRulesMatched {
		t.Errorf(
			"a request a loaded rule matches got %d (%s), want 403 and %q",
			status,
			reason,
			reasonRulesMatched,
		)
	}

	status, reason = call(t, mux, routeFiltered, token(t, mux, issuePath))
	if status != http.StatusOK || reason != reasonRulesClean {
		t.Errorf(
			"a request no rule matches got %d (%s), want 200 and %q",
			status,
			reason,
			reasonRulesClean,
		)
	}
}

// The fail-CLOSED half of policy_store_down, which is the gate's HELD row and
// had no unit coverage: a target that loses its store keeps enforcing the
// last policy it loaded.
func TestAFailClosedPolicyControlKeepsEnforcingWhatItLoaded(t *testing.T) {
	gateway, _, backend := controlFixture(t, FailClosed)
	mux := gateway.routes()

	loaded(t, gateway)

	flagged := token(t, mux, routeFlaggedToken)

	backend.Close()
	awaitStale(t, gateway)

	status, reason := call(t, mux, routeGoverned, flagged)
	if status != http.StatusForbidden || reason != reasonPolicyStale {
		t.Errorf(
			"a fail-closed target that lost its store answered %d (%s), want 403 and %q",
			status,
			reason,
			reasonPolicyStale,
		)
	}

	// And the legitimate subject is still served, which is what makes this
	// HELD rather than DENIED on the live range.
	if status, reason := call(
		t,
		mux,
		routeGoverned,
		token(t, mux, issuePath),
	); status != http.StatusOK {
		t.Errorf(
			"the legitimate subject stopped being served: %d (%s)",
			status,
			reason,
		)
	}
}

// A credential that is absent or not a bearer token is refused by this
// service's own authentication, never by a control.
func TestAMissingOrNonBearerCredentialIsRefusedBeforeAnyControl(t *testing.T) {
	gateway, _, _ := controlFixture(t, FailClosed)
	mux := gateway.routes()

	for _, row := range []struct{ name, header string }{
		{"no header at all", ""},
		{"a non-bearer scheme", "Basic bm90LWEtYmVhcmVy"},
	} {
		t.Run(row.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, routeGoverned, nil)
			if row.header != "" {
				request.Header.Set(headerAuthorization, row.header)
			}

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Errorf("%s got %d, want 401", row.name, recorder.Code)
			}

			if got := recorder.Header().Get(
				headerControlReason,
			); got != reasonNoCredential {
				t.Errorf("reason was %q, want %q", got, reasonNoCredential)
			}
		})
	}
}

// F11 and F12 are two bugs reporting the same direction on the same
// observable, so the fixture has to keep them apart.
func TestThePolicyControlSeparatesLostFromNeverLoaded(t *testing.T) {
	gateway, _, backend := controlFixture(t, FailOpen)
	mux := gateway.routes()

	loaded(t, gateway)

	flagged := token(t, mux, routeFlaggedToken)

	if status, _ := call(
		t,
		mux,
		routeGoverned,
		flagged,
	); status != http.StatusForbidden {
		t.Fatalf(
			"the policy was not being enforced before the fault, got %d",
			status,
		)
	}

	backend.Close()
	awaitStale(t, gateway)

	status, reason := call(t, mux, routeGoverned, flagged)
	if status != http.StatusOK {
		t.Errorf(
			"a fail-open target that lost its policy answered %d (%s), want 200",
			status,
			reason,
		)
	}

	if reason != reasonPolicyDropped {
		t.Errorf(
			"a target that LOST a loaded policy reported %q, which is the never-loaded wording",
			reason,
		)
	}
}

// The cold start, which is the reading the F12 row is about: an empty policy
// set usually means nothing is denied.
func TestAColdStartedPolicyControlSplitsOnItsFailMode(t *testing.T) {
	for _, row := range []struct {
		mode   string
		status int
		reason string
	}{
		{FailOpen, http.StatusOK, reasonPolicyNeverLoaded},
		{FailClosed, http.StatusForbidden, reasonPolicyCannotEvaluate},
	} {
		t.Run(row.mode, func(t *testing.T) {
			store := newStubStore(t)

			gateway := newControlGateway(
				store.address(),
				"http://127.0.0.1:0",
				"http://127.0.0.1:0",
				row.mode,
				controlTestSecret,
				defaultLimit,
			)
			mux := gateway.routes()

			status, reason := call(
				t,
				mux,
				routeGoverned,
				token(t, mux, routeFlaggedToken),
			)

			if status != row.status {
				t.Errorf(
					"a cold-started %s target answered %d, want %d",
					row.mode,
					status,
					row.status,
				)
			}

			if reason != row.reason {
				t.Errorf("reason was %q, want %q", reason, row.reason)
			}

			// The STATE, not the first sample. Both rows above would hold
			// for the first millisecond even against a reachable store,
			// because the refresh goroutine has not run yet: this is what
			// proves the gateway can never load rather than has not yet.
			time.Sleep(3 * controlRefresh)

			gateway.mu.Lock()
			everLoaded := gateway.loadedPolicy
			gateway.mu.Unlock()

			if everLoaded {
				t.Fatal(
					"the gateway loaded a policy after all, so this test was measuring a race rather than a cold start",
				)
			}
		})
	}
}

// The cold-start experiment restarts this container mid-run, so a credential
// khaos was issued before the restart has to still authenticate after it.
//
// Measured on a live range: with the credentials held in memory, the restart
// left every one of them unknown, the valid stream went 401 for the whole
// fault window, and khaos reported `deviated / DENIED` on a run that had
// measured its own restart rather than the policy.
func TestACredentialSurvivesARestartOfTheGateway(t *testing.T) {
	before, store, backend := controlFixture(t, FailOpen)
	credential := token(t, before.routes(), issuePath)

	after := newControlGateway(
		store.address(),
		backend.URL,
		backend.URL,
		FailOpen,
		controlTestSecret,
		defaultLimit,
	)
	mux := after.routes()

	loaded(t, after)

	status, reason := call(t, mux, routeGoverned, credential)
	if status == http.StatusUnauthorized {
		t.Fatalf(
			"a credential issued before the restart no longer authenticates (%s), so a cold-start run measures the restart rather than the control",
			reason,
		)
	}
}

// F21. The rule path must be severable on its own even though it terminates
// at the same backend as the policy path.
func TestTheRuleAndPolicyPathsAreSeveredIndependently(t *testing.T) {
	store := newStubStore(t)

	policy := httptest.NewServer(newControlBackend().routes())
	t.Cleanup(policy.Close)

	rules := httptest.NewServer(newControlBackend().routes())
	t.Cleanup(rules.Close)

	gateway := newControlGateway(
		store.address(),
		policy.URL,
		rules.URL,
		FailOpen,
		controlTestSecret,
		defaultLimit,
	)
	mux := gateway.routes()

	loaded(t, gateway)

	flagged := token(t, mux, routeFlaggedToken)

	// The rule path must be ENFORCING before it is severed, or this test
	// passes against a matcher that never refused anything.
	if status, reason := call(
		t,
		mux,
		routeFiltered,
		flagged,
	); status != http.StatusForbidden {
		t.Fatalf(
			"the rule matcher was not enforcing before the fault: %d (%s)",
			status,
			reason,
		)
	}

	rules.Close()

	deadline := time.Now().Add(5 * time.Second)
	split := false
	for time.Now().Before(deadline) && !split {
		gateway.mu.Lock()
		split = !gateway.freshRules && gateway.freshPolicy
		gateway.mu.Unlock()

		if !split {
			time.Sleep(10 * time.Millisecond)
		}
	}

	if !split {
		t.Fatal(
			"the gateway never reached the state this test needs: rules stale and policy still fresh",
		)
	}

	if status, reason := call(
		t,
		mux,
		routeFiltered,
		flagged,
	); status != http.StatusOK {
		t.Errorf(
			"the severed rule path answered %d (%s), want a fail-open 200",
			status,
			reason,
		)
	}

	if status, reason := call(
		t,
		mux,
		routeGoverned,
		flagged,
	); status != http.StatusForbidden {
		t.Errorf(
			"severing the rule path also stopped the policy path enforcing: %d (%s), want 403",
			status,
			reason,
		)
	}
}
