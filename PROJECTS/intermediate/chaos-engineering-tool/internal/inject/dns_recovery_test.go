// ©AngelaMos | 2026
// dns_recovery_test.go

package inject

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

func TestDNSRecoveryDistinguishesAbsenceFromDiscoveryFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("API-Version", "1.56")
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/containers/json"):
					if failed {
						w.WriteHeader(http.StatusInternalServerError)
						fmt.Fprint(w, `{"message":"daemon unavailable"}`)
					} else {
						fmt.Fprint(w, `[]`)
					}
				case strings.HasSuffix(r.URL.Path, "/info"):
					fmt.Fprint(w, `{"ID":"test-daemon"}`)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(handler))
			defer server.Close()
			docker, err := dockerx.Connect(
				context.Background(), dockerx.Endpoint{Host: server.URL},
			)
			if err != nil {
				t.Fatal(err)
			}
			defer docker.Close()
			payload, err := journal.EncodePayload(
				dnsPayload{Network: "fixture"},
			)
			if err != nil {
				t.Fatal(err)
			}
			err = (dnsMutator{kind: dnsrv.NXDomain}).Revert(
				context.Background(), Env{Docker: docker},
				journal.Record{Payload: payload},
			)
			if (err != nil) != failed {
				t.Fatalf("discovery failure=%v, recovery error=%v", failed, err)
			}
		})
	}
}
