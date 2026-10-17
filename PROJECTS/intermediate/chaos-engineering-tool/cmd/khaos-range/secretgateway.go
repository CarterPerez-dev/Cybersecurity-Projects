// ©AngelaMos | 2026
// secretgateway.go

package main

import (
	"crypto/rand"
	"net/http"
	"os"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/rangelab"
	"github.com/CarterPerez-dev/khaos/internal/secretfile"
)

const (
	// SecretValidated is the correct handling research 07 part 8 prescribes:
	// explicit length validation after every read. An empty secret is not "no
	// secret", it is "a secret equal to the empty string", and HMAC will
	// happily compute with it.
	SecretValidated = rangelab.SecretValidated

	// SecretUnchecked is the CVE-2019-20933 shape: the secret is read, no
	// length check is made, and the empty value flows straight into the
	// crypto. The upstream fix for that CVE is literally
	// `if h.Config.SharedSecret == "" { 401 }`.
	SecretUnchecked = rangelab.SecretUnchecked

	routeSecretToken = "/secret-token"

	reasonSecretUnreadable = "the secret file could not be read"
	reasonSecretEmpty      = "the secret file is empty, and this mode refuses to verify with an empty key"
	reasonSecretBad        = "the credential does not verify against the secret this service holds"
	reasonSecretOK         = "verified against the secret read for this request"
)

// secretGateway re-reads its secret on EVERY request, which is what makes the
// fault observable at all: a service that read it once at startup holds the
// original for the life of the process and khaos would be measuring nothing.
// That is the same property the DNS gateway needs for re-resolution, and it is
// a deliberate choice of fixture rather than a claim about real services.
type secretGateway struct {
	path string
	mode string
}

func newSecretGateway(path, mode string) *secretGateway {
	return &secretGateway{path: path, mode: mode}
}

func (g *secretGateway) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc(routeAlive, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Liveness does NOT depend on the secret, deliberately. A healthcheck that
	// did would make the container unstartable the moment khaos broke the
	// secret, and compose would restart the target mid-measurement.
	mux.HandleFunc(routeHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc(routeSecretToken, g.issue)
	mux.HandleFunc(routeProtected, g.protected)

	return mux
}

// issue hands out a credential signed with whatever secret the service holds
// right now, which is how khaos gets a valid one without reading the file.
func (g *secretGateway) issue(w http.ResponseWriter, _ *http.Request) {
	secret, err := os.ReadFile(g.path)
	if err != nil {
		w.Header().Set(headerReason, reasonSecretUnreadable)
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	w.Header().Set(contentType, mimeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(
		`{"token":"` + secretfile.Token(secret, rand.Text()) + `"}`,
	))
}

func (g *secretGateway) protected(w http.ResponseWriter, r *http.Request) {
	token, scheme := strings.CutPrefix(
		r.Header.Get(headerAuthorization),
		bearerPrefix,
	)

	if !scheme || token == "" {
		w.Header().Set(headerReason, reasonNoCredential)
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	secret, err := os.ReadFile(g.path)
	if err != nil {
		w.Header().Set(headerReason, reasonSecretUnreadable)
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	// The one line that separates the two modes, and the whole fixture.
	if g.mode == SecretValidated && len(secret) == 0 {
		w.Header().Set(headerReason, reasonSecretEmpty)
		w.WriteHeader(http.StatusForbidden)

		return
	}

	if !secretfile.Verify(token, secret) {
		w.Header().Set(headerReason, reasonSecretBad)
		w.WriteHeader(http.StatusForbidden)

		return
	}

	w.Header().Set(headerReason, reasonSecretOK)
	w.WriteHeader(http.StatusOK)
}
