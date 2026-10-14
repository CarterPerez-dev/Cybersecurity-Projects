// ©AngelaMos | 2026
// idp.go

package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
)

const (
	routeToken      = "/token"
	routeRevoke     = "/revoke"
	routeIntrospect = "/introspect"
	routeHealth     = "/health"

	paramUser  = "user"
	paramToken = "token"

	contentType = "Content-Type"
	mimeJSON    = "application/json"

	tokenPrefix = "khaos-range-token-"
)

type introspection struct {
	Active bool   `json:"active"`
	User   string `json:"user,omitempty"`

	// Asked counts introspections of the ROGUE provider and is only ever set
	// by that fixture.
	Asked int64 `json:"asked,omitempty"`
}

type identityProvider struct {
	mu     sync.RWMutex
	issued map[string]string
	serial int
}

func newIdentityProvider() *identityProvider {
	return &identityProvider{issued: map[string]string{}}
}

func (p *identityProvider) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(routeHealth, p.health)
	mux.HandleFunc(routeToken, p.issue)
	mux.HandleFunc(routeRevoke, p.revoke)
	mux.HandleFunc(routeIntrospect, p.introspect)
	return mux
}

func (p *identityProvider) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (p *identityProvider) issue(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get(paramUser)
	if user == "" {
		user = "operator"
	}

	p.mu.Lock()
	p.serial++
	token := tokenPrefix + strconv.Itoa(p.serial)
	p.issued[token] = user
	p.mu.Unlock()

	writeJSON(w, map[string]string{paramToken: token, paramUser: user})
}

func (p *identityProvider) revoke(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get(paramToken)

	p.mu.Lock()
	delete(p.issued, token)
	p.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (p *identityProvider) introspect(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get(paramToken)

	p.mu.RLock()
	user, active := p.issued[token]
	p.mu.RUnlock()

	writeJSON(w, introspection{Active: active, User: user})
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set(contentType, mimeJSON)
	_ = json.NewEncoder(w).Encode(body)
}
