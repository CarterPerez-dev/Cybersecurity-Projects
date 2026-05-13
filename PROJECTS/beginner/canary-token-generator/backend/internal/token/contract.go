// ©AngelaMos | 2026
// contract.go

package token

import (
	"context"
	"net/http"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

type ArtifactKind string

const (
	KindURL              ArtifactKind = "url"
	KindFile             ArtifactKind = "file"
	KindText             ArtifactKind = "text"
	KindConnectionString ArtifactKind = "connection_string"
)

type Artifact struct {
	Kind             ArtifactKind
	URL              string
	Filename         string
	Content          []byte
	ContentType      string
	ConnectionString string
	DestinationURL   string
}

type TriggerResponse struct {
	StatusCode   int
	ContentType  string
	Body         []byte
	RedirectURL  string
	ExtraHeaders map[string]string
}

type Generator interface {
	Type() Type
	Generate(
		ctx context.Context,
		t *Token,
		baseURL string,
	) (Artifact, error)
	Trigger(
		ctx context.Context,
		t *Token,
		r *http.Request,
	) (*event.Event, *TriggerResponse, error)
}
