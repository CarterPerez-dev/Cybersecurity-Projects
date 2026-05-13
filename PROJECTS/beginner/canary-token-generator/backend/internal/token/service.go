// ©AngelaMos | 2026
// service.go

package token

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

const (
	tokenIDAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	tokenIDLength   = 12

	metadataDestinationURL = "destination_url"
	metadataIncludeKeys    = "include_keys"
)

var (
	ErrInvalidDestinationURL = errors.New(
		"token: slowredirect requires metadata.destination_url",
	)
	ErrInvalidIncludeKeys = errors.New(
		"token: envfile metadata.include_keys must be a subset of {aws,stripe,github,db}",
	)
	ErrUnknownGeneratorType = errors.New(
		"token: no generator registered for this type",
	)
	ErrGenerateFailed = errors.New("token: artifact generation failed")
)

var allowedIncludeKeys = map[string]struct{}{
	"aws": {}, "stripe": {}, "github": {}, "db": {},
}

type ServiceRepository interface {
	Insert(ctx context.Context, t *Token) error
	GetByID(ctx context.Context, id string) (*Token, error)
	GetByManageID(ctx context.Context, manageID string) (*Token, error)
	IncrementTriggerCount(ctx context.Context, id string) error
}

type Registry interface {
	Get(t Type) (Generator, bool)
}

type MapRegistry map[Type]Generator

func (m MapRegistry) Get(t Type) (Generator, bool) {
	g, ok := m[t]
	return g, ok
}

type ServiceConfig struct {
	BaseURL   string
	ManageURL string
}

type Service struct {
	repo      ServiceRepository
	registry  Registry
	validate  *validator.Validate
	baseURL   string
	manageURL string
}

func NewService(
	repo ServiceRepository,
	reg Registry,
	cfg ServiceConfig,
) *Service {
	return &Service{
		repo:      repo,
		registry:  reg,
		validate:  validator.New(),
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		manageURL: strings.TrimRight(cfg.ManageURL, "/"),
	}
}

func (s *Service) Create(
	ctx context.Context,
	req CreateRequest,
	createdFP, createdIP string,
) (*Token, Artifact, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, Artifact{}, fmt.Errorf(
			"validate request: %w", err,
		)
	}
	if err := validateTypeMetadata(req.Type, req.Metadata); err != nil {
		return nil, Artifact{}, err
	}

	gen, ok := s.registry.Get(req.Type)
	if !ok {
		return nil, Artifact{}, fmt.Errorf(
			"%w: %s", ErrUnknownGeneratorType, req.Type,
		)
	}

	id, err := generateTokenID()
	if err != nil {
		return nil, Artifact{}, fmt.Errorf(
			"generate id: %w", err,
		)
	}
	manageID := uuid.NewString()

	tok := &Token{
		ID:           id,
		ManageID:     manageID,
		Type:         req.Type,
		Memo:         req.Memo,
		Filename:     filenamePointer(req.Filename),
		AlertChannel: req.AlertChannel,
		TelegramBot:  optionalString(req.TelegramBot),
		TelegramChat: optionalString(req.TelegramChat),
		WebhookURL:   optionalString(req.WebhookURL),
		CreatedIP:    createdIP,
		CreatedFP:    createdFP,
		Enabled:      true,
		Metadata:     normalizeMetadata(req.Metadata),
	}

	art, err := gen.Generate(ctx, tok, s.baseURL)
	if err != nil {
		return nil, Artifact{}, fmt.Errorf(
			"%w: %w", ErrGenerateFailed, err,
		)
	}

	if err := s.repo.Insert(ctx, tok); err != nil {
		return nil, Artifact{}, fmt.Errorf(
			"persist token: %w", err,
		)
	}
	return tok, art, nil
}

func (s *Service) GetByID(
	ctx context.Context,
	id string,
) (*Token, error) {
	tok, err := s.repo.GetByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func (s *Service) GetByManageID(
	ctx context.Context,
	manageID string,
) (*Token, error) {
	tok, err := s.repo.GetByManageID(ctx, manageID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func (s *Service) IncrementTriggerCount(
	ctx context.Context,
	id string,
) error {
	return s.repo.IncrementTriggerCount(ctx, id)
}

func (s *Service) TriggerURL(id string) string {
	return s.baseURL + "/c/" + id
}

func (s *Service) ManageURL(manageID string) string {
	return s.manageURL + "/m/" + manageID
}

func (s *Service) Generator(t Type) (Generator, bool) {
	return s.registry.Get(t)
}

func validateTypeMetadata(t Type, metadata json.RawMessage) error {
	switch t {
	case TypeSlowRedirect:
		return validateSlowredirectMetadata(metadata)
	case TypeEnvfile:
		return validateEnvfileMetadata(metadata)
	case TypeWebbug, TypeDocx, TypePDF, TypeKubeconfig, TypeMySQL:
		return nil
	}
	return nil
}

func validateSlowredirectMetadata(metadata json.RawMessage) error {
	if len(metadata) == 0 {
		return ErrInvalidDestinationURL
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &m); err != nil {
		return fmt.Errorf(
			"parse metadata: %w (slowredirect: %w)",
			err, ErrInvalidDestinationURL,
		)
	}
	raw, ok := m[metadataDestinationURL]
	if !ok {
		return ErrInvalidDestinationURL
	}
	var dest string
	if err := json.Unmarshal(raw, &dest); err != nil {
		return ErrInvalidDestinationURL
	}
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return ErrInvalidDestinationURL
	}
	low := strings.ToLower(dest)
	if !strings.HasPrefix(low, "http://") &&
		!strings.HasPrefix(low, "https://") {
		return ErrInvalidDestinationURL
	}
	return nil
}

func validateEnvfileMetadata(metadata json.RawMessage) error {
	if len(metadata) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &m); err != nil {
		return fmt.Errorf("envfile metadata: %w", err)
	}
	raw, ok := m[metadataIncludeKeys]
	if !ok {
		return nil
	}
	var keys []string
	if err := json.Unmarshal(raw, &keys); err != nil {
		return ErrInvalidIncludeKeys
	}
	for _, k := range keys {
		if _, ok := allowedIncludeKeys[k]; !ok {
			return fmt.Errorf("%w: %q", ErrInvalidIncludeKeys, k)
		}
	}
	return nil
}

func generateTokenID() (string, error) {
	out := make([]byte, tokenIDLength)
	bigLen := big.NewInt(int64(len(tokenIDAlphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, bigLen)
		if err != nil {
			return "", fmt.Errorf("rand: %w", err)
		}
		out[i] = tokenIDAlphabet[idx.Int64()]
	}
	return string(out), nil
}

func filenamePointer(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func optionalString(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func normalizeMetadata(metadata json.RawMessage) json.RawMessage {
	if len(metadata) == 0 {
		return json.RawMessage(`{}`)
	}
	return metadata
}
