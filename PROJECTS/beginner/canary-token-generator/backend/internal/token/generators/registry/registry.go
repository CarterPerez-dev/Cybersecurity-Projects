// ©AngelaMos | 2026
// registry.go

package registry

import (
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/webbug"
)

type Config struct {
	BaseURL string
}

type Registry map[token.Type]generators.Generator

func Build(_ Config) Registry {
	return Registry{
		token.TypeWebbug: webbug.New(),
	}
}
