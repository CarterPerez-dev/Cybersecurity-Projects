// ©AngelaMos | 2026
// generator.go

package generators

import (
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
)

type ArtifactKind = token.ArtifactKind

const (
	KindURL              = token.KindURL
	KindFile             = token.KindFile
	KindText             = token.KindText
	KindConnectionString = token.KindConnectionString
)

type Artifact = token.Artifact

type TriggerResponse = token.TriggerResponse

type Generator = token.Generator
