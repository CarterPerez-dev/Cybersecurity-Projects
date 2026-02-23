// ©AngelaMos | 2026
// source.go

package source

import (
	"context"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

type Source interface {
	Chunks(ctx context.Context, out chan<- types.Chunk) error
	String() string
}
