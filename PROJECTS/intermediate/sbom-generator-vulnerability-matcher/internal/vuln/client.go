// ©AngelaMos | 2026
// client.go

package vuln

import (
	"context"

	"github.com/CarterPerez-dev/bomber/pkg/types"
)

type Client interface {
	Query(ctx context.Context, packages []types.Package) ([]types.VulnMatch, error)
	Source() string
}
