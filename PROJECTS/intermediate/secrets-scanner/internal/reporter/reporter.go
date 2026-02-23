// ©AngelaMos | 2026
// reporter.go

package reporter

import (
	"io"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

type Reporter interface {
	Report(w io.Writer, result *types.ScanResult) error
}

func New(format string) Reporter {
	switch format {
	case "json":
		return &JSON{}
	case "sarif":
		return &SARIF{}
	default:
		return &Terminal{}
	}
}
