/*
AngelaMos | 2026
reporter.go
*/

package report

import (
	"fmt"
	"io"
	"os"

	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type Reporter interface {
	Report(findings finding.Collection) error
}

func NewReporter(format, outputFile string) (Reporter, error) {
	var w io.Writer = os.Stdout
	var closer func() error

	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("creating output file: %w", err)
		}
		w = f
		closer = f.Close
	}

	switch format {
	case "terminal", "":
		return &TerminalReporter{
			w:       w,
			closer:  closer,
			colored: outputFile == "",
		}, nil
	case "json":
		return &JSONReporter{w: w, closer: closer}, nil
	case "sarif":
		return &SARIFReporter{w: w, closer: closer}, nil
	case "junit":
		return &JUnitReporter{w: w, closer: closer}, nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format)
	}
}

type baseReporter struct {
	w      io.Writer
	closer func() error
}

func (r *baseReporter) close() error {
	if r.closer != nil {
		return r.closer()
	}
	return nil
}
