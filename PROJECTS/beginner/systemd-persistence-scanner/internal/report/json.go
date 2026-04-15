/*
©AngelaMos | 2026
json.go

Structured JSON output formatter for scan results

Serializes the full ScanResult to JSON with indentation for human
readability. Outputs to stdout for piping into jq, SIEM ingestion,
or file redirection.
*/

package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func PrintJSON(result types.ScanResult) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding json: %w", err)
	}
	return nil
}
