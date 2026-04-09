// ©AngelaMos | 2026
// json.go

package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/CarterPerez-dev/bomber/pkg/types"
)

type JSONReport struct {
	Scan   *types.ScanResult   `json:"scan,omitempty"`
	Vulns  *types.VulnReport   `json:"vulnerabilities,omitempty"`
	Policy *types.CheckResult  `json:"policy,omitempty"`
}

func WriteJSON(w io.Writer, scan *types.ScanResult, vulns *types.VulnReport, policy *types.CheckResult) error {
	report := JSONReport{
		Scan:   scan,
		Vulns:  vulns,
		Policy: policy,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json report: %w", err)
	}

	_, err = w.Write(data)
	return err
}
