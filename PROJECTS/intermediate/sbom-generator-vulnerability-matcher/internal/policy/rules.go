// ©AngelaMos | 2026
// rules.go

package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	MaxSeverity string `yaml:"max_severity"`
	MaxAgeDays  int    `yaml:"max_age_days"`
	MaxDepth    int    `yaml:"max_depth"`
}

func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &p, nil
}

func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return ParsePolicy(data)
}
