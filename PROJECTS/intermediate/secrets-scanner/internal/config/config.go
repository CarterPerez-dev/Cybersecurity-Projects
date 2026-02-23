// ©AngelaMos | 2026
// config.go

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

const DefaultConfigFile = ".portia.toml"

type Config struct {
	Rules     RulesConfig     `toml:"rules"`
	Scan      ScanConfig      `toml:"scan"`
	Output    OutputConfig    `toml:"output"`
	HIBP      HIBPConfig      `toml:"hibp"`
	Allowlist AllowlistConfig `toml:"allowlist"`
}

type RulesConfig struct {
	Disable []string `toml:"disable"`
	Enable  []string `toml:"enable"`
}

type ScanConfig struct {
	MaxFileSize int64    `toml:"max_file_size"`
	Excludes    []string `toml:"excludes"`
	Depth       int      `toml:"depth"`
	Since       string   `toml:"since"`
}

type OutputConfig struct {
	Format  string `toml:"format"`
	Verbose bool   `toml:"verbose"`
	NoColor bool   `toml:"no_color"`
}

type HIBPConfig struct {
	Enabled bool `toml:"enabled"`
}

type AllowlistConfig struct {
	Paths     []string `toml:"paths"`
	Values    []string `toml:"values"`
	Stopwords []string `toml:"stopwords"`
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Scan: ScanConfig{
			MaxFileSize: 1 << 20,
		},
		Output: OutputConfig{
			Format: "terminal",
		},
	}

	if path == "" {
		path = findConfig()
	}

	if path == "" {
		if pyCfg, ok := loadFromPyproject(); ok {
			return pyCfg, nil
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

type pyprojectWrapper struct {
	Tool struct {
		Portia Config `toml:"portia"`
	} `toml:"tool"`
}

func loadFromPyproject() (*Config, bool) {
	data, err := os.ReadFile("pyproject.toml")
	if err != nil {
		return nil, false
	}

	var wrapper pyprojectWrapper
	if err := toml.Unmarshal(data, &wrapper); err != nil {
		return nil, false
	}

	cfg := wrapper.Tool.Portia
	if cfg.Output.Format == "" && !cfg.Output.Verbose &&
		!cfg.Output.NoColor && !cfg.HIBP.Enabled &&
		len(cfg.Rules.Disable) == 0 && len(cfg.Scan.Excludes) == 0 {
		return nil, false
	}

	if cfg.Scan.MaxFileSize == 0 {
		cfg.Scan.MaxFileSize = 1 << 20
	}
	if cfg.Output.Format == "" {
		cfg.Output.Format = "terminal"
	}

	return &cfg, true
}

func findConfig() string {
	candidates := []string{
		DefaultConfigFile,
		filepath.Join(".portia", "config.toml"),
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	home, err := os.UserHomeDir()
	if err == nil {
		global := filepath.Join(home, ".config", "portia", "config.toml")
		if _, err := os.Stat(global); err == nil {
			return global
		}
	}

	return ""
}

func PyprojectTemplate(name string) string {
	return fmt.Sprintf(`[project]
name = "%s"
version = "0.1.0"
description = ""
requires-python = ">=3.13"
dependencies = []

[tool.portia]
# [tool.portia.rules]
# disable = ["generic-password"]

# [tool.portia.scan]
# max_file_size = 1048576
# excludes = ["*.test.js", "fixtures/"]

# [tool.portia.output]
# format = "terminal"
# verbose = false
# no_color = false

# [tool.portia.hibp]
# enabled = false

# [tool.portia.allowlist]
# paths = ["test/fixtures/"]
# values = ["my_test_value"]
# stopwords = ["mycompany"]
`, name)
}

func DefaultTemplate() string {
	return `# ©AngelaMos | 2026
# .portia.toml

[rules]
# disable = ["generic-password"]

[scan]
max_file_size = 1048576
# excludes = ["*.test.js", "fixtures/"]
# depth = 0
# since = ""

[output]
format = "terminal"
verbose = false
no_color = false

[hibp]
enabled = false

[allowlist]
# paths = ["test/fixtures/"]
# values = ["my_test_value"]
# stopwords = ["mycompany"]
`
}
